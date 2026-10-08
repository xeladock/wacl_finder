# import sys
# import urllib3
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import ipaddress
from collections import defaultdict
from itertools import product
import re
import os

from path import DATA_DIR

base_dir = DATA_DIR + "/config_files_clear"

KNOWN_PROTOCOLS = frozenset({
    'ip', 'tcp', 'udp', 'icmp', 'ipv4'
})
PORT_OPS = frozenset({'eq', 'gt', 'lt', 'neq', 'range'})

class BaseACLParser:
    """ Базовый класс для сопоставления IP, масок и проверки лимитов/ignore_any """

    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.object_groups = defaultdict(list)
        self.acls = {}
        self.parse()

    @staticmethod
    def _wildcard_to_cidr(wildcard):
        try:
            mask_int = int(ipaddress.IPv4Address(wildcard))
            inverted = 0xFFFFFFFF ^ mask_int
            return bin(inverted).count('1')
        except Exception:
            return None

    @staticmethod
    def _mask_to_cidr(mask):
        try:
            mask_int = int(ipaddress.IPv4Address(mask))
            return bin(mask_int).count('1')
        except Exception:
            return None

    @staticmethod
    def _is_ip(s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _cand_to_net(self, cand):
        try:
            if isinstance(cand, str):
                if cand in ("any", "any4", "0.0.0.0/0"):
                    return None
                if '/' in cand:
                    net = ipaddress.ip_network(cand, strict=False)
                    return None if net.prefixlen == 0 else net
                elif ' ' in cand:
                    parts = cand.split()
                    if len(parts) == 2:
                        if parts[1].startswith('0.') or parts[1] == '0.0.0.0':
                            prefix = self._wildcard_to_cidr(parts[1])
                        else:
                            prefix = self._mask_to_cidr(parts[1])
                        if prefix is not None:
                            if prefix == 0:
                                return None
                            return ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
            elif isinstance(cand, tuple) and len(cand) == 2:
                start, end = cand
                if start == end:
                    return ipaddress.ip_network(f"{start}/32", strict=False)
        except ValueError:
            return None
        return None

    def _resolve_entry(self, entry):
        if not entry or entry in ("any", "any4", "0.0.0.0/0"):
            return ["any"]
        if "/" in entry or self._is_ip(entry) or ' ' in entry:
            return [entry]
        if entry in self.object_groups:
            return self.object_groups[entry]
        return []

    def _matches(self, input_str, candidates, strict_mode, is_standard_acl=False, ignore_any=False, mask_limit=None):
        normalized_candidates = []
        for c in candidates:
            if isinstance(c, str) and (c in ("any", "any4", "0.0.0.0/0") or c.startswith("0.0.0.0/0")):
                normalized_candidates.append("any")
            else:
                normalized_candidates.append(c)
        candidates = normalized_candidates

        # 1. Проверка ignore_any
        is_any_in_candidates = any(c in ("any", "any4") for c in candidates)
        if ignore_any and is_any_in_candidates:
            return False

        # 2. Если вход поиска "any"
        if input_str == "any":
            if mask_limit and mask_limit is not False:
                if is_any_in_candidates:
                    return False
            return True

        # 3. Разбор поискового IP/сети
        is_search_network = False
        try:
            if '/' in input_str and not input_str.endswith('/32'):
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            else:
                input_ip = ipaddress.ip_address(input_str.split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
        except ValueError:
            return False

        effective_strict_mode = strict_mode or is_search_network

        # 4. Обработка mask_limit
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                if isinstance(mask_limit, str):
                    parsed_mask_limit = int(mask_limit.replace("/", "").strip())
                elif isinstance(mask_limit, int):
                    parsed_mask_limit = mask_limit
            except ValueError:
                parsed_mask_limit = None

        # 5. Сопоставление с правилами в конфиге
        for cand in candidates:
            if cand in ("any", "any4"):
                if ignore_any:
                    continue
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    continue
                if not effective_strict_mode or is_standard_acl:
                    return True
                continue

            cand_net = self._cand_to_net(cand)

            if parsed_mask_limit is not None and cand_net is not None:
                if cand_net.prefixlen > parsed_mask_limit:
                    continue

            # Строгий режим (или поиск подсети) -> точное совпадение
            if effective_strict_mode:
                if cand_net and cand_net == input_net:
                    return True
            # Нестрогий режим -> вхождение или пересечение
            else:
                try:
                    if input_ip is not None:
                        if cand_net and input_ip in cand_net:
                            return True
                        elif self._is_ip(cand) and input_ip == ipaddress.ip_address(cand):
                            return True
                    else:
                        if cand_net and input_net.overlaps(cand_net):
                            return True
                except Exception:
                    continue

        return False

    def find_acl_matches(
            self,
            src_ip,
            dst_ip,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        matches = []
        for acl_name, acl_data in self.acls.items():
            acl_type = acl_data['type']
            acl_rules = []
            for rule in acl_data['rules']:
                if rule.startswith('remark') or not rule.strip():
                    continue
                parts = rule.split()
                if not parts:
                    continue
                try:
                    src_entry, dst_entry = self._extract_src_dst(parts, acl_type)
                    src_ips = self._resolve_entry(src_entry)
                    dst_ips = self._resolve_entry(dst_entry)

                    # ИСКЛЮЧАЕМ ЯВНЫЕ "any any", "deny any" И ОБЩИЕ ПРАВИЛА ПО УМОЛЧАНИЮ
                    if src_ips == ["any"] and dst_ips == ["any"]:
                        continue

                    src_ok = self._matches(
                        src_ip,
                        src_ips,
                        strict_mode,
                        is_standard_acl=(acl_type == 'standard'),
                        ignore_any=ignore_src_any,
                        mask_limit=src_mask_limit
                    )

                    if acl_type == 'standard':
                        if ignore_dst_any:
                            dst_ok = False
                        else:
                            dst_ok = (not strict_mode or dst_ip == "any")
                    else:
                        dst_ok = self._matches(
                            dst_ip,
                            dst_ips,
                            strict_mode,
                            is_standard_acl=False,
                            ignore_any=ignore_dst_any,
                            mask_limit=dst_mask_limit
                        )

                    if src_ok and dst_ok:
                        acl_rules.append(rule)
                except Exception:
                    continue
            if acl_rules:
                header = f"access-list {acl_name}" if acl_name.isdigit() else f"ip access-list {acl_type} {acl_name}"
                matches.append(header)
                for rule in acl_rules:
                    matches.append(f" {rule}")
        return tuple(matches)

class CiscoIOSXEParser2:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.object_groups = defaultdict(list)
        self.acl_lines = []  # list of (acl_name, rule_line, seq_number, acl_type, header_prefix)
        self.parse()

    def _is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _is_mask(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _wildcard_to_cidr(self, wildcard):
        try:
            wildcard_int = int(ipaddress.IPv4Address(wildcard))
            subnet_mask_int = 0xFFFFFFFF ^ wildcard_int
            prefix = bin(subnet_mask_int).count('1')
            return prefix
        except Exception:
            return None

    def _mask_to_cidr(self, mask):
        try:
            mask_int = int(ipaddress.IPv4Address(mask))
            prefix = bin(mask_int).count('1')
            return prefix
        except Exception:
            return None

    def _cand_to_net(self, cand):
        try:
            if isinstance(cand, str):
                if '/' in cand:
                    return ipaddress.ip_network(cand, strict=False)
                elif ' ' in cand:
                    parts = cand.split()
                    if len(parts) == 2:
                        prefix = self._wildcard_to_cidr(parts[1]) or self._mask_to_cidr(parts[1])
                        if prefix is not None:
                            return ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
            elif isinstance(cand, tuple) and len(cand) == 2:
                start, end = cand
                if start == end:
                    return ipaddress.ip_network(f"{start}/32", strict=False)
        except ValueError:
            return None
        return None

    def _matches(self, input_str, candidates, strict_mode, is_standard_acl=False, ignore_any=False, mask_limit=None):
        ANY_VARIANTS = ("any", "any4", "0.0.0.0/0")

        # 1. СТРОГАЯ ПРОВЕРКА IGNORE_ANY
        is_any_in_candidates = any(c in ANY_VARIANTS for c in candidates)
        if ignore_any and is_any_in_candidates:
            return False

        # 2. Нормализация mask_limit
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                if isinstance(mask_limit, str):
                    parsed_mask_limit = int(mask_limit.replace("/", "").strip())
                elif isinstance(mask_limit, int):
                    parsed_mask_limit = mask_limit
            except ValueError:
                parsed_mask_limit = None

        # 3. Если ищем "any"
        if input_str == "any":
            if is_any_in_candidates:
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    return False
                return True
            return not strict_mode

        if is_any_in_candidates:
            if parsed_mask_limit is not None and parsed_mask_limit > 0:
                return False
            return not strict_mode or is_standard_acl

        # 4. Парсинг поискового ввода (IP или Сеть)
        is_search_network = False
        try:
            if '/' in input_str and not input_str.endswith('/32'):
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            else:
                input_ip = ipaddress.ip_address(input_str.split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
        except ValueError:
            try:
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            except ValueError:
                return False

        effective_strict_mode = strict_mode or is_search_network

        # 5. Проверка кандидатов
        for cand in candidates:
            if cand in ANY_VARIANTS:
                if ignore_any:
                    continue
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    continue
                return not effective_strict_mode or is_standard_acl

            cand_net = self._cand_to_net(cand)

            # Проверка лимита маски (ИСПРАВЛЕНО: отбраковываем сети с префиксом > limit)
            if parsed_mask_limit is not None:
                if cand_net is not None:
                    if cand_net.prefixlen > parsed_mask_limit:
                        continue
                elif isinstance(cand, tuple) and len(cand) == 2:
                    start, end = cand
                    range_size = int(end) - int(start) + 1
                    min_allowed_size = 2 ** (32 - parsed_mask_limit)
                    if range_size < min_allowed_size:
                        continue

            # --- СТРОГИЙ РЕЖИМ ---
            if effective_strict_mode:
                if cand_net and cand_net == input_net:
                    return True
            # --- ОБЫЧНЫЙ РЕЖИМ ---
            else:
                try:
                    if input_ip is not None:
                        if isinstance(cand, tuple) and len(cand) == 2:
                            start, end = cand
                            if start <= input_ip <= end:
                                return True
                        elif cand_net:
                            if input_ip in cand_net:
                                return True
                        elif self._is_ip(cand):
                            if input_ip == ipaddress.ip_address(cand):
                                return True
                    else:
                        if cand_net and input_net.overlaps(cand_net):
                            return True
                except Exception:
                    continue

        return False

    def _extract_src_dst(self, parts, acl_type):
        i = 0
        if parts[0] == 'access-list':
            i = 2
        if i < len(parts) and parts[i].isdigit():
            i += 1
        if i < len(parts) and parts[i] in ('permit', 'deny'):
            i += 1

        # KNOWN_PROTOCOLS = frozenset({
        #     'ip', 'tcp', 'udp', 'icmp','ipv4'
        # })

        if acl_type == 'extended' and i < len(parts):
            if parts[i] in KNOWN_PROTOCOLS or (parts[i].isdigit() and int(parts[i]) <= 255):
                i += 1

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx
            word = parts[idx]
            if word in ("object-group", "addrgroup"):
                if idx + 1 < len(parts):
                    return parts[idx + 1], idx + 2
                return "any", idx + 2
            elif word == "host":
                if idx + 1 < len(parts) and self._is_ip(parts[idx + 1]):
                    return parts[idx + 1] + "/32", idx + 2
                return "any", idx + 2
            elif word in ("any", "any4"):
                return "any", idx + 1
            elif re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', word):
                return word, idx + 1
            elif self._is_ip(word):
                if idx + 1 < len(parts) and self._is_mask(parts[idx + 1]):
                    prefix = self._wildcard_to_cidr(parts[idx + 1]) or self._mask_to_cidr(parts[idx + 1])
                    if prefix is not None:
                        return f"{parts[idx]}/{prefix}", idx + 2
                    else:
                        return parts[idx] + "/32", idx + 1
                else:
                    return parts[idx] + "/32", idx + 1
            return "any", idx + 1

        src, i = parse_entry(i)
        if acl_type == 'standard':
            return src, "any"

        while i < len(parts) and parts[i] in ('eq', 'range', 'gt', 'lt', 'established', 'log', 'nexthop', 'vrf'):
            # Пропускаем параметры портов и опций XR (nexthop1/vrf/и т.д.)
            if parts[i] in ('nexthop', 'vrf'):
                i += 2
            else:
                i += 2 if parts[i] in ('eq', 'gt', 'lt', 'log', 'established') else 3

        dst, i = parse_entry(i)
        return src, dst

    def _resolve_entry(self, entry):
        if not entry or entry in ("any", "any4", "all"):
            return ["any"]
        if "/" in entry or self._is_ip(entry):
            return [entry]
        if entry in self.object_groups:
            resolved = []
            for sub in self.object_groups[entry]:
                if sub in ("any", "any4", "all", "0.0.0.0/0"):
                    return ["any"]
                if self._is_ip(sub) and '/' not in sub:
                    resolved.append(sub + "/32")
                else:
                    sub_resolved = self._resolve_entry(sub)
                    if sub_resolved == ["any"]:
                        return ["any"]
                    resolved.extend(sub_resolved)
            return resolved
        return []

    def parse(self):
        current_group = None
        current_values = []
        current_acl = None
        acl_type = ''
        in_acl = False
        header_prefix = ''

        for line_num, line in enumerate(self.config_lines):
            line = line.strip()
            if not line:
                continue

            # Object groups
            if line.startswith("object-group network "):
                if current_group:
                    self.object_groups[current_group] = current_values
                current_group = line.split()[2]
                current_values = []
                continue

            if current_group:
                if line == "exit" or line.endswith("}"):
                    self.object_groups[current_group] = current_values
                    current_group = None
                    current_values = []
                    continue

                if (line.startswith("access-list ") or
                        line.startswith("ip access-list ") or
                        line.startswith("ipv4 access-list ") or
                        line.startswith("route-map ") or
                        line.startswith("ip prefix-list ") or
                        line.startswith("crypto ") or
                        line.startswith("aaa ") or
                        line.startswith("snmp-server ") or
                        line.startswith("logging ") or
                        line.startswith("ntp ")):
                    self.object_groups[current_group] = current_values
                    current_group = None
                    current_values = []

                if current_group:
                    parts = line.split()
                    if not parts:
                        continue
                    if parts[0].isdigit():
                        parts = parts[1:]
                    if not parts:
                        continue
                    word = parts[0]
                    if word == "description":
                        continue
                    elif word == "host":
                        if len(parts) > 1 and self._is_ip(parts[1]):
                            current_values.append(parts[1] + "/32")
                    elif word in ("group-object", "object-group"):
                        if len(parts) > 1:
                            current_values.append(parts[1])
                    elif len(parts) == 2 and self._is_ip(parts[0]) and self._is_mask(parts[1]):
                        try:
                            prefix = self._mask_to_cidr(parts[1]) or self._wildcard_to_cidr(parts[1])
                            if prefix is not None:
                                network = ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                                current_values.append(str(network))
                        except ValueError:
                            continue
                    elif self._is_ip(word):
                        current_values.append(word + "/32")
                    elif word in ("any", "any4"):
                        current_values.append("any")
                    continue

            # Numbered ACLs
            if line.startswith("access-list "):
                parts = line.split(maxsplit=3)
                if len(parts) > 2:
                    acl_name = parts[1]
                    rule = ' '.join(parts[2:])
                    seq_number = parts[2] if len(parts) > 2 and parts[2].isdigit() else None
                    try:
                        acl_num = int(acl_name)
                        acl_type = 'standard' if 1 <= acl_num <= 99 or 1300 <= acl_num <= 1999 else 'extended'
                    except ValueError:
                        acl_type = 'standard'
                    self.acl_lines.append((acl_name, rule, seq_number, acl_type, 'access-list'))
                continue

            # Named ACLs (IOS, IOS XE, IOS XR)
            if line.startswith("ip access-list ") or line.startswith("ipv4 access-list "):
                parts = line.split(maxsplit=4)
                header_prefix = 'ip access-list' if line.startswith("ip access-list ") else 'ipv4 access-list'
                if len(parts) >= 3:
                    acl_type = parts[2] if len(parts) == 4 and parts[2] in ('standard', 'extended') else 'extended'
                    current_acl = parts[3] if len(parts) == 4 else parts[2]
                    in_acl = True
                continue

            # Rules
            if in_acl:
                if line == "exit" or line.endswith("}"):
                    in_acl = False
                    current_acl = None
                    acl_type = ''
                    continue

                parts = line.split()
                seq_number = None
                if parts and parts[0].isdigit():
                    seq_number = parts[0]
                    parts = parts[1:]

                rule = ' '.join(parts)
                if rule.startswith("permit") or rule.startswith("deny"):
                    self.acl_lines.append((current_acl, rule, seq_number, acl_type, header_prefix))
                continue

        if current_group:
            self.object_groups[current_group] = current_values

    def find_acl_matches(
            self,
            src_ip,
            dst_ip,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        matches = []
        current_acl = None
        for acl_name, full_line, seq_number, acl_type, header_prefix in self.acl_lines:
            parts = full_line.split()
            try:
                src_entry, dst_entry = self._extract_src_dst(parts, acl_type)
                src_ips = self._resolve_entry(src_entry)
                dst_ips = self._resolve_entry(dst_entry)

                if src_ips == ["any"] and dst_ips == ["any"]:
                    continue

                # 1. Проверка SRC
                src_ok = self._matches(
                    src_ip,
                    src_ips,
                    strict_mode,
                    is_standard_acl=(acl_type == 'standard'),
                    ignore_any=ignore_src_any,
                    mask_limit=src_mask_limit
                )

                # 2. Проверка DST
                if acl_type == 'standard':
                    if ignore_dst_any:
                        dst_ok = False
                    else:
                        dst_ok = (not strict_mode or dst_ip == "any")
                else:
                    dst_ok = self._matches(
                        dst_ip,
                        dst_ips,
                        strict_mode,
                        is_standard_acl=False,
                        ignore_any=ignore_dst_any,
                        mask_limit=dst_mask_limit
                    )

                if src_ok and dst_ok:
                    if acl_name != current_acl:
                        if header_prefix == 'access-list' and acl_name.isdigit():
                            header = f"access-list {acl_name}"
                        elif header_prefix == 'ipv4 access-list':
                            header = f"ipv4 access-list {acl_name}"
                        else:
                            header = f"{header_prefix} {acl_type} {acl_name}"
                        matches.append(header)
                        current_acl = acl_name
                    matches.append(f" {full_line}")
            except Exception:
                continue
        return tuple(matches)



class CiscoIOSParser3:
    def __init__(self, config_text, hp_procurve=False):
        self.config_lines = config_text.splitlines()
        self.object_groups = defaultdict(list)
        self.acls = {}
        self.acl_headers = {}
        self.hp_procurve = hp_procurve
        self.parse()

    @staticmethod
    def _wildcard_to_cidr(wildcard: str):
        try:
            mask_int = int(ipaddress.IPv4Address(wildcard))
            inverted = 0xFFFFFFFF ^ mask_int
            return bin(inverted).count('1')
        except Exception:
            return None

    @staticmethod
    def _mask_to_cidr(mask: str):
        try:
            mask_int = int(ipaddress.IPv4Address(mask))
            return bin(mask_int).count('1')
        except Exception:
            return None

    def _cand_to_net(self, cand):
        if cand in ("any", "any4", "all", "0.0.0.0/0"):
            return "any"
        try:
            if isinstance(cand, str):
                if '/' in cand:
                    net = ipaddress.ip_network(cand, strict=False)
                    return "any" if net.prefixlen == 0 else net
                elif ' ' in cand:
                    parts = cand.split()
                    if len(parts) == 2:
                        prefix = (self._wildcard_to_cidr(parts[1])
                                  if (parts[1].startswith('0.') or parts[1] == '0.0.0.0')
                                  else self._mask_to_cidr(parts[1]))
                        if prefix is not None:
                            net = ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                            return "any" if net.prefixlen == 0 else net
                else:
                    return ipaddress.ip_network(f"{cand}/32", strict=False)
            elif isinstance(cand, tuple) and len(cand) == 2:
                start, end = cand
                if start == end:
                    return ipaddress.ip_network(f"{start}/32", strict=False)
                return cand
        except ValueError:
            return None
        return None

    def _is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _matches(self, input_str, candidates, strict_mode, is_standard_acl=False, ignore_any=False, mask_limit=None):
        # 1. Парсинг лимита маски (например, mask_limit=24 или '/24')
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                parsed_mask_limit = int(str(mask_limit).replace("/", "").strip())
            except ValueError:
                parsed_mask_limit = None

        # 2. Нормализация всех кандидатов правила
        normalized_candidates = []
        is_any_in_candidates = False

        for cand in candidates:
            net = self._cand_to_net(cand)
            if net == "any":
                is_any_in_candidates = True
            elif net is not None:
                normalized_candidates.append(net)

        # 3. Обработка правила со значением ANY
        if is_any_in_candidates:
            # Если просим игнорировать ANY
            if ignore_any:
                return False
            # Если задан лимит маски (например /24), ANY считается широкой сетью (/0) и отбрасывается
            if parsed_mask_limit is not None and parsed_mask_limit > 0:
                return False
            # Если адрес поиска не передан или передан ANY
            if not input_str or input_str == "any":
                return True
            return not strict_mode or is_standard_acl

        # 4. Если в правиле нет ANY, но поиск выполняется по "any" или пустой строке
        if not input_str or input_str == "any":
            return not strict_mode

        # 5. Парсинг подсети / IP из запроса
        try:
            if '/' in str(input_str) and not str(input_str).endswith('/32'):
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                effective_strict = True
            else:
                input_ip = ipaddress.ip_address(str(input_str).split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
                effective_strict = strict_mode
        except ValueError:
            return False

        # 6. Проверка соответствия кандидатов и фильтрация по mask_limit
        for cand_net in normalized_candidates:
            # ПРОВЕРКА ЛИМИТА МАСКИ:
            # Маска правила (prefixlen) должна быть КРУПНЕЕ ИЛИ РАВНА лимиту.
            # Пример: mask_limit=24. Сеть /28 (28 >= 24) проходит. Сеть /16 (16 < 24) отбрасывается.
            if parsed_mask_limit is not None:
                if isinstance(cand_net, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    if cand_net.prefixlen < parsed_mask_limit:
                        continue
                elif isinstance(cand_net, tuple) and len(cand_net) == 2:
                    start, end = cand_net
                    range_size = int(end) - int(start) + 1
                    min_allowed_size = 2 ** (32 - parsed_mask_limit)
                    if range_size > min_allowed_size:
                        continue

            # Сопоставление IP / Подсетей
            if effective_strict:
                if isinstance(cand_net, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and cand_net == input_net:
                    return True
            else:
                if input_ip:
                    if isinstance(cand_net, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and input_ip in cand_net:
                        return True
                    elif isinstance(cand_net, tuple) and len(cand_net) == 2:
                        if cand_net[0] <= input_ip <= cand_net[1]:
                            return True
                elif isinstance(cand_net, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    if input_net.overlaps(cand_net):
                        return True

        return False

    def parse(self):
        self._parse_object_groups()
        current_acl = None
        current_type = 'extended'

        for line in self.config_lines:
            s_line = line.strip()
            if not s_line or s_line.startswith("!") or s_line.startswith("#"):
                continue

            if s_line.startswith("access-list ip ") or s_line.startswith("access-list "):
                parts = s_line.split(maxsplit=3)
                if len(parts) >= 3 and parts[1] == "ip" and parts[2] in ("standard", "extended"):
                    acl_type = parts[2]
                    acl_name = parts[3].strip('"')
                    self.acls.setdefault(acl_name, {'type': acl_type, 'rules': [],
                                                    'header': f"access-list ip {acl_type} {acl_name}"})
                    current_acl = acl_name
                    current_type = acl_type
                    continue
                elif len(parts) > 2:
                    acl_name = parts[1]
                    if acl_name.isdigit():
                        acl_type = 'standard' if int(acl_name) < 100 or 1300 <= int(acl_name) <= 1999 else 'extended'
                        rule = ' '.join(parts[2:])
                        self.acls.setdefault(acl_name,
                                             {'type': acl_type, 'rules': [], 'header': f"access-list {acl_name}"})
                        self.acls[acl_name]['rules'].append(rule)
                    continue

            if s_line.startswith("ip access-list "):
                parts = s_line.split(maxsplit=4)
                acl_type = 'extended'
                acl_name = None
                if len(parts) >= 4 and parts[2] in ("standard", "extended"):
                    acl_type = parts[2]
                    acl_name = parts[3].strip('"')
                elif len(parts) >= 3:
                    acl_name = parts[2].strip('"')
                if acl_name:
                    self.acls.setdefault(acl_name, {'type': acl_type, 'rules': [],
                                                    'header': f"ip access-list {acl_type} {acl_name}"})
                    current_acl = acl_name
                    current_type = acl_type
                continue

            if current_acl:
                if s_line.startswith("permit") or s_line.startswith("deny") or s_line[0].isdigit() or s_line.startswith(
                        "seq "):
                    self.acls[current_acl]['rules'].append(s_line)
                elif s_line == "exit" or s_line.endswith("}"):
                    current_acl = None

    def _parse_object_groups(self):
        current_name = None
        current_values = []
        for line in self.config_lines:
            s = line.strip()
            if s.startswith("object-group ip address") or s.startswith("object-group network"):
                if current_name:
                    self.object_groups[current_name] = current_values
                current_name = s.split()[-1]
                current_values = []
            elif current_name:
                if s.startswith("host-info ") or s.startswith("host "):
                    current_values.append(s.split()[-1] + "/32")
                elif re.match(r"\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+", s):
                    ip, mask = s.split()[:2]
                    prefix = self._mask_to_cidr(mask)
                    if prefix is not None:
                        current_values.append(f"{ip}/{prefix}")
                elif s.startswith("exit") or s == "!":
                    self.object_groups[current_name] = current_values
                    current_name = None
                    current_values = []
        if current_name:
            self.object_groups[current_name] = current_values

    def _extract_src_dst(self, parts, acl_type):
        i = 0
        if parts and (parts[i].isdigit() or parts[i] == "seq"):
            i += 1
            if i < len(parts) and parts[i - 1] == "seq":
                i += 1

        if i < len(parts) and parts[i] in ('permit', 'deny'):
            i += 1

        # KNOWN_PROTOCOLS = frozenset({'ip', 'tcp', 'udp', 'icmp'})
        if acl_type == 'extended' and i < len(parts):
            if parts[i] in KNOWN_PROTOCOLS or (parts[i].isdigit() and int(parts[i]) <= 255):
                i += 1

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx
            word = parts[idx]

            if word in ("object-group", "addrgroup"):
                return (parts[idx + 1], idx + 2) if idx + 1 < len(parts) else ("any", idx + 1)
            elif word == "host":
                return (parts[idx + 1] + "/32", idx + 2) if idx + 1 < len(parts) else ("any", idx + 1)
            elif word in ("any", "any4"):
                return "any", idx + 1
            elif '/' in word:
                return word, idx + 1
            elif self._is_ip(word):
                if idx + 1 < len(parts) and self._is_ip(parts[idx + 1]):
                    mask = parts[idx + 1]
                    prefix = (self._wildcard_to_cidr(mask)
                              if (mask.startswith('0.') or mask == '0.0.0.0')
                              else self._mask_to_cidr(mask))
                    if prefix is not None:
                        return f"{word}/{prefix}", idx + 2
                return f"{word}/32", idx + 1
            return "any", idx + 1

        src, i = parse_entry(i)
        dst = "any" if acl_type == 'standard' else parse_entry(i)[0]
        return src, dst

    def _resolve_entry(self, entry):
        if not entry or entry == "any":
            return ["any"]
        if "/" in entry or self._is_ip(entry) or ' ' in entry:
            return [entry]
        if entry in self.object_groups:
            return self.object_groups[entry]
        return []

    def find_matches(
            self,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        matches = []
        for acl_name, acl_data in self.acls.items():
            acl_type = acl_data['type']
            acl_rules = []
            for rule in acl_data['rules']:
                if rule.startswith('remark') or not rule.strip():
                    continue
                parts = rule.split()
                if not parts:
                    continue
                try:
                    src_entry, dst_entry = self._extract_src_dst(parts, acl_type)
                    src_ips = self._resolve_entry(src_entry)
                    dst_ips = self._resolve_entry(dst_entry)

                    if src_ips == ["any"] and dst_ips == ["any"]:
                        continue

                    src_ok = self._matches(
                        src_ip,
                        src_ips,
                        strict_mode,
                        is_standard_acl=(acl_type == 'standard'),
                        ignore_any=ignore_src_any,
                        mask_limit=src_mask_limit
                    )

                    if acl_type == 'standard':
                        dst_ok = False if ignore_dst_any else (not strict_mode or dst_ip == "any")
                    else:
                        dst_ok = self._matches(
                            dst_ip,
                            dst_ips,
                            strict_mode,
                            is_standard_acl=False,
                            ignore_any=ignore_dst_any,
                            mask_limit=dst_mask_limit
                        )

                    if src_ok and dst_ok:
                        acl_rules.append(rule)
                except Exception:
                    continue
            if acl_rules:
                matches.append(acl_data.get('header', f"access-list {acl_name}"))
                for rule in acl_rules:
                    matches.append(f"  {rule}")
        return tuple(matches)

    # find_matches = find_acl_matches

    # @classmethod
    # def from_local_file(
    #         cls,
    #         filename,
    #         src_ip=None,
    #         dst_ip=None,
    #         strict_mode=False,
    #         ignore_src_any=False,
    #         ignore_dst_any=False,
    #         src_mask_limit=None,
    #         dst_mask_limit=None,
    #         base_dir=base_dir,
    #         encoding="utf-8"
    # ):
    #     if os.path.exists(filename) and os.path.isfile(filename):
    #         target_path = filename
    #     else:
    #         base_dir = base_dir or os.getcwd()
    #         target_path = None
    #         target_name = os.path.basename(filename)
    #         for root, _, files in os.walk(base_dir):
    #             if target_name in files:
    #                 target_path = os.path.join(root, target_name)
    #                 break
    #
    #     if not target_path:
    #         return tuple()
    #
    #     try:
    #         with open(target_path, "r", encoding=encoding, errors="ignore") as f:
    #             config_text = f.read()
    #         parser = cls(config_text)
    #         return parser.find_acl_matches(
    #             src_ip=src_ip,
    #             dst_ip=dst_ip,
    #             strict_mode=strict_mode,
    #             ignore_src_any=ignore_src_any,
    #             ignore_dst_any=ignore_dst_any,
    #             src_mask_limit=src_mask_limit,
    #             dst_mask_limit=dst_mask_limit
    #         )
    #     except Exception:
    #         return tuple()


class CiscoASAParser5:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.objects = {}  # object network name -> [networks/ranges]
        self.object_groups = defaultdict(list)  # object-group network -> [networks/objects]
        self.acl_lines = []  # access-list строки
        self.parse()

    def parse(self):
        self._parse_objects()
        self._parse_object_groups()
        self._parse_acls()

    def _parse_objects(self):
        current_name = None
        current_values = []

        for line in self.config_lines:
            line = line.strip()
            if line.startswith("object network "):
                if current_name:
                    self.objects[current_name] = current_values
                current_name = line.split("object network ")[1]
                current_values = []
            elif line.startswith("host "):
                ip = line.split()[1]
                current_values.append(ip + "/32")
            elif line.startswith("range "):
                parts = line.split()
                current_values.extend(self._expand_ip_range(parts[1], parts[2]))
            elif line.startswith("subnet "):
                parts = line.split()
                try:
                    network = ipaddress.ip_network((parts[1], parts[2]), strict=False)
                    current_values.append(str(network))
                except ValueError:
                    continue
        if current_name:
            self.objects[current_name] = current_values

    def _parse_object_groups(self):
        current_group = None
        current_values = []

        for line in self.config_lines:
            line = line.strip()
            if line.startswith("object-group network "):
                if current_group:
                    self.object_groups[current_group] = current_values
                current_group = line.split("object-group network ")[1]
                current_values = []
            elif line.startswith("network-object host "):
                ip = line.split()[-1]
                current_values.append(ip + "/32")
            elif line.startswith("network-object object "):
                obj = line.split()[-1]
                current_values.extend(self.objects.get(obj, []))
            elif line.startswith("network-object "):
                parts = line.split()
                if len(parts) == 3:
                    try:
                        network = ipaddress.ip_network((parts[1], parts[2]), strict=False)
                        current_values.append(str(network))
                    except ValueError:
                        continue
            elif line.startswith("group-object "):
                ref = line.split()[-1]
                current_values.append(("group", ref))
        if current_group:
            self.object_groups[current_group] = current_values

        for group, values in list(self.object_groups.items()):
            expanded = []
            for val in values:
                if isinstance(val, tuple) and val[0] == "group":
                    expanded.extend(self._resolve_group(val[1]))
                else:
                    expanded.append(val)
            self.object_groups[group] = expanded

    def _parse_acls(self):
        for line in self.config_lines:
            line = line.strip()
            if line.startswith("access-list ") and not ("remark" in line or "description" in line):
                self.acl_lines.append(line)

    def _expand_ip_range(self, start_ip, end_ip):
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            return [(start, end)]
        except ValueError:
            return []

    def _resolve_group(self, name):
        results = []
        visited = set()

        def _resolve(n):
            if n in visited:
                return
            visited.add(n)
            if n in self.object_groups:
                for val in self.object_groups[n]:
                    if isinstance(val, tuple) and val[0] == "group":
                        _resolve(val[1])
                    else:
                        results.append(val)
            elif n in self.objects:
                results.extend(self.objects[n])

        _resolve(name)
        return results

    def _resolve_entry(self, entry):
        if not entry or entry in ("any", "any4", "0.0.0.0/0"):
            return ["any"]
        if isinstance(entry, tuple):
            return [entry]
        if "/" in entry or self._is_ip(entry):
            return [entry]
        if entry in self.objects:
            return self.objects[entry]
        if entry in self.object_groups:
            return self.object_groups[entry]
        return []

    def _is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _is_dotted_decimal(self, s):
        parts = s.split('.')
        if len(parts) != 4:
            return False
        for p in parts:
            if not p.isdigit() or not 0 <= int(p) <= 255:
                return False
        return True

    def _cand_to_net(self, cand):
        try:
            if isinstance(cand, str):
                if cand.lower() in ("any", "any4", "all", "0.0.0.0/0"):
                    return None
                if '/' in cand:
                    return ipaddress.ip_network(cand, strict=False)
                elif ' ' in cand:
                    parts = cand.split()
                    if len(parts) == 2:
                        return ipaddress.ip_network((parts[0], parts[1]), strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
            elif isinstance(cand, tuple):
                if len(cand) == 3 and cand[0] == 'netmask':
                    return ipaddress.ip_network((cand[1], cand[2]), strict=False)
                elif len(cand) == 2:
                    start, end = cand
                    if start == end:
                        return ipaddress.ip_network(f"{start}/32", strict=False)
        except ValueError:
            return None
        return None

    def _matches(self, input_str, candidates, strict_mode, ignore_any=False, mask_limit=None):
        ANY_VARIANTS = ("any", "any4", "all", "0.0.0.0/0")

        # 1. СТРОГАЯ ПРОВЕРКА IGNORE_ANY (Первей всего!)
        is_any_in_candidates = any(c in ANY_VARIANTS for c in candidates)
        if ignore_any and is_any_in_candidates:
            return False

        # 2. Нормализация mask_limit (форматы: "/27", "27", 27)
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                if isinstance(mask_limit, str):
                    parsed_mask_limit = int(mask_limit.replace("/", "").strip())
                elif isinstance(mask_limit, int):
                    parsed_mask_limit = mask_limit
            except ValueError:
                parsed_mask_limit = None

        # 3. Если ищем "any" или пустой запрос
        if not input_str or input_str == "any":
            if is_any_in_candidates:
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    return False
                return True
            return not strict_mode

        if is_any_in_candidates:
            if parsed_mask_limit is not None and parsed_mask_limit > 0:
                return False
            return not strict_mode

        # 4. Анализ поискового ввода (IP или Сеть)
        is_search_network = False
        try:
            if '/' in input_str and not input_str.endswith('/32'):
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            else:
                input_ip = ipaddress.ip_address(input_str.split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
        except ValueError:
            try:
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            except ValueError:
                return False

        # При поиске по СЕТИ принудительно включает strict_mode
        effective_strict_mode = strict_mode or is_search_network

        # 5. Проверка объектов-кандидатов
        for cand in candidates:
            if cand in ANY_VARIANTS:
                if ignore_any:
                    continue
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    continue
                return not effective_strict_mode

            cand_net = self._cand_to_net(cand)

            # Проверка лимита маски
            if parsed_mask_limit is not None:
                if cand_net is not None:
                    if cand_net.prefixlen > parsed_mask_limit:
                        continue
                elif isinstance(cand, tuple) and len(cand) == 2:
                    start, end = cand
                    range_size = int(end) - int(start) + 1
                    min_allowed_size = 2 ** (32 - parsed_mask_limit)
                    if range_size < min_allowed_size:
                        continue

            # --- СТРОГИЙ РЕЖИМ ---
            if effective_strict_mode:
                if cand_net and cand_net == input_net:
                    return True
                elif isinstance(cand, tuple) and len(cand) == 2:
                    start, end = cand
                    if input_net and int(input_net.network_address) == int(start) and int(
                            input_net.broadcast_address) == int(end):
                        return True
            # --- ОБЫЧНЫЙ РЕЖИМ ---
            else:
                try:
                    if input_ip is not None:
                        if isinstance(cand, tuple) and len(cand) == 2:
                            start, end = cand
                            if start <= input_ip <= end:
                                return True
                        elif cand_net and input_ip in cand_net:
                            return True
                    else:
                        if isinstance(cand, tuple) and len(cand) == 2:
                            start, end = cand
                            if max(int(input_net.network_address), int(start)) <= min(int(input_net.broadcast_address),
                                                                                      int(end)):
                                return True
                        elif cand_net and input_net.overlaps(cand_net):
                            return True
                except Exception:
                    continue

        return False

    def _extract_src_dst(self, parts):
        i = 4
        if parts[i] in ('ip', 'tcp', 'udp', 'icmp'):
            i += 1
        elif i < len(parts) and parts[i] == 'object-group':
            i += 2

        def parse_entry(idx):
            if idx >= len(parts):
                return None, idx + 1
            if parts[idx] in ("object-group", "object"):
                return parts[idx + 1], idx + 2
            elif parts[idx] == "host":
                return parts[idx + 1] + "/32", idx + 2
            elif parts[idx] in ("any", "any4"):
                return "any", idx + 1
            elif self._is_ip(parts[idx]):
                if idx + 1 < len(parts) and self._is_dotted_decimal(parts[idx + 1]):
                    second = parts[idx + 1]
                    if second.startswith('255'):
                        return ('netmask', parts[idx], second), idx + 2
                    else:
                        try:
                            start = ipaddress.ip_address(parts[idx])
                            end = ipaddress.ip_address(second)
                            if start > end:
                                start, end = end, start
                            return (start, end), idx + 2
                        except ValueError:
                            return parts[idx] + "/32", idx + 1
                else:
                    return parts[idx] + "/32", idx + 1
            return None, idx + 1

        src, i = parse_entry(i)
        dst, i = parse_entry(i)
        return src, dst

    def find_acl_matches(
            self,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        matches = []
        for line in self.acl_lines:
            parts = line.split()
            if len(parts) < 7:
                continue
            try:
                src_entry, dst_entry = self._extract_src_dst(parts)
                src_ips = self._resolve_entry(src_entry)
                dst_ips = self._resolve_entry(dst_entry)

                if src_ips == ["any"] and dst_ips == ["any"]:
                    continue

                src_ok = self._matches(
                    src_ip,
                    src_ips,
                    strict_mode,
                    ignore_any=ignore_src_any,
                    mask_limit=src_mask_limit
                )
                dst_ok = self._matches(
                    dst_ip,
                    dst_ips,
                    strict_mode,
                    ignore_any=ignore_dst_any,
                    mask_limit=dst_mask_limit
                )

                if src_ok and dst_ok:
                    matches.append(line)
            except Exception:
                continue
        return tuple(matches)

    # Алиасы для поддержания полной совместимости
    find_matches = find_acl_matches



class FortiOSParser2:
    def __init__(self, config_text):
        self.config_text = config_text
        self.objects = {}  # {name: [ip_network or (start_ip, end_ip)]}
        self.groups = defaultdict(list)  # {group_name: [members]}
        self.policies = []  # list of policies
        self._parse_objects()
        self._parse_groups()
        self._parse_policies()

    def _parse_objects(self):
        address_blocks = re.findall(r'edit "([^"]+)"(.*?)\n\s*next', self.config_text, re.S)
        for name, body in address_blocks:
            nets = []
            m_subnet = re.search(r'set subnet (\S+) (\S+)', body)
            if m_subnet:
                ip, mask = m_subnet.groups()
                try:
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                    nets.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
                except ValueError:
                    pass
            m_range = re.search(r'set start-ip (\S+)\s+set end-ip (\S+)', body)
            if m_range:
                start_ip, end_ip = m_range.groups()
                try:
                    nets.append((ipaddress.ip_address(start_ip), ipaddress.ip_address(end_ip)))
                except ValueError:
                    pass
            if nets:
                self.objects[name] = nets

    def _parse_groups(self):
        group_blocks = re.findall(r'edit "([^"]+)"(.*?)\n\s*next', self.config_text, re.S)
        for group_name, body in group_blocks:
            if "set member" in body:
                members = re.findall(r'"([^"]+)"', body)
                self.groups[group_name].extend(m for m in members if m != group_name)

    def _resolve_group(self, name):
        """
        Рекурсивно резолвит группу. Если среди членов (в т.ч. вложенных)
        находится "all" / "any", группа возвращается как "all".
        """
        results = []
        visited = set()

        def _resolve(n):
            if n in visited:
                return False
            visited.add(n)

            if n.lower() in ("any", "all", "0.0.0.0/0"):
                return True  # Наткнулись на ALL

            if n in self.objects:
                results.extend(self.objects[n])
            elif n in self.groups:
                for m in self.groups[n]:
                    if _resolve(m):
                        return True
            return False

        contains_all = _resolve(name)
        if contains_all:
            return "all"  # Вся группа рассматривается как системный объект ALL
        return results

    def _parse_policies(self):
        policy_blocks = re.findall(r'edit \d+(.*?)\n\s*next', self.config_text, re.S)
        for body in policy_blocks:
            if re.search(r'set status disable', body):
                continue
            src_list = re.findall(r'set srcaddr (.+)', body)
            dst_list = re.findall(r'set dstaddr (.+)', body)
            service_list = re.findall(r'set service (.+)', body)

            def extract_names(raw_str):
                quoted = re.findall(r'"([^"]+)"', raw_str)
                if quoted:
                    return quoted
                return raw_str.strip().split()

            src_list = extract_names(src_list[0]) if src_list else []
            dst_list = extract_names(dst_list[0]) if dst_list else []
            service_list = extract_names(service_list[0]) if service_list else []

            self.policies.append({
                'srcaddr': src_list,
                'dstaddr': dst_list,
                'service': service_list
            })

    def _ip_in_object(self, input_str, obj_name, strict_mode, ignore_any=False, mask_limit=None):
        # 1. Резолвим группу/объект
        resolved_entries = None
        if obj_name.lower() in ("any", "all"):
            is_any_obj = True
        elif obj_name in self.groups:
            resolved = self._resolve_group(obj_name)
            if resolved == "all":
                is_any_obj = True
            else:
                is_any_obj = False
                resolved_entries = resolved
        else:
            is_any_obj = False
            resolved_entries = self.objects.get(obj_name, [])

        # 2. СТРОГАЯ ПРОВЕРКА IGNORE_ANY (Выполняется первей всего!)
        if ignore_any and is_any_obj:
            return False

        # 3. Нормализация mask_limit (принимает "/27", "27", 27)
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                if isinstance(mask_limit, str):
                    parsed_mask_limit = int(mask_limit.replace("/", "").strip())
                elif isinstance(mask_limit, int):
                    parsed_mask_limit = mask_limit
            except ValueError:
                parsed_mask_limit = None

        # 4. Если сам поисковый запрос равен "any"
        if input_str == "any":
            if is_any_obj:
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    return False
                return True
            return not strict_mode

        if is_any_obj:
            if parsed_mask_limit is not None and parsed_mask_limit > 0:
                return False
            return not strict_mode

        # 5. Парсинг поискового ввода (IP или Сеть)
        is_search_network = False
        try:
            if '/' in input_str and not input_str.endswith('/32'):
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            else:
                input_ip = ipaddress.ip_address(input_str.split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
        except ValueError:
            try:
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            except ValueError:
                return False

        # Если в поиске указана СЕТЬ (например, 10.68.230.0/25) — принудительно strict_mode=True
        effective_strict_mode = strict_mode or is_search_network

        def check_entry(entry):
            # Проверка лимита маски
            if parsed_mask_limit is not None:
                if isinstance(entry, ipaddress.IPv4Network):
                    if entry.prefixlen > parsed_mask_limit:
                        return False
                elif isinstance(entry, tuple):
                    start_ip, end_ip = entry
                    range_size = int(end_ip) - int(start_ip) + 1
                    min_allowed_size = 2 ** (32 - parsed_mask_limit)
                    if range_size < min_allowed_size:
                        return False

            # Проверка совпадения в зависимости от режима
            if isinstance(entry, tuple):
                start_ip, end_ip = entry
                if input_ip is not None:
                    if effective_strict_mode:
                        return start_ip == input_ip and end_ip == input_ip
                    else:
                        return start_ip <= input_ip <= end_ip
                return False
            else:
                if effective_strict_mode:
                    if input_net is not None:
                        return entry == input_net
                    return str(entry) == f"{input_ip}/32"
                else:
                    if input_ip is not None:
                        return input_ip in entry
                    else:
                        return entry.overlaps(input_net)

        # 6. Проверяем все извлеченные IP-записи
        if resolved_entries:
            for entry in resolved_entries:
                if check_entry(entry):
                    return True

        return False

    def find_acl_matches(
            self,
            src_ip,
            dst_ip,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        matches = set()
        for policy in self.policies:
            for src in policy['srcaddr']:
                for dst in policy['dstaddr']:
                    # Если и src и dst равны any/all — пропускаем базовый all-to-all
                    if src.lower() in ("any", "all") and dst.lower() in ("any", "all"):
                        continue

                    src_ok = self._ip_in_object(
                        src_ip, src, strict_mode,
                        ignore_any=ignore_src_any,
                        mask_limit=src_mask_limit
                    )
                    dst_ok = self._ip_in_object(
                        dst_ip, dst, strict_mode,
                        ignore_any=ignore_dst_any,
                        mask_limit=dst_mask_limit
                    )

                    if src_ok and dst_ok:
                        matches.add(f"{src} > {dst} : {', '.join(policy['service'])}")

        return tuple(matches)

    # find_acl_matches = search
    # @classmethod
    # def from_local_file(
    #         cls,
    #         filename,
    #         src_ip,
    #         dst_ip,
    #         strict_mode=False,
    #         ignore_src_any=False,
    #         ignore_dst_any=False,
    #         src_mask_limit=None,
    #         dst_mask_limit=None,
    #         base_dir=base_dir,
    #         encoding="utf-8"
    # ):
    #     for root, _, files in os.walk(base_dir):
    #         for file in files:
    #             if file == filename:
    #                 full_path = os.path.join(root, filename)
    #                 try:
    #                     with open(full_path, "r", encoding=encoding, errors="ignore") as f:
    #                         config_text = f.read()
    #                 except Exception as e:
    #                     raise Exception(f"Error reading {full_path}: {e}")
    #
    #                 parser = cls(config_text)
    #                 return parser.search(
    #                     src_ip,
    #                     dst_ip,
    #                     strict_mode=strict_mode,
    #                     ignore_src_any=ignore_src_any,
    #                     ignore_dst_any=ignore_dst_any,
    #                     src_mask_limit=src_mask_limit,
    #                     dst_mask_limit=dst_mask_limit
    #                 )
    #
    #     return tuple()


class HuaweiParser4:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.acls = {}  # Старый стиль (коммутаторы)
        self.acl_headers = {}
        self.firewall_rules = []  # Новый стиль (Firewall)
        self.address_sets = {}
        self.parse()

    def _parse_address_set(self, start_idx):
        i = start_idx - 1
        line = self.config_lines[i].strip()

        parts = line.split()
        if len(parts) < 3 or parts[1] != "address-set":
            return start_idx

        name = parts[2]
        specs = []

        i = start_idx
        while i < len(self.config_lines):
            line = self.config_lines[i].strip()
            if not line or line.startswith(("ip address-set", "#", "rule name", "security-policy")):
                break

            if line.startswith("address "):
                parts = line.split()
                try:
                    if "mask" in parts:
                        mask_idx = parts.index("mask")
                        if mask_idx >= 3 and mask_idx + 1 < len(parts):
                            ip_part = parts[mask_idx - 1]
                            mask_str = parts[mask_idx + 1]
                            net = ipaddress.IPv4Network(f"{ip_part}/{mask_str}", strict=False)
                            specs.append(str(net))
                            i += 1
                            continue

                    for p in parts:
                        if p.count('.') == 3:
                            try:
                                ipaddress.IPv4Address(p)
                                specs.append(f"{p}/32")
                            except ValueError:
                                pass
                except Exception:
                    pass

            i += 1

        if name:
            self.address_sets[name] = specs

        return i

    def parse(self):
        current_acl = None
        current_header = None

        i = 0
        while i < len(self.config_lines):
            line = self.config_lines[i].strip()
            if not line:
                i += 1
                continue

            # === Старый стиль: ACL для коммутаторов ===
            if line.startswith(("acl number", "acl name")):
                if line.startswith("acl number"):
                    parts = line.split()
                    current_acl = parts[2] if len(parts) >= 3 else None
                    current_header = "acl number " + current_acl if current_acl else line
                else:
                    parts = line.split()
                    name = parts[2] if len(parts) >= 3 else ""
                    number = parts[3] if len(parts) > 3 else ""
                    current_acl = number if number else name
                    current_header = line

                if current_acl:
                    self.acls.setdefault(current_acl, {})
                    self.acl_headers[current_acl] = current_header
                i += 1
                continue

            # === Новый стиль: Firewall rules ===
            if line.startswith("rule name "):
                rule_name = line[10:].strip()
                i = self._parse_firewall_rule(i + 1, rule_name)
                continue

            if line.startswith("ip address-set "):
                i = self._parse_address_set(i + 1)
                continue

            # === Старый стиль правил внутри ACL ===
            if current_acl and line.startswith("rule"):
                if "description" in line.lower():
                    i += 1
                    continue
                try:
                    pairs = self._parse_rule(line)
                    cleaned = [(s, d) for s, d in pairs if not (s == "any" and d == "any")]
                    if cleaned:
                        self.acls[current_acl][line] = cleaned
                except Exception:
                    pass
                i += 1
                continue

            i += 1

    def _parse_firewall_rule(self, start_idx, rule_name):
        rule = {
            'name': rule_name.strip('"'),
            'source_addresses': [],
            'destination_addresses': [],
            'services': [],
            'action': 'deny',
            'disabled': False
        }

        i = start_idx
        while i < len(self.config_lines):
            line = self.config_lines[i].strip()

            if (not line or line.startswith("rule name ") or line.startswith("#") or
                    line.startswith("security-policy") or line.startswith("auth-policy") or
                    line.startswith("traffic-policy") or line.startswith("ip address-set")):
                break

            if line == "disable":
                rule['disabled'] = True

            elif line.startswith("source-address "):
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "address-set":
                    rule['source_addresses'].append(parts[2])
                elif len(parts) >= 2:
                    if len(parts) >= 4 and parts[2] == "mask":
                        rule['source_addresses'].append(self._mask_to_cidr(parts[1], parts[3]))
                    else:
                        rule['source_addresses'].append(f"{parts[1]}/32")

            elif line.startswith("destination-address "):
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "address-set":
                    rule['destination_addresses'].append(parts[2])
                elif len(parts) >= 2:
                    if len(parts) >= 4 and parts[2] == "mask":
                        rule['destination_addresses'].append(self._mask_to_cidr(parts[1], parts[3]))
                    else:
                        rule['destination_addresses'].append(f"{parts[1]}/32")

            elif line.startswith("service ") or line.startswith("service-set "):
                svc = line.split(maxsplit=1)[1].strip().strip('"')
                rule['services'].append(svc)

            elif line.startswith("action "):
                rule['action'] = line.split(maxsplit=1)[1].strip()

            i += 1

        if not rule['disabled']:
            if not rule['source_addresses']:
                rule['source_addresses'] = ["any"]
            if not rule['destination_addresses']:
                rule['destination_addresses'] = ["any"]
            if not rule['services']:
                rule['services'] = ["any"]

            self.firewall_rules.append(rule)

        return i

    def _mask_to_cidr(self, ip, mask):
        try:
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return str(net)
        except Exception:
            return f"{ip}/32"

    # ====================== СТАРЫЙ СТИЛЬ ======================
    def _parse_rule(self, line):
        parts = line.split()
        src_spec = "any"
        dst_spec = "any"

        if "source" in parts:
            i = parts.index("source")
            src_spec = self._parse_addr_with_wildcard(parts, i + 1)

        if "destination" in parts:
            i = parts.index("destination")
            dst_spec = self._parse_addr_with_wildcard(parts, i + 1)

        return [(src_spec, dst_spec)]

    def _parse_addr_with_wildcard(self, parts, idx):
        if idx >= len(parts):
            return "any"

        ip = parts[idx]
        wc = None
        if idx + 1 < len(parts) and self._looks_like_wildcard(parts[idx + 1]):
            wc = parts[idx + 1]

        if wc is None:
            return f"{ip}/32"

        return self._wildcard_to_network_or_range(ip, wc)

    def _looks_like_wildcard(self, s: str) -> bool:
        if s.count(".") == 3:
            try:
                ipaddress.IPv4Address(s)
                return True
            except ValueError:
                return False
        return s.isdigit()

    def _wildcard_to_network_or_range(self, ip_str: str, wildcard_str: str):
        try:
            if wildcard_str.count(".") == 3:
                w = int(ipaddress.IPv4Address(wildcard_str))
            else:
                w = int(wildcard_str)
                if not (0 <= w <= 0xFFFFFFFF):
                    raise ValueError
        except Exception:
            return f"{ip_str}/32"

        if w == 0:
            return f"{ip_str}/32"

        if (w & (w + 1)) == 0:
            k = bin(w).count("1")
            prefix = 32 - k
            try:
                net = ipaddress.IPv4Network((ip_str, prefix), strict=True)
                return str(net)
            except ValueError:
                pass

        ip_int = int(ipaddress.IPv4Address(ip_str))
        start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
        end = (ip_int | w) & 0xFFFFFFFF
        return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))

    # ====================== ОБЩАЯ ЛОГИКА СРАВНЕНИЯ ======================
    def _parse_search(self, text):
        if not text or text == "any":
            return "any"
        if "/" in text:
            try:
                return str(ipaddress.ip_network(text, strict=False))
            except ValueError:
                return None
        if " " in text:
            parts = text.split()
            return self._wildcard_to_network_or_range(parts[0], parts[1])
        return f"{text}/32"

    def _resolve_spec(self, spec):
        """Разворачивает address-set в плоский список спецификаций."""
        if not spec or spec in ("any", "any4", "all", "0.0.0.0/0"):
            return ["any"]
        if spec in self.address_sets:
            resolved = []
            for item in self.address_sets[spec]:
                if item in ("any", "any4", "all", "0.0.0.0/0"):
                    return ["any"]
                resolved.extend(self._resolve_spec(item))
            return resolved if resolved else ["any"]
        return [spec]

    def _spec_intersects(self, spec_search, spec_rule, strict_mode, ignore_any=False, mask_limit=None):
        ANY_VARIANTS = ("any", "any4", "all", "0.0.0.0/0")

        candidates = self._resolve_spec(spec_rule)

        # 1. СТРОГАЯ ПРОВЕРКА IGNORE_ANY
        is_any_in_candidates = any(c in ANY_VARIANTS for c in candidates)
        if ignore_any and is_any_in_candidates:
            return False

        # 2. Нормализация mask_limit
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                if isinstance(mask_limit, str):
                    parsed_mask_limit = int(mask_limit.replace("/", "").strip())
                elif isinstance(mask_limit, int):
                    parsed_mask_limit = mask_limit
            except ValueError:
                parsed_mask_limit = None

        # 3. Обработка search == "any"
        if spec_search == "any":
            if is_any_in_candidates:
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    return False
                return True
            return not strict_mode

        if is_any_in_candidates:
            if parsed_mask_limit is not None and parsed_mask_limit > 0:
                return False
            return not strict_mode

        # 4. Анализ поискового ввода
        is_search_network = False
        try:
            if isinstance(spec_search, str) and '/' in spec_search and not spec_search.endswith('/32'):
                input_net = ipaddress.ip_network(spec_search, strict=False)
                input_ip = None
                is_search_network = True
            elif isinstance(spec_search, str):
                input_ip = ipaddress.ip_address(spec_search.split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
            else:
                return False
        except ValueError:
            return False

        effective_strict_mode = strict_mode or is_search_network

        # 5. Проверка кандидатов
        for cand in candidates:
            if cand in ANY_VARIANTS:
                if ignore_any:
                    continue
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    continue
                return not effective_strict_mode

            # Парсим кандидата
            cand_net = None
            cand_range = None

            if isinstance(cand, tuple) and len(cand) == 3 and cand[0] == "range":
                cand_range = (cand[1], cand[2])
            elif isinstance(cand, str):
                try:
                    cand_net = ipaddress.ip_network(cand, strict=False)
                except ValueError:
                    continue

            # Проверка маски limit
            if parsed_mask_limit is not None:
                if cand_net is not None:
                    if cand_net.prefixlen > parsed_mask_limit:
                        continue
                elif cand_range is not None:
                    range_size = int(cand_range[1]) - int(cand_range[0]) + 1
                    min_allowed_size = 2 ** (32 - parsed_mask_limit)
                    if range_size < min_allowed_size:
                        continue

            # Сравнение
            if effective_strict_mode:
                if cand_net and cand_net == input_net:
                    return True
            else:
                if input_ip is not None:
                    if cand_range:
                        if cand_range[0] <= input_ip <= cand_range[1]:
                            return True
                    elif cand_net:
                        if input_ip in cand_net:
                            return True
                else:
                    if cand_net and input_net.overlaps(cand_net):
                        return True

        return False

    def find_acl_matches(
            self,
            src_ip,
            dst_ip,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        src_spec_search = self._parse_search(src_ip)
        dst_spec_search = self._parse_search(dst_ip)

        if src_spec_search is None or dst_spec_search is None:
            return ()

        results = []

        # 1. Старый стиль — ACL коммутаторов
        for acl_key, rules in self.acls.items():
            matched_rules = []
            for rule_line, pairs in rules.items():
                for src_spec, dst_spec in pairs:
                    src_ok = self._spec_intersects(
                        src_spec_search,
                        src_spec,
                        strict_mode,
                        ignore_any=ignore_src_any,
                        mask_limit=src_mask_limit
                    )
                    dst_ok = self._spec_intersects(
                        dst_spec_search,
                        dst_spec,
                        strict_mode,
                        ignore_any=ignore_dst_any,
                        mask_limit=dst_mask_limit
                    )
                    if src_ok and dst_ok:
                        matched_rules.append(rule_line)
                        break
            if matched_rules:
                header = self.acl_headers.get(acl_key, f"acl {acl_key}")
                results.append(header)
                for r in matched_rules:
                    results.append(f"  {r}")

        # 2. Новый стиль — Firewall rules
        for rule in self.firewall_rules:
            src_addrs = rule['source_addresses']
            dst_addrs = rule['destination_addresses']
            services_str = ", ".join(rule['services']) if rule['services'] and rule['services'] != ["any"] else "any"
            action = rule['action']

            for s_addr, d_addr in product(src_addrs, dst_addrs):
                if s_addr == "any" and d_addr == "any":
                    continue

                src_ok = self._spec_intersects(
                    src_spec_search,
                    s_addr,
                    strict_mode,
                    ignore_any=ignore_src_any,
                    mask_limit=src_mask_limit
                )
                dst_ok = self._spec_intersects(
                    dst_spec_search,
                    d_addr,
                    strict_mode,
                    ignore_any=ignore_dst_any,
                    mask_limit=dst_mask_limit
                )

                if src_ok and dst_ok:
                    line = f"{rule['name']} {s_addr} {d_addr} {services_str} {action}"
                    results.append(line)

        return tuple(results)

    @classmethod
    def from_local_file(
            cls,
            filename,
            src_ip,
            dst_ip,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None,
            base_dir=base_dir,
            encoding="utf-8"
    ):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                    except Exception:
                        return ()
                    parser = cls(config_text)
                    return parser.find_acl_matches(
                        src_ip,
                        dst_ip,
                        strict_mode=strict_mode,
                        ignore_src_any=ignore_src_any,
                        ignore_dst_any=ignore_dst_any,
                        src_mask_limit=src_mask_limit,
                        dst_mask_limit=dst_mask_limit
                    )
        return ()


class CiscoNexusParser2:
    def __init__(self, config_or_lines):
        # Если передали единую строку (например, из f.read()), разбиваем её на строки
        if isinstance(config_or_lines, str):
            self.lines = config_or_lines.splitlines()
        else:
            self.lines = config_or_lines

        self.object_groups = defaultdict(list)
        self.acl_lines = []
        self.parse()

    def parse(self):
        current_group = None
        current_acl = None
        in_group = False
        in_acl = False
        current_values = []

        for line in self.lines:
            original_line = line
            line = line.strip()
            if not line:
                continue

            # Close group if starting a new top-level command
            if line.startswith("ip access-list") and in_group:
                self.object_groups[current_group] = current_values
                in_group = False
                current_group = None

            # Object-group parsing
            if line.startswith("object-group ip address"):
                if current_group:
                    self.object_groups[current_group] = current_values
                parts = line.split()
                current_group = parts[3] if len(parts) > 3 else parts[2]
                current_values = []
                in_group = True
                continue
            if in_group:
                parts = line.split()
                idx = 0
                if parts and parts[0].isdigit():  # Skip sequence
                    idx += 1
                if idx < len(parts):
                    entry = ' '.join(parts[idx:])
                    if entry.startswith("host"):
                        ip = entry.split()[1]
                        current_values.append(ip + "/32")
                    elif entry.startswith("network-object"):
                        subparts = entry.split()
                        if len(subparts) >= 3:
                            if subparts[1] == "host":
                                current_values.append(subparts[2] + "/32")
                            else:
                                try:
                                    addr_mask = ' '.join(subparts[1:])
                                    if '/' in addr_mask:
                                        net = ipaddress.ip_network(addr_mask, strict=False)
                                    else:
                                        net = ipaddress.ip_network((subparts[1], subparts[2]), strict=False)
                                    current_values.append(str(net))
                                except ValueError:
                                    pass
                    else:
                        # direct entry
                        parts_entry = entry.split()
                        if len(parts_entry) == 1:
                            if '/' in entry:
                                try:
                                    net = ipaddress.ip_network(entry, strict=False)
                                    current_values.append(str(net))
                                except ValueError:
                                    pass
                            elif self._is_ip_or_net(entry):
                                current_values.append(entry + "/32")
                        elif len(parts_entry) == 2:
                            if parts_entry[0] == "host":
                                current_values.append(parts_entry[1] + "/32")
                            else:
                                try:
                                    net = ipaddress.ip_network((parts_entry[0], parts_entry[1]), strict=False)
                                    current_values.append(str(net))
                                except ValueError:
                                    pass
                if line == "exit" or line == "}":
                    if current_group:
                        self.object_groups[current_group] = current_values
                    current_group = None
                    in_group = False
                    current_values = []
                continue

            # ACL parsing
            if line.startswith("ip access-list"):
                parts = line.split()
                if len(parts) >= 3:
                    current_acl = parts[2]
                    in_acl = True
                continue
            if in_acl:
                parts = line.split()
                if parts and (parts[0] in ("permit", "deny") or (
                        parts[0].isdigit() and len(parts) > 1 and parts[1] in ("permit", "deny"))):
                    self.acl_lines.append((current_acl, original_line))
                elif line.startswith("statistics per-entry"):
                    continue
                elif line == "exit" or line == "}":
                    in_acl = False
                    current_acl = None
                continue

        if in_group and current_group:
            self.object_groups[current_group] = current_values

    def _cand_to_net(self, cand):
        try:
            if isinstance(cand, str):
                if '/' in cand:
                    return ipaddress.ip_network(cand, strict=False)
                elif ' ' in cand:
                    parts = cand.split()
                    if len(parts) == 2:
                        return ipaddress.ip_network((parts[0], parts[1]), strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
            elif isinstance(cand, tuple) and len(cand) == 2:
                if cand[0] == cand[1]:
                    return ipaddress.ip_network(str(cand[0]) + '/32', strict=False)
        except ValueError:
            return None
        return None

    def _matches(self, input_str, candidates, strict_mode, ignore_any=False, mask_limit=None):
        ANY_VARIANTS = ("any", "any4", "all", "0.0.0.0/0")

        # 1. СТРОГАЯ ПРОВЕРКА IGNORE_ANY (Первей всего!)
        is_any_in_candidates = any(c in ANY_VARIANTS for c in candidates)
        if ignore_any and is_any_in_candidates:
            return False

        # 2. Нормализация mask_limit
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                if isinstance(mask_limit, str):
                    parsed_mask_limit = int(mask_limit.replace("/", "").strip())
                elif isinstance(mask_limit, int):
                    parsed_mask_limit = mask_limit
            except ValueError:
                parsed_mask_limit = None

        # 3. Если ищем "any"
        if not input_str or input_str == "any":
            if is_any_in_candidates:
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    return False
                return True
            return not strict_mode

        if is_any_in_candidates:
            if parsed_mask_limit is not None and parsed_mask_limit > 0:
                return False
            return not strict_mode

        # 4. Парсинг поискового ввода (IP или Сеть)
        is_search_network = False
        try:
            if '/' in input_str and not input_str.endswith('/32'):
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            else:
                input_ip = ipaddress.ip_address(input_str.split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
        except ValueError:
            try:
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            except ValueError:
                return False

        # При поиске по СЕТИ принудительно strict_mode = True
        effective_strict_mode = strict_mode or is_search_network

        # 5. Проверка кандидатов
        for cand in candidates:
            if cand in ANY_VARIANTS:
                if ignore_any:
                    continue
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    continue
                return not effective_strict_mode

            cand_net = self._cand_to_net(cand)

            # Проверка лимита маски
            if parsed_mask_limit is not None:
                if cand_net is not None:
                    if cand_net.prefixlen > parsed_mask_limit:
                        continue
                elif isinstance(cand, tuple) and len(cand) == 2:
                    start, end = cand
                    range_size = int(end) - int(start) + 1
                    min_allowed_size = 2 ** (32 - parsed_mask_limit)
                    if range_size < min_allowed_size:
                        continue

            # --- СТРОГИЙ РЕЖИМ ---
            if effective_strict_mode:
                if cand_net and cand_net == input_net:
                    return True
            # --- ОБЫЧНЫЙ РЕЖИМ ---
            else:
                try:
                    if input_ip is not None:
                        if isinstance(cand, tuple) and len(cand) == 2:
                            start, end = cand
                            if start <= input_ip <= end:
                                return True
                        elif cand_net:
                            if input_ip in cand_net:
                                return True
                        elif self._is_ip_or_net(cand):
                            if input_ip == ipaddress.ip_address(cand):
                                return True
                    else:
                        if cand_net and input_net.overlaps(cand_net):
                            return True
                except Exception:
                    continue

        return False

    def _is_ip_or_net(self, s):
        try:
            if '/' in s:
                ipaddress.ip_network(s, strict=False)
            else:
                ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _is_port_operator(self, token):
        return token in PORT_OPS

    def _extract_src_dst(self, parts):
        idx = 0
        if parts and parts[0].isdigit():
            idx += 1
        if idx < len(parts) and parts[idx] in ('permit', 'deny'):
            idx += 1
        if idx < len(parts) and parts[idx] not in ('any', 'host', 'object-group',
                                                   'addrgroup') and not self._is_ip_or_net(parts[idx]):
            idx += 1

        def parse_entry(idx):
            if idx >= len(parts):
                return None, idx
            val = parts[idx]
            if val in ("object-group", "addrgroup"):
                if idx + 1 < len(parts):
                    return parts[idx + 1], idx + 2
                return None, idx + 1
            elif val == "host":
                if idx + 1 < len(parts):
                    return f"{parts[idx + 1]}/32", idx + 2
                return None, idx + 1
            elif val in ("any", "any4"):
                return "any", idx + 1
            elif '/' in val:
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    return str(net), idx + 1
                except ValueError:
                    return None, idx + 1
            elif self._is_ip_or_net(val):
                if idx + 1 < len(parts) and self._is_ip_or_net(parts[idx + 1]):
                    try:
                        net = ipaddress.ip_network((val, parts[idx + 1]), strict=False)
                        return str(net), idx + 2
                    except ValueError:
                        return f"{val}/32", idx + 1
                else:
                    return f"{val}/32", idx + 1
            return None, idx + 1

        src_entry, idx = parse_entry(idx)

        while idx < len(parts) and self._is_port_operator(parts[idx]):
            op = parts[idx]
            idx += 1
            if op == 'range':
                if idx < len(parts):
                    idx += 1
                if idx < len(parts):
                    idx += 1
            else:
                if idx < len(parts):
                    idx += 1

        dst_entry, idx = parse_entry(idx)

        while idx < len(parts) and self._is_port_operator(parts[idx]):
            op = parts[idx]
            idx += 1
            if op == 'range':
                if idx < len(parts):
                    idx += 1
                if idx < len(parts):
                    idx += 1
            else:
                if idx < len(parts):
                    idx += 1

        return src_entry, dst_entry

    def _resolve_entry(self, entry):
        if not entry or entry in ("any", "any4", "all"):
            return ["any"]
        if "/" in entry or self._is_ip_or_net(entry):
            return [entry]
        if entry in self.object_groups:
            resolved = []
            for sub in self.object_groups[entry]:
                if sub in ("any", "any4", "all", "0.0.0.0/0"):
                    return ["any"]
                if self._is_ip_or_net(sub) and '/' not in sub:
                    resolved.append(sub + "/32")
                else:
                    sub_resolved = self._resolve_entry(sub)
                    if sub_resolved == ["any"]:
                        return ["any"]
                    resolved.extend(sub_resolved)
            return resolved
        return []

    def find_acl_matches(
            self,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        matches = []
        current_acl = None
        for acl_name, line in self.acl_lines:
            parts = line.strip().split()
            if len(parts) < 4:
                continue
            try:
                src_entry, dst_entry = self._extract_src_dst(parts)
                src_candidates = self._resolve_entry(src_entry)
                dst_candidates = self._resolve_entry(dst_entry)

                if src_candidates == ["any"] and dst_candidates == ["any"]:
                    continue

                src_ok = self._matches(
                    src_ip,
                    src_candidates,
                    strict_mode,
                    ignore_any=ignore_src_any,
                    mask_limit=src_mask_limit
                )
                dst_ok = self._matches(
                    dst_ip,
                    dst_candidates,
                    strict_mode,
                    ignore_any=ignore_dst_any,
                    mask_limit=dst_mask_limit
                )

                if src_ok and dst_ok:
                    if acl_name != current_acl:
                        if current_acl is not None:
                            matches.append("")
                        matches.append(f"ip access-list {acl_name}")
                        current_acl = acl_name
                    matches.append(line.rstrip())
            except Exception:
                continue
        return tuple(matches)



class JuniperACLParser2:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.filters = defaultdict(dict)  # filter_name -> {term_name: list of rules}
        self.prefix_lists = defaultdict(list)  # prefix-list name -> [networks]
        self.address_book = defaultdict(list)  # address-book name -> [networks]
        self.parse()

    def parse(self):
        """
        Разбор firewall filter в конфигурации Juniper.
        Сохраняет только те filter/term, где then = accept / discard / reject.
        """
        current_filter = None
        current_term = None
        current_sources = []
        current_dests = []
        current_action = None
        in_from = False
        in_source_address = False
        in_destination_address = False
        in_then = False

        for line in self.config_lines:
            line = line.strip()

            # Пропускаем пустые строки
            if not line:
                continue

            # Начало нового filter
            if line.startswith("filter "):
                parts = line.split()
                if len(parts) >= 2 and parts[1] != "{":
                    current_filter = parts[1]
                    self.filters[current_filter] = {}
                continue

            # Начало term
            if line.startswith("term "):
                parts = line.split()
                if len(parts) >= 2 and parts[1] != "{":
                    current_term = parts[1]
                    current_sources, current_dests, current_action = [], [], None
                    in_from = False
                    in_source_address = False
                    in_destination_address = False
                    in_then = False
                continue

            # Начало from {
            if line == "from {":
                in_from = True
                continue

            # Начало source-address {
            if line == "source-address {" and in_from:
                in_source_address = True
                continue

            # Начало destination-address {
            if line == "destination-address {" and in_from:
                in_destination_address = True
                continue

            # IP в source-address
            if in_source_address and line.endswith(";"):
                ip = line.replace(";", "").strip()
                if ip:
                    current_sources.append(ip)
                continue

            # IP в destination-address
            if in_destination_address and line.endswith(";"):
                ip = line.replace(";", "").strip()
                if ip:
                    current_dests.append(ip)
                continue

            # Начало then { или then accept;
            if line.startswith("then"):
                if line == "then {":
                    in_then = True
                else:
                    # Прямой then accept;
                    action_part = line.split("then")[1].strip().replace(";", "")
                    if action_part in ("accept", "discard", "reject"):
                        current_action = action_part
                continue

            # Action внутри then {
            if in_then and line.endswith(";"):
                action = line.replace(";", "").strip()
                if action in ("accept", "discard", "reject"):
                    current_action = action
                continue

            # Закрывающие скобки }
            if line == "}":
                if in_source_address:
                    in_source_address = False
                elif in_destination_address:
                    in_destination_address = False
                elif in_from:
                    in_from = False
                elif in_then:
                    in_then = False
                elif current_term and current_action:
                    # Закрытие term
                    if current_term not in self.filters[current_filter]:
                        self.filters[current_filter][current_term] = []
                    self.filters[current_filter][current_term].append(
                        {"term": current_term,
                         "src": current_sources or ["any"],
                         "dst": current_dests or ["any"],
                         "action": current_action}
                    )
                    current_term, current_sources, current_dests, current_action = None, [], [], None
                    in_from = False
                    in_source_address = False
                    in_destination_address = False
                    in_then = False

    def _cand_to_net(self, cand):
        try:
            if isinstance(cand, str):
                if '/' in cand:
                    return ipaddress.ip_network(cand, strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
        except ValueError:
            return None
        return None

    def _matches(self, input_str, ip_list, strict_mode, ignore_any=False, mask_limit=None):
        ANY_VARIANTS = ("any", "any4", "all", "0.0.0.0/0")

        # 1. СТРОГАЯ ПРОВЕРКА IGNORE_ANY
        is_any_in_candidates = any(c in ANY_VARIANTS for c in ip_list)
        if ignore_any and is_any_in_candidates:
            return False

        # 2. Нормализация mask_limit
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                if isinstance(mask_limit, str):
                    parsed_mask_limit = int(mask_limit.replace("/", "").strip())
                elif isinstance(mask_limit, int):
                    parsed_mask_limit = mask_limit
            except ValueError:
                parsed_mask_limit = None

        # 3. Если ищем "any"
        if not input_str or input_str == "any":
            if is_any_in_candidates:
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    return False
                return True
            return not strict_mode

        if is_any_in_candidates:
            if parsed_mask_limit is not None and parsed_mask_limit > 0:
                return False
            return not strict_mode

        # 4. Анализ поискового запроса (IP или Сеть)
        is_search_network = False
        try:
            if '/' in input_str and not input_str.endswith('/32'):
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            else:
                input_ip = ipaddress.ip_address(input_str.split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
        except ValueError:
            try:
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            except ValueError:
                return False

        # При поиске по СЕТИ принудительно включает strict_mode
        effective_strict_mode = strict_mode or is_search_network

        # 5. Проверка кандидатов
        for cand in ip_list:
            if cand in ANY_VARIANTS:
                if ignore_any:
                    continue
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    continue
                return not effective_strict_mode

            cand_net = self._cand_to_net(cand)

            # Проверка лимита маски
            if parsed_mask_limit is not None and cand_net is not None:
                if cand_net.prefixlen > parsed_mask_limit:
                    continue

            # --- СТРОГИЙ РЕЖИМ ---
            if effective_strict_mode:
                if cand_net and cand_net == input_net:
                    return True
            # --- ОБЫЧНЫЙ РЕЖИМ ---
            else:
                try:
                    if input_ip is not None:
                        if cand_net and input_ip in cand_net:
                            return True
                    else:
                        if cand_net and input_net.overlaps(cand_net):
                            return True
                except Exception:
                    continue

        return False

    def find_acl_matches(
            self,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        results = []
        for filt, terms in self.filters.items():
            if str(filt) == "None":  # Игнорируем фильтр с именем None
                continue
            matched = []
            for term, rules in terms.items():
                for rule in rules:
                    if not rule["action"]:
                        continue
                    # Пропускаем правила с src=any и dst=any
                    if rule["src"] == ["any"] and rule["dst"] == ["any"]:
                        continue

                    src_ok = self._matches(
                        src_ip,
                        rule["src"],
                        strict_mode,
                        ignore_any=ignore_src_any,
                        mask_limit=src_mask_limit
                    )
                    dst_ok = self._matches(
                        dst_ip,
                        rule["dst"],
                        strict_mode,
                        ignore_any=ignore_dst_any,
                        mask_limit=dst_mask_limit
                    )

                    if src_ok and dst_ok:
                        src = ", ".join(rule["src"]) if rule["src"] != ["any"] else "any"
                        dst = ", ".join(rule["dst"]) if rule["dst"] != ["any"] else "any"
                        matched.append(f"term {term} {rule['action']} ip source {src} destination {dst}")

            if matched:
                results.append(f"filter {filt}:")
                results.extend("  " + m for m in matched)

        return tuple(results)

    @classmethod
    def from_local_file(
            cls,
            filename,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None,
            base_dir=base_dir,
            encoding="utf-8"
    ):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                    except Exception:
                        return tuple()
                    parser = cls(config_text)
                    return tuple(
                        parser.find_acl_matches(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            strict_mode=strict_mode,
                            ignore_src_any=ignore_src_any,
                            ignore_dst_any=ignore_dst_any,
                            src_mask_limit=src_mask_limit,
                            dst_mask_limit=dst_mask_limit
                        )
                    )
        return tuple()


class EltexACLParser2:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.acls = {}  # {acl_name: [ {source, service, raw}, ... ]}
        self.parse()

    def parse(self):
        current_acl = None
        for line in self.config_lines:
            line = line.strip()
            m = re.match(r'^management access-list (\S+)', line)
            if m:
                current_acl = m.group(1)
                self.acls[current_acl] = []
                continue
            if not current_acl:
                continue
            m = re.match(
                r'^(permit|deny)\s+ip-source\s+(\S+)(?:\s+mask\s+(\S+))?(?:\s+service\s+(\S+))?(?:\s+\S+)?$',
                line
            )
            if m:
                action, ip, mask, service = m.groups()
                if ip.lower() in ("any", "any4", "all"):
                    net = "any"
                elif mask:
                    try:
                        net = str(ipaddress.ip_network((ip, mask), strict=False))
                    except ValueError:
                        net = ip
                else:
                    try:
                        net = str(ipaddress.ip_network(f"{ip}/32", strict=False))
                    except ValueError:
                        net = ip

                self.acls[current_acl].append({
                    "action": action,
                    "source": net,
                    "service": service or "any",
                    "raw": line
                })

    def _cand_to_net(self, cand):
        try:
            if isinstance(cand, str):
                if '/' in cand:
                    return ipaddress.ip_network(cand, strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
        except ValueError:
            return None
        return None

    def _matches(self, input_str, candidates, strict_mode, ignore_any=False, mask_limit=None):
        ANY_VARIANTS = ("any", "any4", "all", "0.0.0.0/0")

        # 1. СТРОГАЯ ПРОВЕРКА IGNORE_ANY (Первей всего!)
        is_any_in_candidates = any(c in ANY_VARIANTS for c in candidates)
        if ignore_any and is_any_in_candidates:
            return False

        # 2. Нормализация mask_limit
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                if isinstance(mask_limit, str):
                    parsed_mask_limit = int(mask_limit.replace("/", "").strip())
                elif isinstance(mask_limit, int):
                    parsed_mask_limit = mask_limit
            except ValueError:
                parsed_mask_limit = None

        # 3. Если ищем "any"
        if not input_str or input_str == "any":
            if is_any_in_candidates:
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    return False
                return True
            return not strict_mode

        if is_any_in_candidates:
            if parsed_mask_limit is not None and parsed_mask_limit > 0:
                return False
            return not strict_mode

        # 4. Анализ поискового ввода (IP или Сеть)
        is_search_network = False
        try:
            if '/' in input_str and not input_str.endswith('/32'):
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            else:
                input_ip = ipaddress.ip_address(input_str.split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
        except ValueError:
            try:
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            except ValueError:
                return False

        # При поиске по СЕТИ принудительно включает strict_mode
        effective_strict_mode = strict_mode or is_search_network

        # 5. Проверка кандидатов
        for cand in candidates:
            if cand in ANY_VARIANTS:
                if ignore_any:
                    continue
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    continue
                return not effective_strict_mode

            cand_net = self._cand_to_net(cand)

            # Проверка лимита маски
            if parsed_mask_limit is not None and cand_net is not None:
                if cand_net.prefixlen > parsed_mask_limit:
                    continue

            # --- СТРОГИЙ РЕЖИМ ---
            if effective_strict_mode:
                if cand_net and cand_net == input_net:
                    return True
            # --- ОБЫЧНЫЙ РЕЖИМ ---
            else:
                try:
                    if input_ip is not None:
                        if cand_net and input_ip in cand_net:
                            return True
                    else:
                        if cand_net and input_net.overlaps(cand_net):
                            return True
                except Exception:
                    continue

        return False

    def find_acl_matches(
            self,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        matches = []
        for acl, rules in self.acls.items():
            matched_rules = []
            for rule in rules:
                src_candidates = [rule["source"]]
                dst_candidates = ["any"]  # Management ACL в Eltex проверяют только source

                # Пропускаем правила с src=any и dst=any
                if src_candidates == ["any"] and dst_candidates == ["any"]:
                    continue

                src_ok = self._matches(
                    src_ip,
                    src_candidates,
                    strict_mode,
                    ignore_any=ignore_src_any,
                    mask_limit=src_mask_limit
                )
                dst_ok = self._matches(
                    dst_ip,
                    dst_candidates,
                    strict_mode,
                    ignore_any=ignore_dst_any,
                    mask_limit=dst_mask_limit
                )

                if src_ok and dst_ok:
                    matched_rules.append(f" {rule['raw']}")

            if matched_rules:
                matches.append(f"management access-list {acl}\n" + "\n".join(matched_rules))

        return tuple(matches)

    # Алиас для обеспечения обратной совместимости
    find_matches = find_acl_matches

    @classmethod
    def from_local_file(
            cls,
            filename,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None,
            base_dir=base_dir,
            encoding="utf-8"
    ):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            parser = cls(f.read())
                            return parser.find_acl_matches(
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                strict_mode=strict_mode,
                                ignore_src_any=ignore_src_any,
                                ignore_dst_any=ignore_dst_any,
                                src_mask_limit=src_mask_limit,
                                dst_mask_limit=dst_mask_limit
                            )
                    except Exception:
                        return tuple()
        return tuple()


class EltexESRParser2:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()

        # zone-pair name -> list of rule blocks
        self.zone_pairs = defaultdict(list)

        # object-group network name -> list of networks (str)
        self.network_groups = defaultdict(list)

        # object-group service name -> list of port ranges / single ports
        self.service_groups = defaultdict(list)

        self.parse()

    def parse(self):
        current_zone_pair = None
        current_rule = None
        current_rule_lines = []

        i = 0
        while i < len(self.config_lines):
            line = self.config_lines[i].rstrip()

            if line.startswith("security zone-pair "):
                parts = line.split()
                if len(parts) >= 4:
                    current_zone_pair = f"{parts[2]} {parts[3]}"
                    current_rule = None
                    current_rule_lines = []
                i += 1
                continue

            if current_zone_pair and line.strip().startswith("rule "):
                # новый rule начинается
                if current_rule_lines:
                    self.zone_pairs[current_zone_pair].append(current_rule_lines[:])
                current_rule_lines = [line]
                current_rule = line
                i += 1
                continue

            if current_zone_pair and current_rule_lines:
                # продолжаем собирать строки внутри rule
                if line.strip() in ("exit", "!"):
                    self.zone_pairs[current_zone_pair].append(current_rule_lines[:])
                    current_rule_lines = []
                    current_rule = None
                else:
                    current_rule_lines.append(line)

            # парсим object-group network
            if line.startswith("object-group network "):
                group_name = line.split()[2]
                i += 1
                while i < len(self.config_lines):
                    l = self.config_lines[i].strip()
                    if l.startswith("ip prefix "):
                        prefix = l.split("ip prefix ", 1)[1].strip()
                        self.network_groups[group_name].append(prefix)
                    elif l in ("exit", "!") or l.startswith("object-group"):
                        break
                    i += 1
                continue

            # парсим object-group service
            if line.startswith("object-group service "):
                group_name = line.split()[2]
                i += 1
                while i < len(self.config_lines):
                    l = self.config_lines[i].strip()
                    if l.startswith("port-range "):
                        ports = l.split("port-range ", 1)[1].strip()
                        self.service_groups[group_name].append(ports)
                    elif l.startswith("description"):
                        pass
                    elif l in ("exit", "!") or l.startswith("object-group"):
                        break
                    i += 1
                continue

            i += 1

        if current_rule_lines:
            self.zone_pairs[current_zone_pair].append(current_rule_lines[:])

    def _expand_network_group(self, group_name):
        """Возвращает список всех IP-сетей из группы (включая рекурсию, если группы вложенные)"""
        result = set()
        seen = set()

        def recurse(g):
            if g in seen:
                return
            seen.add(g)
            for prefix in self.network_groups.get(g, []):
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                    result.add(str(net))
                except Exception:
                    pass

        recurse(group_name)
        return list(result) if result else ["any"]

    def _expand_service_group(self, group_name):
        """Возвращает список портов/диапазонов"""
        return self.service_groups.get(group_name, ["any"])

    def _cand_to_net(self, cand):
        try:
            if isinstance(cand, str):
                if cand.lower() in ("any", "any4", "all", "0.0.0.0/0"):
                    return None
                if '/' in cand:
                    return ipaddress.ip_network(cand, strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
        except ValueError:
            return None
        return None

    def _matches(self, input_str, candidates, strict_mode, ignore_any=False, mask_limit=None):
        ANY_VARIANTS = frozenset({"any", "any4", "all", "0.0.0.0/0"})

        # 1. СТРОГАЯ ПРОВЕРКА IGNORE_ANY (Первей всего!)
        is_any_in_candidates = any(c in ANY_VARIANTS for c in candidates)
        if ignore_any and is_any_in_candidates:
            return False

        # 2. Нормализация mask_limit
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                if isinstance(mask_limit, str):
                    parsed_mask_limit = int(mask_limit.replace("/", "").strip())
                elif isinstance(mask_limit, int):
                    parsed_mask_limit = mask_limit
            except ValueError:
                parsed_mask_limit = None

        # 3. Если ищем "any" или пустой фильтр
        if not input_str or input_str == "any":
            if is_any_in_candidates:
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    return False
                return True
            return not strict_mode

        if is_any_in_candidates:
            if parsed_mask_limit is not None and parsed_mask_limit > 0:
                return False
            return not strict_mode

        # 4. Анализ поискового ввода (IP или Сеть)
        is_search_network = False
        try:
            if '/' in input_str and not input_str.endswith('/32'):
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            else:
                input_ip = ipaddress.ip_address(input_str.split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
        except ValueError:
            try:
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            except ValueError:
                return False

        # При поиске по СЕТИ принудительно включает strict_mode
        effective_strict_mode = strict_mode or is_search_network

        # 5. Проверка кандидатов
        for cand in candidates:
            if cand in ANY_VARIANTS:
                if ignore_any:
                    continue
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    continue
                return not effective_strict_mode

            cand_net = self._cand_to_net(cand)

            # Проверка лимита маски
            if parsed_mask_limit is not None and cand_net is not None:
                if cand_net.prefixlen > parsed_mask_limit:
                    continue

            # --- СТРОГИЙ РЕЖИМ ---
            if effective_strict_mode:
                if cand_net and cand_net == input_net:
                    return True
            # --- ОБЫЧНЫЙ РЕЖИМ ---
            else:
                try:
                    if input_ip is not None:
                        if cand_net and input_ip in cand_net:
                            return True
                    else:
                        if cand_net and input_net.overlaps(cand_net):
                            return True
                except Exception:
                    continue

        return False

    def find_acl_matches(
            self,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        results = []

        for zone_pair, rule_blocks in self.zone_pairs.items():
            matched_blocks = []

            for rule_lines in rule_blocks:
                src_groups = []
                dst_groups = []
                action = None
                enabled = False
                filtered_rule_lines = []

                for ln in rule_lines:
                    s = ln.strip()
                    if s.startswith("description "):
                        continue
                    filtered_rule_lines.append(ln)

                    if s.startswith("action "):
                        action = s.split("action ", 1)[1].strip()
                    elif s.startswith("match source-address object-group "):
                        src_groups.append(s.split("object-group ", 1)[1].strip())
                    elif s.startswith("match destination-address object-group "):
                        dst_groups.append(s.split("object-group ", 1)[1].strip())
                    elif s.startswith("match source-address prefix "):
                        prefix = s.split("prefix ", 1)[1].strip()
                        src_groups.append(prefix)
                    elif s == "enable":
                        enabled = True

                if not enabled or not action:
                    continue

                # Формируем списки кандидатов сетей для source
                src_candidates = []
                if not src_groups:
                    src_candidates = ["any"]
                else:
                    for g in src_groups:
                        if '/' in g and not g.startswith("object-group"):
                            src_candidates.append(g)
                        else:
                            src_candidates.extend(self._expand_network_group(g))

                # Формируем списки кандидатов сетей для destination
                dst_candidates = []
                if not dst_groups:
                    dst_candidates = ["any"]
                else:
                    for g in dst_groups:
                        dst_candidates.extend(self._expand_network_group(g))

                # Проверяем совпадение по Source и Destination
                src_ok = self._matches(
                    src_ip,
                    src_candidates,
                    strict_mode,
                    ignore_any=ignore_src_any,
                    mask_limit=src_mask_limit
                )
                dst_ok = self._matches(
                    dst_ip,
                    dst_candidates,
                    strict_mode,
                    ignore_any=ignore_dst_any,
                    mask_limit=dst_mask_limit
                )

                if src_ok and dst_ok:
                    matched_blocks.extend(filtered_rule_lines)

            if matched_blocks:
                results.append(f"security zone-pair {zone_pair}")
                results.extend(matched_blocks)
                results.append("  exit")

        return tuple(results)

    # Алиас для поддержания обратной совместимости
    find_matches = find_acl_matches

    @classmethod
    def from_local_file(
            cls,
            filename,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None,
            base_dir=base_dir,
            encoding="utf-8"
    ):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            parser = cls(f.read())
                            return parser.find_acl_matches(
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                strict_mode=strict_mode,
                                ignore_src_any=ignore_src_any,
                                ignore_dst_any=ignore_dst_any,
                                src_mask_limit=src_mask_limit,
                                dst_mask_limit=dst_mask_limit
                            )
                    except Exception:
                        return tuple()
        return tuple()


class HPEParser2:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.acls = {}
        self.acl_headers = {}
        self.parse()

    @staticmethod
    def safe_ip_network(addr_str: str, strict: bool = True) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        if not addr_str or str(addr_str).lower() == "any":
            return None
        try:
            return ipaddress.ip_network(addr_str, strict=strict)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def safe_ip_address(addr_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        if not addr_str:
            return None
        try:
            return ipaddress.ip_address(addr_str)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def normalize_to_network(addr_spec: str) -> str | None:
        if str(addr_spec).lower() == "any":
            return "any"

        net = HPEParser2.safe_ip_network(addr_spec, strict=True)
        if net is not None:
            return str(net)

        ip = HPEParser2.safe_ip_address(addr_spec)
        if ip is not None:
            return f"{ip}/{ip.max_prefixlen}"

        return None

    def parse(self):
        current_acl = None
        current_header = None
        for raw in self.config_lines:
            line = raw.strip()
            if not line:
                continue

            # === Comware / Huawei-подобный стиль (acl number / acl name) ===
            if line.startswith("acl number") or line.startswith("acl name"):
                current_header = line.strip()
                parts = line.split()

                if line.startswith("acl number") and len(parts) >= 3:
                    current_acl = parts[2]
                    self.acls.setdefault(current_acl, {})
                    self.acl_headers[current_acl] = current_header

                elif line.startswith("acl name") and len(parts) >= 3:
                    name = parts[2]
                    number = parts[3] if len(parts) > 3 else ""
                    current_acl = number if number else name
                    self.acls.setdefault(current_acl, {})
                    self.acl_headers[current_acl] = current_header

                continue

            # === OfficeConnect нумерованный ACL (access-list N permit/deny...) ===
            if line.lower().startswith("access-list") and ("permit" in line.lower() or "deny" in line.lower()):
                parts = line.split()
                num_idx = 1
                if len(parts) > 1 and parts[1].lower() in ("extended", "standard"):
                    num_idx = 2
                if len(parts) > num_idx and parts[num_idx].isdigit():
                    acl_num = parts[num_idx]
                    if current_acl != acl_num or current_acl is None:
                        current_acl = acl_num
                        current_header = f"access-list {acl_num}"
                        self.acls.setdefault(current_acl, {})
                        self.acl_headers[current_acl] = current_header

                    rule_part = " ".join(parts[num_idx + 1:]) if len(parts) > num_idx + 1 else ""
                    if not rule_part or "comment" in line.lower():
                        continue
                    try:
                        pairs = self._parse_office_rule(rule_part)
                        cleaned = [(src, dst) for src, dst in pairs if not (src == "any" and dst == "any")]
                        if cleaned:
                            self.acls[current_acl][line] = cleaned
                    except Exception:
                        pass
                    continue

            # === OfficeConnect именованный ACL (ip access-list NAME) ===
            if line.lower().startswith("ip access-list"):
                parts = line.split()
                name_idx = 2
                if len(parts) > 2 and parts[2].lower() in ("extended", "standard"):
                    name_idx = 3
                if len(parts) > name_idx:
                    name = parts[name_idx]
                    current_acl = name
                    current_header = line
                    self.acls.setdefault(current_acl, {})
                    self.acl_headers[current_acl] = current_header
                continue

            # === Правила Comware (строки с rule) ===
            if current_acl and line.startswith("rule "):
                if "comment" in line.lower():
                    continue
                try:
                    pairs = self._parse_rule(line)
                    if not pairs:
                        continue
                    cleaned = [(src, dst) for src, dst in pairs if not (src == "any" and dst == "any")]
                    if cleaned:
                        self.acls[current_acl][line] = cleaned
                except Exception:
                    pass
                continue

            # === Правила OfficeConnect именованного ACL (permit/deny или N permit/deny) ===
            tokens = line.lstrip().lower().split()
            if current_acl and tokens:
                first_token = tokens[0]
                second_token = tokens[1] if len(tokens) > 1 else ""

                if first_token in ("permit", "deny") or (first_token.isdigit() and second_token in ("permit", "deny")):
                    rule_line = line.strip()
                    if "comment" in rule_line.lower():
                        continue
                    try:
                        pairs = self._parse_office_rule(rule_line)
                        if not pairs:
                            continue
                        cleaned = [(src, dst) for src, dst in pairs if not (src == "any" and dst == "any")]
                        if cleaned:
                            self.acls[current_acl][rule_line] = cleaned
                    except Exception:
                        pass

    def _parse_rule(self, line):
        parts = line.split()
        src_spec = "any"
        dst_spec = "any"

        if "source" in parts:
            i = parts.index("source")
            src_spec = self._parse_addr_with_wildcard(parts, i + 1)

        if "destination" in parts:
            i = parts.index("destination")
            dst_spec = self._parse_addr_with_wildcard(parts, i + 1)

        return [(src_spec, dst_spec)]

    def _parse_addr_with_wildcard(self, parts, idx):
        if idx >= len(parts):
            return "any"

        ip = parts[idx]
        if ip.lower() == "any":
            return "any"

        if not ip.replace(".", "").isdigit() and not ip.startswith("::"):
            return "BS"

        wc = None
        if idx + 1 < len(parts):
            nxt = parts[idx + 1]
            if self._looks_like_wildcard(nxt):
                wc = nxt

        if wc is None:
            return f"{ip}/32"

        return self._wildcard_to_network_or_range(ip, wc)

    def _looks_like_wildcard(self, s: str) -> bool:
        if s.count(".") == 3:
            try:
                ipaddress.IPv4Address(s)
                return True
            except ValueError:
                return False
        return s.isdigit()

    def _wildcard_to_network_or_range(self, ip_str: str, wildcard_str: str):
        ip = HPEParser2.safe_ip_address(ip_str)
        if ip is None:
            return "any"

        try:
            if wildcard_str.count(".") == 3:
                w = int(ipaddress.IPv4Address(wildcard_str))
            else:
                w = int(wildcard_str)
                if not (0 <= w <= 0xFFFFFFFF):
                    raise ValueError("wildcard out of range")
        except Exception:
            return f"{ip_str}/32"

        # 0.0.0.0 255.255.255.255 или любой адрес с маской 255.255.255.255 — это 'any'
        if w == 0xFFFFFFFF or wildcard_str == "255.255.255.255":
            return "any"

        if w == 0:
            return f"{ip_str}/32"

        if (w & (w + 1)) == 0:
            k = bin(w).count("1")
            prefix = 32 - k
            if prefix == 0:
                return "any"
            try:
                net = ipaddress.IPv4Network((ip_str, prefix), strict=True)
                return str(net)
            except ValueError:
                ip_int = int(ipaddress.IPv4Address(ip_str))
                start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
                end = (ip_int | w) & 0xFFFFFFFF
                return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))

        ip_int = int(ipaddress.IPv4Address(ip_str))
        start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
        end = (ip_int | w) & 0xFFFFFFFF
        return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))

    def _parse_office_rule(self, rule_str):
        parts = rule_str.split()
        if not parts:
            return []

        idx = 0
        if parts[idx].isdigit():
            idx += 1

        if idx >= len(parts) or parts[idx].lower() not in ("permit", "deny"):
            return []
        idx += 1

        if idx < len(parts) and parts[idx].lower() in ("ip", "tcp", "udp", "icmp"):
            idx += 1

        src_spec, consumed = self._parse_office_addr(parts, idx)
        idx += consumed

        # Стандартные ACL без указания destination (например: access-list 99 deny 0.0.0.0 255.255.255.255)
        if idx >= len(parts):
            return [(src_spec, "any")]

        dst_spec, consumed_dst = self._parse_office_addr(parts, idx)

        # Если после разбора dst остались суффиксы eq/log/etc, проверяем корректность
        return [(src_spec, dst_spec)]

    def _parse_office_addr(self, parts, start_idx):
        if start_idx >= len(parts):
            return "any", 0

        token = parts[start_idx].lower()

        # Игнорируем служебные слова, стоящие на месте IP
        if token in ("log", "logging", "established"):
            return "any", 0

        if token == "any":
            return "any", 1

        if token == "host":
            if start_idx + 1 < len(parts):
                ip = parts[start_idx + 1]
                return f"{ip}/32", 2
            return "any", 1

        ip = parts[start_idx]
        consumed = 1

        if start_idx + 1 < len(parts) and self._looks_like_wildcard(parts[start_idx + 1]):
            wc = parts[start_idx + 1]
            consumed = 2
            spec = self._wildcard_to_network_or_range(ip, wc)
            return spec, consumed

        if self._looks_like_wildcard(ip):
            return f"{ip}/32", 1

        return "any", 0

    def _cand_to_net(self, cand):
        if isinstance(cand, tuple) and cand[0] == "range":
            return cand
        try:
            if isinstance(cand, str):
                if cand.lower() in ("any", "any4", "all", "0.0.0.0/0"):
                    return None
                if '/' in cand:
                    return ipaddress.ip_network(cand, strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
        except ValueError:
            return None
        return None

    def _matches(self, input_str, candidates, strict_mode, ignore_any=False, mask_limit=None):
        ANY_VARIANTS = ("any", "any4", "all", "0.0.0.0/0")

        # 1. СТРОГАЯ ПРОВЕРКА IGNORE_ANY
        is_any_in_candidates = any(c in ANY_VARIANTS for c in candidates)
        if ignore_any and is_any_in_candidates:
            return False

        # 2. Нормализация mask_limit
        parsed_mask_limit = None
        if mask_limit and mask_limit is not False:
            try:
                if isinstance(mask_limit, str):
                    parsed_mask_limit = int(mask_limit.replace("/", "").strip())
                elif isinstance(mask_limit, int):
                    parsed_mask_limit = mask_limit
            except ValueError:
                parsed_mask_limit = None

        # 3. Если ищем "any" или пустой запрос
        if not input_str or input_str == "any":
            if is_any_in_candidates:
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    return False
                return True
            return not strict_mode

        if is_any_in_candidates:
            if parsed_mask_limit is not None and parsed_mask_limit > 0:
                return False
            return not strict_mode

        # 4. Анализ поискового ввода (IP или Сеть)
        is_search_network = False
        try:
            if '/' in input_str and not input_str.endswith('/32'):
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            else:
                input_ip = ipaddress.ip_address(input_str.split('/')[0])
                input_net = ipaddress.ip_network(f"{input_ip}/32", strict=False)
        except ValueError:
            try:
                input_net = ipaddress.ip_network(input_str, strict=False)
                input_ip = None
                is_search_network = True
            except ValueError:
                return False

        effective_strict_mode = strict_mode or is_search_network

        # 5. Проверка кандидатов
        for cand in candidates:
            if cand in ANY_VARIANTS:
                if ignore_any:
                    continue
                if parsed_mask_limit is not None and parsed_mask_limit > 0:
                    continue
                return not effective_strict_mode

            cand_net = self._cand_to_net(cand)

            # --- ИСПРАВЛЕНИЕ ЛИМИТА МАСКИ ---
            if parsed_mask_limit is not None and cand_net is not None:
                if isinstance(cand_net, tuple) and cand_net[0] == "range":
                    # Вычисляем эквивалентный размер диапазона адресов
                    _, start, end = cand_net
                    num_addresses = int(end) - int(start) + 1
                    # Если префикс сети диапазона больше лимита (сеть у́же лимита) -> отбрасываем
                    if num_addresses < (1 << (32 - parsed_mask_limit)):
                        continue
                elif hasattr(cand_net, "prefixlen"):
                    # Чем больше prefixlen, тем у́же подсеть.
                    # Если prefixlen > parsed_mask_limit (например /25 > 24) -> отбрасываем
                    if cand_net.prefixlen > parsed_mask_limit:
                        continue

            if isinstance(cand_net, tuple) and cand_net[0] == "range":
                _, start, end = cand_net
                min_c, max_c = int(start), int(end)

                if effective_strict_mode:
                    if input_net:
                        if int(input_net.network_address) == min_c and int(input_net.broadcast_address) == max_c:
                            return True
                else:
                    if input_ip is not None:
                        if min_c <= int(input_ip) <= max_c:
                            return True
                    elif input_net is not None:
                        if max(int(input_net.network_address), min_c) <= min(int(input_net.broadcast_address), max_c):
                            return True
                continue

            if effective_strict_mode:
                if cand_net and cand_net == input_net:
                    return True
            else:
                try:
                    if input_ip is not None:
                        if cand_net and input_ip in cand_net:
                            return True
                    else:
                        if cand_net and input_net.overlaps(cand_net):
                            return True
                except Exception:
                    continue

        return False

    def find_acl_matches(
            self,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None
    ):
        results = []
        for acl_key, rules in self.acls.items():
            matched_rules = []
            for rule_line, pairs in rules.items():
                for src_spec, dst_spec in pairs:
                    src_candidates = [src_spec]
                    dst_candidates = [dst_spec]

                    # Игнорируем любая комбинация any-any
                    if src_candidates == ["any"] and dst_candidates == ["any"]:
                        continue

                    src_ok = self._matches(
                        src_ip,
                        src_candidates,
                        strict_mode,
                        ignore_any=ignore_src_any,
                        mask_limit=src_mask_limit
                    )
                    dst_ok = self._matches(
                        dst_ip,
                        dst_candidates,
                        strict_mode,
                        ignore_any=ignore_dst_any,
                        mask_limit=dst_mask_limit
                    )

                    if src_ok and dst_ok:
                        matched_rules.append(rule_line)
                        break

            if matched_rules:
                header = self.acl_headers.get(acl_key, f"acl {acl_key}")
                results.append(header)
                for r in matched_rules:
                    results.append(f"  {r}")

        return tuple(results)

    find_matches = find_acl_matches

    @classmethod
    def from_local_file(
            cls,
            filename,
            src_ip=None,
            dst_ip=None,
            strict_mode=False,
            ignore_src_any=False,
            ignore_dst_any=False,
            src_mask_limit=None,
            dst_mask_limit=None,
            base_dir=base_dir,
            encoding="utf-8"
    ):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                        parser = cls(config_text)
                        return parser.find_acl_matches(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            strict_mode=strict_mode,
                            ignore_src_any=ignore_src_any,
                            ignore_dst_any=ignore_dst_any,
                            src_mask_limit=src_mask_limit,
                            dst_mask_limit=dst_mask_limit
                        )
                    except Exception:
                        return tuple()
        return tuple()


class CiscoIOSParser2(BaseACLParser):
    """ Парсер для Cisco IOS """

    def parse(self):
        self._parse_object_groups()
        current_group = None
        current_acl = None
        current_type = 'extended'

        for line in self.config_lines:
            line = line.strip()
            if not line or line.startswith("!"):
                continue

            # Именованные ACL вида: access-list ip extended ACL-NAME
            if line.startswith("access-list ip ") or line.startswith("access-list "):
                parts = line.split(maxsplit=3)
                if len(parts) >= 3 and parts[1] == "ip" and parts[2] in ("standard", "extended"):
                    acl_type = parts[2]
                    acl_name = parts[3].strip('"')
                    if acl_name not in self.acls:
                        self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'access-list ip'}
                    current_acl = acl_name
                    current_type = acl_type
                    continue
                # Нумерованные ACL вида: access-list 20 permit ...
                elif len(parts) > 2:
                    acl_name = parts[1]
                    if acl_name.isdigit():
                        acl_type = 'standard' if int(acl_name) < 100 or 1300 <= int(acl_name) <= 1999 else 'extended'
                        rule = ' '.join(parts[2:])
                        if acl_name not in self.acls:
                            self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'access-list'}
                        self.acls[acl_name]['rules'].append(rule)
                    continue

            # Именованные ACL вида: ip access-list extended ACL-NAME
            if line.startswith("ip access-list "):
                parts = line.split(maxsplit=4)
                acl_type = 'extended'
                acl_name = None
                if len(parts) >= 4 and parts[2] in ("standard", "extended"):
                    acl_type = parts[2]
                    acl_name = parts[3].strip('"')
                elif len(parts) >= 3:
                    acl_name = parts[2].strip('"')
                if acl_name and acl_name not in self.acls:
                    self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'ip access-list'}
                current_acl = acl_name
                current_type = acl_type
                continue

            # Обработка секций object-group network
            if line.startswith("object-group network "):
                if current_group:
                    self.object_groups[current_group] = current_values
                current_group = line.split()[2]
                current_values = []
                continue

            if current_group:
                if line.startswith("host "):
                    current_values.append(line.split()[1] + "/32")
                elif line.startswith("range "):
                    parts = line.split()
                    current_values.extend(self._expand_ip_range(parts[1], parts[2]))
                elif re.match(r"\d", line):
                    parts = line.split()
                    if len(parts) == 2:
                        try:
                            network = ipaddress.ip_network(f"{parts[0]}/{self._wildcard_to_cidr(parts[1])}",
                                                           strict=False)
                            current_values.append(str(network))
                        except ValueError:
                            continue
                elif line == "exit" or line.endswith("}"):
                    self.object_groups[current_group] = current_values
                    current_group = None
                continue

            if current_acl:
                if line.startswith("permit") or line.startswith("deny") or line[0].isdigit() or line.startswith("seq "):
                    self.acls[current_acl]['rules'].append(line)
                elif line == "exit" or line.endswith("}"):
                    current_acl = None

    def _parse_object_groups(self):
        current_name = None
        current_values = []
        for line in self.config_lines:
            s = line.strip()
            if s.startswith("object-group network"):
                if current_name:
                    self.object_groups[current_name] = current_values
                current_name = s.split()[-1]
                current_values = []
            elif current_name:
                if s.startswith("host "):
                    current_values.append(s.split()[-1] + "/32")
                elif s.startswith("exit") or s == "!":
                    self.object_groups[current_name] = current_values
                    current_name = None
                    current_values = []
        if current_name:
            self.object_groups[current_name] = current_values

    def _extract_src_dst(self, parts, acl_type):
        i = 0
        # Пропускаем номера правил или ключевые слова
        if parts and (parts[i].isdigit() or parts[i] == "seq"):
            i += 1
            if i < len(parts) and parts[i - 1] == "seq":
                i += 1

        if i < len(parts) and parts[i] in ('permit', 'deny'):
            i += 1

        # KNOWN_PROTOCOLS = frozenset({'tcp', 'udp', 'ip', 'icmp'})

        if acl_type == 'extended' and i < len(parts):
            if parts[i] in KNOWN_PROTOCOLS or (parts[i].isdigit() and int(parts[i]) <= 255):
                i += 1

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx
            word = parts[idx]

            if word in ("object-group", "addrgroup"):
                if idx + 1 < len(parts):
                    return parts[idx + 1], idx + 2
                return "any", idx + 1
            elif word == "host":
                if idx + 1 < len(parts):
                    return parts[idx + 1] + "/32", idx + 2
                return "any", idx + 1
            elif word in ("any", "any4"):
                return "any", idx + 1
            elif re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', word):
                return word, idx + 1
            elif self._is_ip(word):
                if idx + 1 < len(parts) and (
                        self._is_ip(parts[idx + 1]) or re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[idx + 1])):
                    wildcard = parts[idx + 1]
                    prefix = self._wildcard_to_cidr(wildcard)
                    if prefix is not None:
                        if prefix == 0:
                            return "any", idx + 2
                        return f"{parts[idx]}/{prefix}", idx + 2
                    return parts[idx] + "/32", idx + 1
                return parts[idx] + "/32", idx + 1
            return "any", idx + 1

        src, i = parse_entry(i)
        dst = "any" if acl_type == 'standard' else parse_entry(i)[0]
        return src, dst


class HPProCurveParser2(BaseACLParser):
    """ Парсер для HP ProCurve """

    def parse(self):
        self._parse_object_groups()
        current_acl = None
        current_type = 'extended'

        for line in self.config_lines:
            line = line.strip()
            if not line or line.startswith("!"):
                continue

            if line.startswith("access management-network"):
                parts = line.split()
                if len(parts) >= 3 and self._is_ip(parts[2]):
                    acl_name = "management-network"
                    if acl_name not in self.acls:
                        self.acls[acl_name] = {'type': 'standard', 'rules': [], 'header_prefix': 'access'}
                    rule = f"permit {parts[2]} {parts[3]}"
                    self.acls[acl_name]['rules'].append(rule)
                continue

            if line.startswith("ip access-list "):
                parts = line.split(maxsplit=4)
                if len(parts) >= 4 and parts[2] in ("standard", "extended"):
                    acl_type = parts[2]
                    acl_name = parts[3].strip('"')
                    if acl_name not in self.acls:
                        self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'ip access-list'}
                    current_acl = acl_name
                    current_type = acl_type
                    continue

            if current_acl:
                if line.startswith("permit") or line.startswith("deny") or line[0].isdigit() or line.startswith("seq "):
                    self.acls[current_acl]['rules'].append(line)
                elif line == "exit" or line.endswith("}"):
                    current_acl = None

    def _parse_object_groups(self):
        current_name = None
        current_values = []
        for line in self.config_lines:
            s = line.strip()
            if s.startswith("object-group ip address"):
                if current_name:
                    self.object_groups[current_name] = current_values
                current_name = s.split()[-1]
                current_values = []
            elif current_name:
                if s.startswith("host-info ") or s.startswith("host "):
                    current_values.append(s.split()[-1] + "/32")
                elif re.match(r"\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+", s):
                    ip, mask = s.split()[:2]
                    prefix = self._mask_to_cidr(mask) or self._wildcard_to_cidr(mask)
                    if prefix is not None:
                        current_values.append(f"{ip}/{prefix}")
                elif s.startswith("exit") or s == "!":
                    self.object_groups[current_name] = current_values
                    current_name = None
                    current_values = []
        if current_name:
            self.object_groups[current_name] = current_values

    def _extract_src_dst(self, parts, acl_type):
        i = 0

        # 1. Пропуск номера правила / seq (например: "6", "seq 10")
        if i < len(parts) and parts[i] == "seq":
            i += 1
            if i < len(parts) and parts[i].isdigit():
                i += 1
        elif i < len(parts) and parts[i].isdigit():
            i += 1

        # 2. Пропуск действия (permit/deny)
        if i < len(parts) and parts[i] in ('permit', 'deny'):
            i += 1

        # 3. Пропуск протокола для extended ACL (ip, tcp, udp, icmp, etc.)
        # KNOWN_PROTOCOLS = frozenset({'ip', 'tcp', 'udp', 'icmp'})
        if acl_type == 'extended' and i < len(parts):
            if parts[i] in KNOWN_PROTOCOLS or (parts[i].isdigit() and int(parts[i]) <= 255):
                i += 1

        # PORT_OPS = frozenset({'eq', 'gt', 'lt', 'neq', 'range'})

        def consume_port_and_flags(idx):
            """ Сдвигает индекс через операторы портов и служебные флаги """
            while idx < len(parts):
                if parts[idx] in PORT_OPS:
                    idx += 3 if parts[idx] == 'range' else 2
                elif parts[idx] in ('established', 'log', 'log-input', 'ack', 'rst'):
                    idx += 1
                else:
                    break
            return idx

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx

            word = parts[idx]

            # Вариант 1: any / any4
            if word in ("any", "any4"):
                next_idx = consume_port_and_flags(idx + 1)
                return "any", next_idx

            # Вариант 2: host <IP>
            if word == "host":
                if idx + 1 < len(parts):
                    host_ip = parts[idx + 1]
                    next_idx = consume_port_and_flags(idx + 2)
                    return f"{host_ip}/32", next_idx
                return "any", idx + 1

            # Вариант 3: object-group / addrgroup <NAME>
            if word in ("object-group", "addrgroup"):
                if idx + 1 < len(parts):
                    group_name = parts[idx + 1]
                    next_idx = consume_port_and_flags(idx + 2)
                    return group_name, next_idx
                return "any", idx + 1

            # Вариант 4: IP-адрес + Маска / Wildcard
            if self._is_ip(word):
                if idx + 1 < len(parts) and self._is_ip(parts[idx + 1]):
                    mask_or_wildcard = parts[idx + 1]

                    # HP ProCurve ANY: 0.0.0.0 255.255.255.255
                    if word == "0.0.0.0" and mask_or_wildcard == "255.255.255.255":
                        next_idx = consume_port_and_flags(idx + 2)
                        return "any", next_idx

                    # Перевод Wildcard / Mask в CIDR prefix
                    prefix = self._wildcard_to_cidr(mask_or_wildcard)
                    if prefix is None:
                        prefix = self._mask_to_cidr(mask_or_wildcard)

                    if prefix is not None:
                        if prefix == 0 and word == "0.0.0.0":
                            next_idx = consume_port_and_flags(idx + 2)
                            return "any", next_idx

                        next_idx = consume_port_and_flags(idx + 2)
                        return f"{word}/{prefix}", next_idx

                # Если маски нет — считаем /32 (отдельный хост)
                next_idx = consume_port_and_flags(idx + 1)
                return f"{word}/32", next_idx

            return "any", idx + 1

        src, i = parse_entry(i)
        dst = "any" if acl_type == 'standard' else parse_entry(i)[0]
        return src, dst


class IPInfusionParser(BaseACLParser):
    """ Парсер ACL для IP Infusion (OcNOS) """

    def parse(self):
        self._parse_object_groups()
        current_acl = None
        current_type = 'extended'

        for line in self.config_lines:
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("#"):
                continue

            # 1. Формат именованных/нумерованных ACL: access-list <NAME> [seq <NUM>] permit/deny ...
            if line.startswith("access-list ") or line.startswith("ip access-list "):
                parts = line.split()
                # Разбор заголовочной части для создания структуры ACL
                if len(parts) >= 2:
                    if parts[0] == "ip" and len(parts) >= 4 and parts[2] in ("standard", "extended"):
                        acl_type = parts[2]
                        acl_name = parts[3]
                        if acl_name not in self.acls:
                            self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'ip access-list'}
                        current_acl = acl_name
                        current_type = acl_type
                        # Если сама строка содержит правило (не просто заголовок контекста)
                        if any(w in parts for w in ('permit', 'deny')):
                            self.acls[acl_name]['rules'].append(line)
                        continue
                    elif parts[0] == "access-list":
                        acl_name = parts[1]
                        # В OcNOS стандартные ACL обычно имеют номера 1-99, расширенные 100-199
                        acl_type = 'standard' if acl_name.isdigit() and int(acl_name) < 100 else 'extended'
                        if acl_name not in self.acls:
                            self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'access-list'}
                        self.acls[acl_name]['rules'].append(line)
                        continue

            if current_acl:
                if line.startswith("permit") or line.startswith("deny") or line.startswith("seq "):
                    self.acls[current_acl]['rules'].append(line)
                elif line == "exit" or line.startswith("!"):
                    current_acl = None

    def _parse_object_groups(self):
        """ Парсинг object-group в IP Infusion (при наличии) """
        current_name = None
        current_values = []
        for line in self.config_lines:
            s = line.strip()
            if s.startswith("object-group ip address") or s.startswith("object-group network"):
                if current_name:
                    self.object_groups[current_name] = current_values
                current_name = s.split()[-1]
                current_values = []
            elif current_name:
                if s.startswith("host ") or s.startswith("network-object host"):
                    current_values.append(s.split()[-1] + "/32")
                elif s.startswith("network-object "):
                    parts = s.split()
                    if len(parts) >= 2:
                        target = parts[1]
                        if '/' in target:
                            current_values.append(target)
                        elif len(parts) >= 3 and self._is_ip(parts[2]):
                            prefix = self._mask_to_cidr(parts[2]) or self._wildcard_to_cidr(parts[2])
                            if prefix is not None:
                                current_values.append(f"{target}/{prefix}")
                elif s.startswith("exit") or s == "!":
                    self.object_groups[current_name] = current_values
                    current_name = None
                    current_values = []
        if current_name:
            self.object_groups[current_name] = current_values

    def _extract_src_dst(self, parts, acl_type):
        i = 0

        # 1. Пропуск префикса "access-list <NAME>" или "ip access-list <TYPE> <NAME>"
        if len(parts) > 1 and parts[0] in ("access-list", "ip"):
            if parts[0] == "access-list":
                i = 2
            elif parts[0] == "ip" and parts[1] == "access-list":
                i = 4 if parts[2] in ("standard", "extended") else 3

        # 2. Пропуск номера правила / seq (например: "seq 10" или "10")
        if i < len(parts) and parts[i] == "seq":
            i += 1
            if i < len(parts) and parts[i].isdigit():
                i += 1
        elif i < len(parts) and parts[i].isdigit():
            i += 1

        # 3. Пропуск действия (permit/deny)
        if i < len(parts) and parts[i] in ('permit', 'deny'):
            i += 1

        # 4. Пропуск протокола для extended ACL (ip, tcp, udp, icmp и др.)
        # KNOWN_PROTOCOLS = frozenset({'ip', 'tcp', 'udp', 'icmp'})
        if acl_type == 'extended' and i < len(parts):
            if parts[i] in KNOWN_PROTOCOLS or (parts[i].isdigit() and int(parts[i]) <= 255):
                i += 1

        # PORT_OPS = {'eq', 'gt', 'lt', 'neq', 'range'}

        def consume_port_and_flags(idx):
            """ Пропускает порты и мета-флаги (log, established и т.д.) """
            while idx < len(parts):
                if parts[idx] in PORT_OPS:
                    idx += 3 if parts[idx] == 'range' else 2
                elif parts[idx] in ('established', 'log', 'log-input', 'dscp', 'tos'):
                    if parts[idx] in ('dscp', 'tos') and idx + 1 < len(parts):
                        idx += 2
                    else:
                        idx += 1
                else:
                    break
            return idx

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx

            word = parts[idx]

            # Вариант 1: any / any4
            if word in ("any", "any4"):
                next_idx = consume_port_and_flags(idx + 1)
                return "any", next_idx

            # Вариант 2: host <IP>
            if word == "host":
                if idx + 1 < len(parts):
                    host_ip = parts[idx + 1]
                    next_idx = consume_port_and_flags(idx + 2)
                    return f"{host_ip}/32", next_idx
                return "any", idx + 1

            # Вариант 3: addrgroup / object-group <NAME>
            if word in ("object-group", "addrgroup"):
                if idx + 1 < len(parts):
                    group_name = parts[idx + 1]
                    next_idx = consume_port_and_flags(idx + 2)
                    return group_name, next_idx
                return "any", idx + 1

            # Вариант 4: Префикс с маской в формате CIDR (10.1.1.0/24)
            if '/' in word:
                next_idx = consume_port_and_flags(idx + 1)
                return word, next_idx

            # Вариант 5: IP-адрес + Wildcard/Subnet маска (10.1.1.0 0.0.0.255 или 10.1.1.0 255.255.255.0)
            if self._is_ip(word):
                if idx + 1 < len(parts) and self._is_ip(parts[idx + 1]):
                    mask_or_wildcard = parts[idx + 1]

                    if word == "0.0.0.0" and mask_or_wildcard in ("255.255.255.255", "0.0.0.0"):
                        next_idx = consume_port_and_flags(idx + 2)
                        return "any", next_idx

                    prefix = self._wildcard_to_cidr(mask_or_wildcard)
                    if prefix is None:
                        prefix = self._mask_to_cidr(mask_or_wildcard)

                    if prefix is not None:
                        if prefix == 0 and word == "0.0.0.0":
                            next_idx = consume_port_and_flags(idx + 2)
                            return "any", next_idx

                        next_idx = consume_port_and_flags(idx + 2)
                        return f"{word}/{prefix}", next_idx

                # Если маска не указана — хост /32
                next_idx = consume_port_and_flags(idx + 1)
                return f"{word}/32", next_idx

            return "any", idx + 1

        src, i = parse_entry(i)
        dst = "any" if acl_type == 'standard' else parse_entry(i)[0]
        return src, dst


class EdgeCoreParser(BaseACLParser):
    """ Парсер ACL для EdgeCore (EdgeOS) """

    def parse(self):
        self._parse_object_groups()
        current_acl = None
        current_type = 'extended'

        for line in self.config_lines:
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("#"):
                continue

            # 1. Заголовок контекста ACL (например: access-list ip extended testn)
            lower_line = line.lower()
            if lower_line.startswith("access-list ip "):
                parts = line.split()
                if len(parts) >= 4 and parts[2].lower() in ("standard", "extended"):
                    acl_type = parts[2].lower()
                    acl_name = parts[3]
                    if acl_name not in self.acls:
                        self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'access-list ip'}
                    current_acl = acl_name
                    current_type = acl_type
                    continue

            # 2. Правила внутри контекста
            if current_acl:
                if lower_line.startswith("permit") or lower_line.startswith("deny") or lower_line.startswith("seq "):
                    self.acls[current_acl]['rules'].append(line)
                elif lower_line in ("exit", "end") or line.startswith("!"):
                    current_acl = None

    def _parse_object_groups(self):
        """ Парсинг object-group в EdgeCore (если присутствуют в конфиге) """
        current_name = None
        current_values = []
        for line in self.config_lines:
            s = line.strip()
            if s.lower().startswith("object-group ip address"):
                if current_name:
                    self.object_groups[current_name] = current_values
                current_name = s.split()[-1]
                current_values = []
            elif current_name:
                if s.lower().startswith("host "):
                    current_values.append(s.split()[-1] + "/32")
                elif self._is_ip(s.split()[0]):
                    parts = s.split()
                    if len(parts) >= 2 and self._is_ip(parts[1]):
                        prefix = self._mask_to_cidr(parts[1]) or self._wildcard_to_cidr(parts[1])
                        if prefix is not None:
                            current_values.append(f"{parts[0]}/{prefix}")
                elif s.lower().startswith("exit") or s == "!":
                    self.object_groups[current_name] = current_values
                    current_name = None
                    current_values = []
        if current_name:
            self.object_groups[current_name] = current_values

    def _extract_src_dst(self, parts, acl_type):
        i = 0

        # 1. Пропуск номера правила / seq (если есть)
        if i < len(parts) and parts[i].lower() == "seq":
            i += 1
            if i < len(parts) and parts[i].isdigit():
                i += 1
        elif i < len(parts) and parts[i].isdigit():
            i += 1

        # 2. Пропуск действия (permit/deny)
        if i < len(parts) and parts[i].lower() in ('permit', 'deny'):
            i += 1

        # 3. Пропуск протокола для extended ACL (ip, tcp, udp, icmp и др.)
        # KNOWN_PROTOCOLS = frozenset({'ip', 'tcp', 'udp', 'icmp'})
        if acl_type == 'extended' and i < len(parts):
            if parts[i].lower() in KNOWN_PROTOCOLS or (parts[i].isdigit() and int(parts[i]) <= 255):
                i += 1

        # PORT_OPS = {'eq', 'gt', 'lt', 'neq', 'range', 'destination-port', 'source-port'}

        def consume_port_and_flags(idx):
            """ Пропускает специфичные для EdgeCore конструкции портов (destination-port 80 и т.д.) """
            while idx < len(parts):
                word = parts[idx].lower()
                if word in ('destination-port', 'source-port'):
                    idx += 1
                    if idx < len(parts) and parts[idx].lower() in ('eq', 'gt', 'lt', 'neq'):
                        idx += 2
                    elif idx < len(parts) and parts[idx].lower() == 'range':
                        idx += 3
                    else:
                        idx += 1  # просто значение порта (например: destination-port 80)
                elif word in ('eq', 'gt', 'lt', 'neq'):
                    idx += 2
                elif word == 'range':
                    idx += 3
                elif word in ('established', 'log', 'log-input', 'dscp', 'tos'):
                    if word in ('dscp', 'tos') and idx + 1 < len(parts):
                        idx += 2
                    else:
                        idx += 1
                else:
                    break
            return idx

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx

            word = parts[idx]

            # Вариант 1: any / any4
            if word.lower() in ("any", "any4"):
                next_idx = consume_port_and_flags(idx + 1)
                return "any", next_idx

            # Вариант 2: host <IP>
            if word.lower() == "host":
                if idx + 1 < len(parts):
                    host_ip = parts[idx + 1]
                    next_idx = consume_port_and_flags(idx + 2)
                    return f"{host_ip}/32", next_idx
                return "any", idx + 1

            # Вариант 3: object-group / addrgroup <NAME>
            if word.lower() in ("object-group", "addrgroup"):
                if idx + 1 < len(parts):
                    group_name = parts[idx + 1]
                    next_idx = consume_port_and_flags(idx + 2)
                    return group_name, next_idx
                return "any", idx + 1

            # Вариант 4: IP с маской CIDR (10.78.4.0/24)
            if '/' in word:
                next_idx = consume_port_and_flags(idx + 1)
                return word, next_idx

            # Вариант 5: IP-адрес + Обычная Маска или Wildcard (10.78.4.0 255.255.255.0)
            if self._is_ip(word):
                if idx + 1 < len(parts) and self._is_ip(parts[idx + 1]):
                    mask_or_wildcard = parts[idx + 1]

                    if word == "0.0.0.0" and mask_or_wildcard in ("255.255.255.255", "0.0.0.0"):
                        next_idx = consume_port_and_flags(idx + 2)
                        return "any", next_idx

                    # Для EdgeCore сначала проверяем обычную маску (255.255.255.0), затем wildcard
                    prefix = self._mask_to_cidr(mask_or_wildcard)
                    if prefix is None:
                        prefix = self._wildcard_to_cidr(mask_or_wildcard)

                    if prefix is not None:
                        if prefix == 0 and word == "0.0.0.0":
                            next_idx = consume_port_and_flags(idx + 2)
                            return "any", next_idx

                        next_idx = consume_port_and_flags(idx + 2)
                        return f"{word}/{prefix}", next_idx

                # Если маски нет — считаем /32 (отдельный хост)
                next_idx = consume_port_and_flags(idx + 1)
                return f"{word}/32", next_idx

            return "any", idx + 1

        src, i = parse_entry(i)
        dst = "any" if acl_type == 'standard' else parse_entry(i)[0]
        return src, dst


class IBMLenovoParser(BaseACLParser):
    """ Парсер ACL для IBM / Lenovo Network OS (ENOS / CNOS) """

    def parse(self):
        self._parse_object_groups()

        # Разбор строк конфигурации
        for line in self.config_lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("!") or line_str.startswith("#"):
                continue

            lower_line = line_str.lower()

            # Фильтруем только строки с определением правил IPv4:
            # access-control macl <N> ipv4 ...
            if lower_line.startswith("access-control macl ") and " ipv4 " in lower_line:
                parts = line_str.split()
                if len(parts) >= 3 and parts[2].isdigit():
                    acl_number = parts[2]
                    acl_name = f"macl_{acl_number}"

                    if acl_name not in self.acls:
                        self.acls[acl_name] = {
                            'type': 'extended',
                            'rules': [],
                            'header_prefix': 'access-control macl'
                        }

                    self.acls[acl_name]['rules'].append(line_str)

    def _parse_object_groups(self):
        """ В ENOS/CNOS object-groups обычно не используются для MACL,
            но оставляем заготовку для совместимости с базовым классом """
        pass

    def _extract_src_dst(self, parts, acl_type):
        """
        Извлечение source-ip-address и destination-ip-address
        из строки вида: access-control macl 1 ipv4 source-ip-address 10.26.230.0 255.255.255.128 ...
        """
        src = "any"
        dst = "any"

        # Приводим к нижнему регистру для удобства поиска ключевых слов
        parts_lower = [p.lower() for p in parts]

        # 1. Извлечение Source IP
        if "source-ip-address" in parts_lower:
            idx = parts_lower.index("source-ip-address")
            if idx + 1 < len(parts):
                ip_val = parts[idx + 1]
                # Проверяем, есть ли дальше маска
                if idx + 2 < len(parts) and self._is_ip(parts[idx + 2]):
                    mask_val = parts[idx + 2]

                    if ip_val == "0.0.0.0" and mask_val in ("0.0.0.0", "255.255.255.255"):
                        src = "any"
                    else:
                        prefix = self._mask_to_cidr(mask_val) or self._wildcard_to_cidr(mask_val)
                        if prefix is not None:
                            src = "any" if (prefix == 0 and ip_val == "0.0.0.0") else f"{ip_val}/{prefix}"
                        else:
                            src = f"{ip_val}/32"
                else:
                    # Если указан только IP без маски — считаем хостом /32
                    src = "any" if ip_val == "any" else f"{ip_val}/32"

        # 2. Извлечение Destination IP
        if "destination-ip-address" in parts_lower:
            idx = parts_lower.index("destination-ip-address")
            if idx + 1 < len(parts):
                ip_val = parts[idx + 1]
                if idx + 2 < len(parts) and self._is_ip(parts[idx + 2]):
                    mask_val = parts[idx + 2]

                    if ip_val == "0.0.0.0" and mask_val in ("0.0.0.0", "255.255.255.255"):
                        dst = "any"
                    else:
                        prefix = self._mask_to_cidr(mask_val) or self._wildcard_to_cidr(mask_val)
                        if prefix is not None:
                            dst = "any" if (prefix == 0 and ip_val == "0.0.0.0") else f"{ip_val}/{prefix}"
                        else:
                            dst = f"{ip_val}/32"
                else:
                    dst = "any" if ip_val == "any" else f"{ip_val}/32"

        return src, dst


class DellOSParser(BaseACLParser):
    """ Парсер ACL для Dell Networking OS (FTOS / OS9 / OS10) """

    def parse(self):
        self._parse_object_groups()
        current_acl = None
        current_type = 'extended'

        for line in self.config_lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("!") or line_str.startswith("#"):
                continue

            lower_line = line_str.lower()

            # 1. Заголовок контекста ACL: ip access-list [standard|extended] <NAME>
            if lower_line.startswith("ip access-list ") or lower_line.startswith("mac access-list "):
                parts = line_str.split()
                if len(parts) >= 4 and parts[2].lower() in ("standard", "extended"):
                    acl_type = parts[2].lower()
                    acl_name = parts[3]
                    if acl_name not in self.acls:
                        self.acls[acl_name] = {
                            'type': acl_type,
                            'rules': [],
                            'header_prefix': f"{parts[0]} access-list"
                        }
                    current_acl = acl_name
                    current_type = acl_type
                    continue

            # 2. Правила внутри контекста
            if current_acl:
                if lower_line.startswith("seq ") or lower_line.startswith("permit") or lower_line.startswith(
                        "deny") or lower_line.startswith("remark"):
                    self.acls[current_acl]['rules'].append(line_str)
                elif lower_line in ("exit", "end") or line_str.startswith("!"):
                    current_acl = None

    def _parse_object_groups(self):
        """ Парсинг object-group в Dell OS (при наличии) """
        current_name = None
        current_values = []
        for line in self.config_lines:
            s = line.strip()
            lower_s = s.lower()
            if lower_s.startswith("object-group ip address") or lower_s.startswith("object-group network"):
                if current_name:
                    self.object_groups[current_name] = current_values
                current_name = s.split()[-1]
                current_values = []
            elif current_name:
                if lower_s.startswith("host ") or lower_s.startswith("network-object host"):
                    current_values.append(s.split()[-1] + "/32")
                elif lower_s.startswith("network-object "):
                    parts = s.split()
                    if len(parts) >= 2:
                        target = parts[1]
                        if '/' in target:
                            current_values.append(target)
                        elif len(parts) >= 3 and self._is_ip(parts[2]):
                            prefix = self._mask_to_cidr(parts[2]) or self._wildcard_to_cidr(parts[2])
                            if prefix is not None:
                                current_values.append(f"{target}/{prefix}")
                elif lower_s.startswith("exit") or s == "!":
                    self.object_groups[current_name] = current_values
                    current_name = None
                    current_values = []
        if current_name:
            self.object_groups[current_name] = current_values

    def _extract_src_dst(self, parts, acl_type):
        i = 0

        # 1. Пропуск префикса "ip access-list <TYPE> <NAME>", если передана строка целиком
        if len(parts) > 1 and parts[0].lower() in ("ip", "mac") and parts[1].lower() == "access-list":
            i = 4 if len(parts) >= 4 and parts[2].lower() in ("standard", "extended") else 3

        # 2. Пропуск номера правила / seq (например: "seq 20" или "20")
        if i < len(parts) and parts[i].lower() == "seq":
            i += 1
            if i < len(parts) and parts[i].isdigit():
                i += 1
        elif i < len(parts) and parts[i].isdigit():
            i += 1

        # 3. Пропуск действия (permit/deny)
        if i < len(parts) and parts[i].lower() in ('permit', 'deny'):
            i += 1

        # 4. Пропуск протокола для extended ACL (ip, tcp, udp, icmp и др.)
        # KNOWN_PROTOCOLS = frozenset({'ip', 'tcp', 'udp', 'icmp'})
        if acl_type == 'extended' and i < len(parts):
            if parts[i].lower() in KNOWN_PROTOCOLS or (parts[i].isdigit() and int(parts[i]) <= 255):
                i += 1

        # PORT_OPS = {'eq', 'gt', 'lt', 'neq', 'range'}

        def consume_port_and_flags(idx):
            """ Пропускает порты и мета-флаги (log threshold-in-msgs 10 interval 5 и т.д.) """
            while idx < len(parts):
                word = parts[idx].lower()
                if word in PORT_OPS:
                    idx += 3 if word == 'range' else 2
                elif word == 'log':
                    idx += 1
                    # Пропуск доп. параметров Dell log: threshold-in-msgs <N> interval <N>
                    while idx < len(parts) and parts[idx].lower() in ('threshold-in-msgs', 'interval', 'count'):
                        idx += 2
                elif word in ('established', 'count', 'bytes'):
                    idx += 1
                else:
                    break
            return idx

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx

            word = parts[idx]

            # Вариант 1: any / any4
            if word.lower() in ("any", "any4"):
                next_idx = consume_port_and_flags(idx + 1)
                return "any", next_idx

            # Вариант 2: host <IP>
            if word.lower() == "host":
                if idx + 1 < len(parts):
                    host_ip = parts[idx + 1]
                    next_idx = consume_port_and_flags(idx + 2)
                    return f"{host_ip}/32", next_idx
                return "any", idx + 1

            # Вариант 3: object-group / addrgroup <NAME>
            if word.lower() in ("object-group", "addrgroup"):
                if idx + 1 < len(parts):
                    group_name = parts[idx + 1]
                    next_idx = consume_port_and_flags(idx + 2)
                    return group_name, next_idx
                return "any", idx + 1

            # Вариант 4: Префикс CIDR (например, 10.26.244.24/31 или 10.160.18.0/26)
            if '/' in word:
                next_idx = consume_port_and_flags(idx + 1)
                return word, next_idx

            # Вариант 5: IP-адрес + Wildcard/Subnet маска
            if self._is_ip(word):
                if idx + 1 < len(parts) and self._is_ip(parts[idx + 1]):
                    mask_or_wildcard = parts[idx + 1]

                    if word == "0.0.0.0" and mask_or_wildcard in ("255.255.255.255", "0.0.0.0"):
                        next_idx = consume_port_and_flags(idx + 2)
                        return "any", next_idx

                    prefix = self._wildcard_to_cidr(mask_or_wildcard)
                    if prefix is None:
                        prefix = self._mask_to_cidr(mask_or_wildcard)

                    if prefix is not None:
                        if prefix == 0 and word == "0.0.0.0":
                            next_idx = consume_port_and_flags(idx + 2)
                            return "any", next_idx

                        next_idx = consume_port_and_flags(idx + 2)
                        return f"{word}/{prefix}", next_idx

                # Если маска не указана — считаем /32
                next_idx = consume_port_and_flags(idx + 1)
                return f"{word}/32", next_idx

            return "any", idx + 1

        src, i = parse_entry(i)
        dst = "any" if acl_type == 'standard' else parse_entry(i)[0]
        return src, dst


class QTechParser(BaseACLParser):
    """ Парсер ACL для устройств QTECH (QOS / QSW) """

    def parse(self):
        self._parse_object_groups()
        current_acl = None
        current_type = 'extended'

        for line in self.config_lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("!") or line_str.startswith("#"):
                continue

            lower_line = line_str.lower()

            # 1. Заголовок контекста ACL: ip access-list [standard|extended] <NAME>
            if lower_line.startswith("ip access-list "):
                parts = line_str.split()
                if len(parts) >= 4 and parts[2].lower() in ("standard", "extended"):
                    acl_type = parts[2].lower()
                    acl_name = parts[3]
                    if acl_name not in self.acls:
                        self.acls[acl_name] = {
                            'type': acl_type,
                            'rules': [],
                            'header_prefix': 'ip access-list'
                        }
                    current_acl = acl_name
                    current_type = acl_type
                    continue

            # 2. Правила внутри контекста
            if current_acl:
                if lower_line.startswith("permit") or lower_line.startswith("deny") or lower_line.startswith(
                        "seq ") or lower_line.startswith("remark"):
                    self.acls[current_acl]['rules'].append(line_str)
                elif lower_line in ("exit", "end") or line_str.startswith("!"):
                    current_acl = None

    def _parse_object_groups(self):
        """ Парсинг object-group в QTECH (при наличии) """
        current_name = None
        current_values = []
        for line in self.config_lines:
            s = line.strip()
            lower_s = s.lower()
            if lower_s.startswith("object-group ip address") or lower_s.startswith("object-group network"):
                if current_name:
                    self.object_groups[current_name] = current_values
                current_name = s.split()[-1]
                current_values = []
            elif current_name:
                if lower_s.startswith("host ") or lower_s.startswith("host-source ") or lower_s.startswith(
                        "host-destination "):
                    current_values.append(s.split()[-1] + "/32")
                elif lower_s.startswith("network-object "):
                    parts = s.split()
                    if len(parts) >= 2:
                        target = parts[1]
                        if '/' in target:
                            current_values.append(target)
                        elif len(parts) >= 3 and self._is_ip(parts[2]):
                            prefix = self._wildcard_to_cidr(parts[2]) or self._mask_to_cidr(parts[2])
                            if prefix is not None:
                                current_values.append(f"{target}/{prefix}")
                elif lower_s.startswith("exit") or s == "!":
                    self.object_groups[current_name] = current_values
                    current_name = None
                    current_values = []
        if current_name:
            self.object_groups[current_name] = current_values

    def _extract_src_dst(self, parts, acl_type):
        i = 0

        # 1. Пропуск префикса "ip access-list <TYPE> <NAME>" если передана вся строка
        if len(parts) > 1 and parts[0].lower() == "ip" and parts[1].lower() == "access-list":
            i = 4 if len(parts) >= 4 and parts[2].lower() in ("standard", "extended") else 3

        # 2. Пропуск номера правила / seq (если есть)
        if i < len(parts) and parts[i].lower() == "seq":
            i += 1
            if i < len(parts) and parts[i].isdigit():
                i += 1
        elif i < len(parts) and parts[i].isdigit():
            i += 1

        # 3. Пропуск действия (permit/deny)
        if i < len(parts) and parts[i].lower() in ('permit', 'deny'):
            i += 1

        # 4. Пропуск протокола для extended ACL (ip, tcp, udp, icmp и др.)
        # KNOWN_PROTOCOLS = frozenset({'ip', 'tcp', 'udp', 'icmp'})
        if acl_type == 'extended' and i < len(parts):
            if parts[i].lower() in KNOWN_PROTOCOLS or (parts[i].isdigit() and int(parts[i]) <= 255):
                i += 1

        # PORT_OPS = {'eq', 'gt', 'lt', 'neq', 'range', 'destination-port', 'source-port'}

        def consume_port_and_flags(idx):
            """ Пропускает порты и служебные флаги """
            while idx < len(parts):
                word = parts[idx].lower()
                if word in ('destination-port', 'source-port'):
                    idx += 1
                    if idx < len(parts) and parts[idx].lower() in ('eq', 'gt', 'lt', 'neq'):
                        idx += 2
                    elif idx < len(parts) and parts[idx].lower() == 'range':
                        idx += 3
                    else:
                        idx += 1
                elif word in ('eq', 'gt', 'lt', 'neq'):
                    idx += 2
                elif word == 'range':
                    idx += 3
                elif word in ('established', 'log', 'log-input', 'dscp', 'tos'):
                    if word in ('dscp', 'tos') and idx + 1 < len(parts):
                        idx += 2
                    else:
                        idx += 1
                else:
                    break
            return idx

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx

            word = parts[idx]

            # Вариант 1: any / any4 / any-source / any-destination
            if word.lower() in ("any", "any4", "any-source", "any-destination"):
                next_idx = consume_port_and_flags(idx + 1)
                return "any", next_idx

            # Вариант 2: host / host-source / host-destination <IP>
            if word.lower() in ("host", "host-source", "host-destination"):
                if idx + 1 < len(parts):
                    host_ip = parts[idx + 1]
                    next_idx = consume_port_and_flags(idx + 2)
                    return f"{host_ip}/32", next_idx
                return "any", idx + 1

            # Вариант 3: object-group / addrgroup <NAME>
            if word.lower() in ("object-group", "addrgroup"):
                if idx + 1 < len(parts):
                    group_name = parts[idx + 1]
                    next_idx = consume_port_and_flags(idx + 2)
                    return group_name, next_idx
                return "any", idx + 1

            # Вариант 4: Префикс CIDR (10.143.58.128/26)
            if '/' in word:
                next_idx = consume_port_and_flags(idx + 1)
                return word, next_idx

            # Вариант 5: IP-адрес + Wildcard/Subnet маска (10.143.58.128 0.0.0.63)
            if self._is_ip(word):
                if idx + 1 < len(parts) and self._is_ip(parts[idx + 1]):
                    mask_or_wildcard = parts[idx + 1]

                    if word == "0.0.0.0" and mask_or_wildcard in ("255.255.255.255", "0.0.0.0"):
                        next_idx = consume_port_and_flags(idx + 2)
                        return "any", next_idx

                    # Для QTECH сначала проверяем Wildcard (0.0.0.63), затем Subnet mask
                    prefix = self._wildcard_to_cidr(mask_or_wildcard)
                    if prefix is None:
                        prefix = self._mask_to_cidr(mask_or_wildcard)

                    if prefix is not None:
                        if prefix == 0 and word == "0.0.0.0":
                            next_idx = consume_port_and_flags(idx + 2)
                            return "any", next_idx

                        next_idx = consume_port_and_flags(idx + 2)
                        return f"{word}/{prefix}", next_idx

                # Если маска не указана — считаем /32
                next_idx = consume_port_and_flags(idx + 1)
                return f"{word}/32", next_idx

            return "any", idx + 1

        src, i = parse_entry(i)
        dst = "any" if acl_type == 'standard' else parse_entry(i)[0]
        return src, dst

class ACLParserFactory:
    PARSERS = {
        'Cisco ASA': CiscoASAParser5,
        'Cisco FXOS': CiscoASAParser5,
        'Cisco PIX': CiscoASAParser5,
        'FortiOS': FortiOSParser2,
        'Cisco IOS': CiscoIOSParser2,
        'Cisco IOS XE': CiscoIOSXEParser2,
        'Cisco IOS XR': CiscoIOSXEParser2,
        'HP ProCurve': HPProCurveParser2,
        'B4COM BCOM-OS-DC': IPInfusionParser,
        'B4COM BCOM-OS-DC (VXLAN)': IPInfusionParser,
        'EdgeCore': EdgeCoreParser,
        'IBM_Lenovo Network OS': IBMLenovoParser,
        'Dell Networking OS': DellOSParser,
        'QTECH': QTechParser,
        'Cisco NX-OS': CiscoNexusParser2,
        'Huawei VRP': HuaweiParser4,
        'Huawei VRP 2403': HuaweiParser4,
        'Juniper Junos': JuniperACLParser2,
        'Eltex': EltexACLParser2,
        'Eltex ESR': EltexESRParser2,
        'HPE OfficeConnect': HPEParser2,
        'HPE Comware 1910': HPEParser2,
        'HPE Comware': HPEParser2,
        '3Com Comware 1910': HPEParser2,
    }

    @classmethod
    def parse_from_file(
        cls,
        vendor_os,
        filename,
        src_ip="any",
        dst_ip="any",
        strict_mode=False,
        ignore_src_any=False,
        ignore_dst_any=False,
        src_mask_limit=None,
        dst_mask_limit=None,
        base_dir=base_dir,
        encoding="utf-8"
    ):
        parser_cls = cls.PARSERS.get(vendor_os)
        if not parser_cls:
            return tuple()

        # Поиск файла в файловой системе
        for root, _, files in os.walk(base_dir):
            if filename in files:
                full_path = os.path.join(root, filename)
                try:
                    with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                        config_text = f.read()
                except Exception:
                    return tuple()

                # 1. Передаем конфиг в __init__ конкретного класса
                parser = parser_cls(config_text)

                # 2. Передаем критерии поиска в метод поиска конкретного класса
                return parser.find_acl_matches(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    strict_mode=strict_mode,
                    ignore_src_any=ignore_src_any,
                    ignore_dst_any=ignore_dst_any,
                    src_mask_limit=src_mask_limit,
                    dst_mask_limit=dst_mask_limit
                )
        return tuple()
