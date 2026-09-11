import sys

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import ipaddress
from collections import defaultdict
from itertools import product
import re
import os

from path import DATA_DIR
base_dir = DATA_DIR+"/config_files_clear"
# base_dir = os.path.join(DATA_DIR,'config_files_clear')


# base_dir = DATA_DIR + "/config_files_clear"
# APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
# base_dir="/home/PR.RT.RU/a.kalyaev/PycharmProjects/PythonProject/data/config_files_clear"
# print("здесь 2:",base_dir)

class CiscoIOSXEParser:
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
        except Exception as e:
            # print(f"[DEBUG] _wildcard_to_cidr: Error for wildcard={wildcard}: {e}")
            return None

    def _mask_to_cidr(self, mask):
        try:
            mask_int = int(ipaddress.IPv4Address(mask))
            prefix = bin(mask_int).count('1')
            return prefix
        except:
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
        except ValueError as e:
            # print(f"[DEBUG] _cand_to_net: Error for cand={cand}: {e}")
            return None
        return None

    def _matches(self, input_str, candidates, strict_mode):
        # print(f"[DEBUG] _matches: input_str={input_str}, candidates={candidates}, strict_mode={strict_mode}")
        if not input_str and any(c == "any" for c in candidates):
            # print(f"[DEBUG] _matches: Empty input matches 'any'")
            return True
        if input_str == "any":
            if strict_mode:
                if "any" in candidates:
                    # print(f"[DEBUG] _matches: Input 'any' matches 'any' in candidates (strict_mode=True)")
                    return True
                else:
                    # print(f"[DEBUG] _matches: Input 'any' does not match candidates (strict_mode=True)")
                    return False
            else:
                # print(f"[DEBUG] _matches: Input 'any' matches any candidate (strict_mode=False)")
                return True
        try:
            if '/' in input_str:
                input_net = ipaddress.ip_network(input_str, strict=False)
                for cand in candidates:
                    if cand == "any" and strict_mode:
                        continue
                    cand_net = self._cand_to_net(cand)
                    if cand_net and cand_net == input_net:
                        # print(f"[DEBUG] _matches: Network match: input_net={input_net}, cand_net={cand_net}")
                        return True
                # print(f"[DEBUG] _matches: No network match for input_net={input_net}")
                return False
            else:
                input_ip = ipaddress.ip_address(input_str)
                input_net_32 = ipaddress.ip_network(str(input_ip) + '/32', strict=False)
                for cand in candidates:
                    if cand == "any" and strict_mode:
                        continue
                    cand_net = self._cand_to_net(cand)
                    if cand_net:
                        if strict_mode:
                            if cand_net == input_net_32:
                                # print(f"[DEBUG] _matches: Strict IP match: input_ip={input_ip}, cand_net={cand_net}")
                                return True
                        else:
                            if input_ip in cand_net:
                                # print(f"[DEBUG] _matches: IP in network: input_ip={input_ip}, cand_net={cand_net}")
                                return True
                            # else:
                            #     print(f"[DEBUG] _matches: IP {input_ip} not in network {cand_net}")
                        continue
                    elif self._is_ip(cand):
                        if input_ip == ipaddress.ip_address(cand):
                            # print(f"[DEBUG] _matches: Exact IP match: input_ip={input_ip}, cand={cand}")
                            return True
                        # else:
                            # print(f"[DEBUG] _matches: No exact IP match: input_ip={input_ip}, cand={cand}")
                # print(f"[DEBUG] _matches: No match for input_ip={input_ip}")
                return False
        except ValueError as e:
            # print(f"[DEBUG] _matches: ValueError: {e}")
            return False

    def _extract_src_dst(self, parts, acl_type):
        i = 0
        if parts[0] == 'access-list':
            i = 2
        if i < len(parts) and parts[i].isdigit():
            i += 1
        if i < len(parts) and parts[i] in ['permit', 'deny']:
            i += 1
        if i < len(parts) and parts[i] == 'ipv4':  # Handle IOS XR
            i += 1
        if acl_type == 'extended' and i < len(parts) and parts[i] not in ['any', 'host', 'object-group'] and not self._is_ip(parts[i]):
            i += 1

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx
            word = parts[idx]
            if word == "object-group":
                if idx + 1 < len(parts):
                    return parts[idx + 1], idx + 2
                return "any", idx + 2
            elif word == "host":
                if idx + 1 < len(parts) and self._is_ip(parts[idx + 1]):
                    return parts[idx + 1] + "/32", idx + 2
                return "any", idx + 2
            elif word == "any":
                return "any", idx + 1
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

        while i < len(parts) and parts[i] in ['eq', 'range', 'gt', 'lt', 'established', 'log']:
            i += 2 if parts[i] in ['eq', 'gt', 'lt', 'log', 'established'] else 3

        dst, i = parse_entry(i)
        while i < len(parts) and parts[i] in ['eq', 'range', 'gt', 'lt', 'established', 'log']:
            i += 2 if parts[i] in ['eq', 'gt', 'lt', 'log', 'established'] else 3

        return src, dst

    def _resolve_entry(self, entry):
        if not entry or entry == "any":
            return ["any"]
        if "/" in entry or self._is_ip(entry):
            return [entry]
        if entry in self.object_groups:
            resolved = []
            for sub in self.object_groups[entry]:
                if self._is_ip(sub) and '/' not in sub:
                    resolved.append(sub + "/32")
                else:
                    resolved.extend(self._resolve_entry(sub))
            return resolved
        return []

    def parse(self):
        current_group = None
        current_values = []
        current_acl = None
        acl_type = ''
        in_acl = False

        for line_num, line in enumerate(self.config_lines):
            original_line = line.strip()
            line = line.strip()
            if not line:
                continue

            # print(f"[DEBUG] Processing line {line_num}: '{line}'")

            # Object groups
            if line.startswith("object-group network "):
                if current_group:
                    self.object_groups[current_group] = current_values
                    # print(f"[DEBUG] Closing object-group: {current_group}")
                current_group = line.split()[2]
                current_values = []
                # print(f"[DEBUG] Starting object-group: {current_group}")
                continue

            if current_group:
                if line == "exit" or line.endswith("}"):
                    self.object_groups[current_group] = current_values
                    # print(f"[DEBUG] Ending object-group: {current_group} with {len(current_values)} entries")
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
                    # print(f"[DEBUG] Closing object-group due to new section: {current_group}")
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
                            # print(f"[DEBUG] Added host to {current_group}: {parts[1]}/32")
                    elif word == "group-object":
                        if len(parts) > 1:
                            current_values.append(parts[1])
                            # print(f"[DEBUG] Added group-object to {current_group}: {parts[1]}")
                    elif len(parts) == 2 and self._is_ip(parts[0]) and self._is_mask(parts[1]):
                        try:
                            prefix = self._mask_to_cidr(parts[1]) or self._wildcard_to_cidr(parts[1])
                            if prefix is not None:
                                network = ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                                current_values.append(str(network))
                                # print(f"[DEBUG] Added network to {current_group}: {network}")
                        except ValueError as e:
                            # print(f"[DEBUG] parse: Error processing network {parts[0]} {parts[1]}: {e}")
                            continue
                    elif self._is_ip(word):
                        current_values.append(word + "/32")
                        # print(f"[DEBUG] Added IP to {current_group}: {word}/32")
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
                    # print(f"[DEBUG] Parsing numbered ACL: acl_name={acl_name}, rule={rule}, seq={seq_number}, type={acl_type}")
                    self.acl_lines.append((acl_name, rule, seq_number, acl_type, 'access-list'))
                continue

            # Named ACLs (IOS, IOS XE, IOS XR)
            if line.startswith("ip access-list ") or line.startswith("ipv4 access-list "):
                # print(f"[DEBUG] Found ACL header: '{line}'")
                parts = line.split(maxsplit=4)
                header_prefix = 'ip access-list' if line.startswith("ip access-list ") else 'ipv4 access-list'
                if len(parts) >= 3:
                    acl_type = parts[2] if len(parts) == 4 and parts[2] in ['standard', 'extended'] else 'extended'
                    current_acl = parts[3] if len(parts) == 4 else parts[2]
                    in_acl = True
                    # print(f"[DEBUG] Starting ACL: {header_prefix} {acl_type} {current_acl}")
                continue

            # Rules
            if in_acl:
                if line == "exit" or line.endswith("}"):
                    # print(f"[DEBUG] Ending ACL: {current_acl}")
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
                    # print(f"[DEBUG] Adding ACL rule: {current_acl} - {rule}")
                    self.acl_lines.append((current_acl, rule, seq_number, acl_type, header_prefix))
                continue

        if current_group:
            self.object_groups[current_group] = current_values
            # print(f"[DEBUG] Closing object-group at EOF: {current_group}")

        # print(f"[DEBUG] Total ACL lines parsed: {len(self.acl_lines)}")
        # print(f"[DEBUG] Total object-groups parsed: {len(self.object_groups)}")

    def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
        matches = []
        current_acl = None
        for acl_name, full_line, seq_number, acl_type, header_prefix in self.acl_lines:
            parts = full_line.split()
            # print(f"[DEBUG] Processing ACL: acl_name={acl_name}, line={full_line}, seq={seq_number}, acl_type={acl_type}, header_prefix={header_prefix}")
            try:
                src_entry, dst_entry = self._extract_src_dst(parts, acl_type)
                src_ips = self._resolve_entry(src_entry)
                dst_ips = self._resolve_entry(dst_entry)
                # print(f"[DEBUG] Extracted: src_entry={src_entry}, dst_entry={dst_entry}, src_ips={src_ips}, dst_ips={dst_ips}")

                is_special_case = (not src_ip or src_ip == "any") and (not dst_ip or dst_ip == "any")
                if is_special_case:
                    # print(f"[DEBUG] Matched: acl={acl_name}, line={full_line}, special case inputs")
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
                else:
                    src_ok = self._matches(src_ip, src_ips, strict_mode)
                    dst_ok = self._matches(dst_ip, dst_ips, strict_mode)
                    if src_ok and dst_ok:
                        # print(f"[DEBUG] Matched: acl={acl_name}, line={full_line}, src_ok={src_ok}, dst_ok={dst_ok}")
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
            except Exception as e:
                # print(f"[!] Error: {e} in line: {full_line}")
                continue
        return tuple(matches)

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, strict_mode=False, base_dir=base_dir, encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                        # print(f"[DEBUG] Found and reading file: {full_path}")
                    except Exception as e:
                        # print(f"[!] Error reading {full_path}: {e}")
                        continue
                    parser = cls(config_text)
                    return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
        # print(f"⚠️ File {filename} not found in directory {base_dir}")
        return tuple()
class CiscoIOSParser:
    def __init__(self, config_text, hp_procurve=False):
        self.config_lines = config_text.splitlines()
        self.object_groups = defaultdict(list)
        self.acls = {}  # {acl_name: {'type': 'standard'|'extended', 'rules': [raw_line, ...], 'header_prefix': 'ip'|'access-list ip'}}
        self.hp_procurve = hp_procurve
        self.parse()

    def _wildcard_to_cidr(self, wildcard):
        try:
            mask = int(ipaddress.IPv4Address(wildcard))
            prefix = 32 - bin(mask).count('1')
            return prefix
        except:
            return None

    def _mask_to_cidr(self, mask):
        try:
            mask_int = int(ipaddress.IPv4Address(mask))
            prefix = bin(mask_int).count('1')
            return prefix
        except:
            return None

    def _expand_ip_range(self, start_ip, end_ip):
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            return [(start, end)]
        except ValueError:
            return []

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
            elif isinstance(cand, tuple):
                if len(cand) == 2 and cand[0] == cand[1]:
                    return ipaddress.ip_network(str(cand[0]) + '/32', strict=False)
        except ValueError:
            return None
        return None

    def _is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _matches(self, input_str, candidates, strict_mode, is_standard_acl=False):
        if input_str == "any":
            return True
        if "any" in candidates:
            return not strict_mode or is_standard_acl  # For standard ACL, dst=any always matches in strict mode if input is any
        try:
            if '/' in input_str:  # Network input
                input_net = ipaddress.ip_network(input_str, strict=False)
                for candid in candidates:
                    cand_net = self._cand_to_net(candid)
                    if cand_net and cand_net == input_net:
                        return True
                return False
            else:  # IP input
                input_ip = ipaddress.ip_address(input_str)
                input_net_32 = ipaddress.ip_network(str(input_ip) + '/32', strict=False)
                for candid in candidates:
                    if strict_mode:
                        cand_net = self._cand_to_net(candid)
                        if cand_net and cand_net == input_net_32:
                            return True
                    else:
                        try:
                            if isinstance(candid, tuple) and len(candid) == 2:
                                start, end = candid
                                if start <= input_ip <= end:
                                    return True
                            elif "/" in candid or ' ' in candid:
                                cand_net = self._cand_to_net(candid)
                                if cand_net and input_ip in cand_net:
                                    return True
                            elif self._is_ip(candid):
                                if input_ip == ipaddress.ip_address(candid):
                                    return True
                            else:
                                parts = candid.split('/')
                                if len(parts) == 2 and self._is_ip(parts[0]):
                                    if input_ip == ipaddress.ip_address(parts[0]):
                                        return True
                        except Exception:
                            continue
                return False
        except ValueError:
            return False

    def parse(self):
        self._parse_object_groups()
        current_group = None
        current_acl = None
        current_type = 'extended'  # Default
        for line in self.config_lines:
            line = line.strip()
            if not line:
                continue

            # IBM Lenovo: access management-network
            if line.startswith("access management-network"):
                parts = line.split()
                if len(parts) >= 3 and self._is_ip(parts[2]):
                    acl_name = "management-network"
                    if acl_name not in self.acls:
                        self.acls[acl_name] = {'type': 'standard', 'rules': [], 'header_prefix': 'access'}
                    rule = f"permit {parts[2]} {parts[3]}"
                    self.acls[acl_name]['rules'].append(rule)
                continue

            # EdgeCore/Cisco numbered ACLs
            if line.startswith("access-list ip ") or line.startswith("access-list "):
                parts = line.split(maxsplit=3)
                if len(parts) >= 3 and parts[1] == "ip" and parts[2] in ("standard", "extended"):
                    acl_type = parts[2]
                    acl_name = parts[3].strip('"')  # Strip quotes for HP ProCurve compatibility
                    if acl_name not in self.acls:
                        self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'access-list ip'}
                    current_acl = acl_name
                    current_type = acl_type
                    continue
                elif len(parts) > 2:
                    acl_name = parts[1]
                    if acl_name.isdigit():
                        acl_type = 'standard' if int(acl_name) < 100 or 1300 <= int(acl_name) <= 1999 else 'extended'
                        rule = ' '.join(parts[2:])
                        if acl_name not in self.acls:
                            self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'access-list'}
                        self.acls[acl_name]['rules'].append(rule)
                    continue

            # Named ACLs (Cisco, Ip Infusion, Dell, HP ProCurve)
            if line.startswith("ip access-list "):
                parts = line.split(maxsplit=4)
                acl_type = 'extended'  # Default
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

            # Object groups
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
                            network = ipaddress.ip_network(f"{parts[0]}/{self._wildcard_to_cidr(parts[1])}", strict=False)
                            current_values.append(str(network))
                        except ValueError:
                            continue
                elif line == "exit" or line.endswith("}"):
                    self.object_groups[current_group] = current_values
                    current_group = None
                continue

            # Rules
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
            if s.startswith("object-group ip address") or s.startswith("object-group network"):
                if current_name:
                    self.object_groups[current_name] = current_values
                current_name = s.split()[-1]
                current_values = []
            elif current_name:
                if s.startswith("host-info "):
                    ip = s.split()[-1]
                    current_values.append(ip + "/32")
                elif s.startswith("host "):
                    ip = s.split()[-1]
                    current_values.append(ip + "/32")
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
        # Skip sequence number or "seq <num>"
        if parts and (parts[i].isdigit() or parts[i] == "seq"):
            i += 1
            if parts[i-1] == "seq" and i < len(parts):
                i += 1
        # Skip action
        if i < len(parts) and parts[i] in ['permit', 'deny']:
            i += 1

        # For extended, skip protocol
        if acl_type == 'extended':
            if i < len(parts) and parts[i] not in ['any', 'host', 'object-group', 'addrgroup', 'range'] and not re.match(r'\d+\.\d+\.\d+\.\d+(?:/\d+)?', parts[i]):
                i += 1

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx
            word = parts[idx]
            if word in ["object-group", "addrgroup"]:
                return parts[idx + 1], idx + 2
            elif word == "host":
                return parts[idx + 1] + "/32", idx + 2
            elif word == "any":
                return "any", idx + 1
            elif re.match(r'\d+\.\d+\.\d+\.\d+/\d+', word):  # CIDR
                return word, idx + 1
            elif self._is_ip(word):
                if idx + 1 < len(parts) and (self._is_ip(parts[idx + 1]) or re.match(r'\d+\.\d+\.\d+\.\d+', parts[idx + 1])):
                    mask = parts[idx + 1]
                    if re.match(r'0\.', mask):  # Wildcard
                        prefix = self._wildcard_to_cidr(mask)
                    else:  # Subnet mask
                        prefix = self._mask_to_cidr(mask)
                    if prefix is not None:
                        return f"{parts[idx]}/{prefix}", idx + 2
                    else:
                        return parts[idx] + "/32", idx + 1
                else:
                    return parts[idx] + "/32", idx + 1
            return "any", idx + 1

        src, i = parse_entry(i)

        # For standard ACLs, destination is always 'any'
        dst = "any" if acl_type == 'standard' else parse_entry(i)[0]

        # For extended ACLs, parse destination and skip extras
        if acl_type == 'extended':
            dst, i = parse_entry(i)
            # Skip destination ports or extras
            while i < len(parts) and parts[i] in ["eq", "gt", "lt", "neq", "range", "established", "destination-port", "log", "threshold-in-msgs", "interval"]:
                i += 1
                if i < len(parts):
                    i += 1
                    if parts[i-2] in ["range", "threshold-in-msgs", "interval"] and i < len(parts):
                        i += 1

        return src, dst

    def _resolve_entry(self, entry):
        if not entry or entry == "any":
            return ["any"]
        if "/" in entry or self._is_ip(entry) or ' ' in entry:
            return [entry]
        if entry in self.object_groups:
            return self.object_groups[entry]
        return []

    def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
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

                    # Skip rules with src=any and dst=any
                    if src_ips == ["any"] and dst_ips == ["any"]:
                        continue

                    src_ok = self._matches(src_ip, src_ips, strict_mode, is_standard_acl=(acl_type == 'standard'))
                    # For standard ACL, dst_ok is True only if dst_ip is "any" in strict_mode
                    dst_ok = (acl_type == 'standard' and (not strict_mode or dst_ip == "any")) or \
                             self._matches(dst_ip, dst_ips, strict_mode, is_standard_acl=False)
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

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, strict_mode=False, base_dir=base_dir,
                        encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                    except Exception as e:
                        # print(f"[!] Error reading {full_path}: {e}")
                        continue
                    parser = cls(config_text)
                    return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
        # print(f"⚠️ File {filename} not found in directory {base_dir}")
        return tuple()
class CiscoASAParser3:
        def __init__(self, config_text):
            self.config_lines = config_text.splitlines()
            self.objects = {}  # object network name -> [networks]
            self.object_groups = defaultdict(list)  # object-group network -> [networks/objects]
            self.acl_lines = []  # access-list строки
            self.parse()

        @classmethod
        def from_local_file(cls, filename, src_ip, dst_ip, strict_mode=False, base_dir=base_dir,
                            encoding="utf-8"):
            for root, _, files in os.walk(base_dir):
                for file in files:
                    if file == filename:
                        full_path = os.path.join(root, file)
                        try:
                            with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                                config_text = f.read()
                        except Exception as e:
                            # print(f"[!] Error reading {full_path}: {e}")
                            continue
                        parser = cls(config_text)
                        return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
            # print(f"⚠️ File {filename} not found in directory {base_dir}")
            return tuple()

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

            # Разворачиваем вложенные группы
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
                return [(start, end)]  # диапазон
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
            if not entry or entry == "any" or entry == "any4":
                return ["any"]
            if isinstance(entry, tuple):  # диапазон или netmask
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
                        if cand[0] == cand[1]:
                            return ipaddress.ip_network(str(cand[0]) + '/32', strict=False)
                        else:
                            return None
            except ValueError:
                return None
            return None

        def _matches(self, input_str, candidates, strict_mode):
            if input_str == "any":
                return True

            try:
                if '/' in input_str:  # network
                    input_net = ipaddress.ip_network(input_str, strict=False)
                    for cand in candidates:
                        cand_net = self._cand_to_net(cand)
                        if cand_net and cand_net == input_net:
                            return True
                    return False
                else:  # IP
                    input_ip = ipaddress.ip_address(input_str)
                    input_net_32 = ipaddress.ip_network(str(input_ip) + '/32', strict=False)
                    for cand in candidates:
                        if strict_mode:
                            # only exact /32
                            cand_net = self._cand_to_net(cand)
                            if cand_net and cand_net == input_net_32:
                                return True
                        else:
                            try:
                                if isinstance(cand, tuple):
                                    if len(cand) == 3 and cand[0] == 'netmask':
                                        net = ipaddress.ip_network((cand[1], cand[2]), strict=False)
                                        if input_ip in net:
                                            return True
                                    elif len(cand) == 2:
                                        start, end = cand
                                        if start <= input_ip <= end:
                                            return True
                                elif cand.startswith("host "):
                                    cand_ip = cand.split()[1]
                                    if input_ip == ipaddress.ip_address(cand_ip):
                                        return True
                                elif "/" in cand:  # CIDR
                                    if input_ip in ipaddress.ip_network(cand, strict=False):
                                        return True
                                else:
                                    parts = cand.split()
                                    if len(parts) == 2:  # ip + mask
                                        net_ip, mask = parts
                                        net = ipaddress.ip_network((net_ip, mask), strict=False)
                                        if input_ip in net:
                                            return True
                                    elif self._is_ip(cand):
                                        if input_ip == ipaddress.ip_address(cand):
                                            return True
                            except Exception:
                                continue
                    return False
            except ValueError:
                return False

        def _extract_src_dst(self, parts):
            i = 4
            if parts[i] in ['ip', 'tcp', 'udp', 'icmp']:
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
                elif parts[idx] == "any" or parts[idx] == "any4":
                    return "any", idx + 1
                elif self._is_ip(parts[idx]):
                    if idx + 1 < len(parts) and self._is_dotted_decimal(parts[idx + 1]):
                        second = parts[idx + 1]
                        if second.startswith('255'):
                            # Treat as netmask
                            return ('netmask', parts[idx], second), idx + 2
                        else:
                            # Treat as range (though rare in ACLs)
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

        def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
            matches = set()
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
                    src_ok = self._matches(src_ip, src_ips, strict_mode)
                    dst_ok = self._matches(dst_ip, dst_ips, strict_mode)

                    if src_ok and dst_ok:
                        matches.add(line)
                except Exception as e:
                    # print(f"[!] Ошибка: {e} в строке: {line}")
                    continue
            return matches
class CiscoASAParser4:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.objects = {}  # object network name -> [networks]
        self.object_groups = defaultdict(list)  # object-group network -> [networks/objects]
        self.acl_lines = []  # access-list строки
        self.parse()

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
        base_dir=None,
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
                        continue
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
        return tuple()

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
        if not entry or entry == "any" or entry == "any4":
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
                    if cand[0] == cand[1]:
                        return ipaddress.ip_network(str(cand[0]) + '/32', strict=False)
                    else:
                        return None
        except ValueError:
            return None
        return None

    def _matches(self, input_str, candidates, strict_mode, ignore_any=False, mask_limit=None):
        # 1. Если кандидат "any" и включен флаг ignore_any — бракуем сразу
        if ignore_any and candidates == ["any"]:
            return False

        # Поведение по умолчанию для any (если ignore_any=False)
        if input_str == "any":
            return True

        try:
            input_ip = ipaddress.ip_address(input_str)
            input_net_32 = ipaddress.ip_network(str(input_ip) + '/32', strict=False)

            for cand in candidates:
                cand_net = self._cand_to_net(cand)

                # 2. Если включен mask_limit, проверяем длину префикса сети-кандидата
                if mask_limit is not None and cand_net is not None:
                    # Чем МЕНЬШЕ prefixlen, тем ШИРЕ сеть (/24 меньше чем /29).
                    # Если сеть кандидата шире установленного лимита — игнорируем candidate.
                    if cand_net.prefixlen < mask_limit:
                        continue

                # Режим строгого совпадения (только exact /32)
                if strict_mode:
                    if cand_net and cand_net == input_net_32:
                        return True
                else:
                    # Обычный режим вхождения IP в сеть/диапазон
                    try:
                        if isinstance(cand, tuple):
                            if len(cand) == 3 and cand[0] == 'netmask':
                                net = ipaddress.ip_network((cand[1], cand[2]), strict=False)
                                if input_ip in net:
                                    return True
                            elif len(cand) == 2:
                                start, end = cand
                                # Диапазон не имеет строгого CIDR, но если mask_limit задан,
                                # можно отсекать диапазоны шириной больше допустимого лимита:
                                if mask_limit is not None:
                                    range_size = int(end) - int(start) + 1
                                    max_size = 2 ** (32 - mask_limit)
                                    if range_size > max_size:
                                        continue
                                if start <= input_ip <= end:
                                    return True
                        elif cand.startswith("host "):
                            cand_ip = cand.split()[1]
                            if input_ip == ipaddress.ip_address(cand_ip):
                                return True
                        elif cand_net:
                            if input_ip in cand_net:
                                return True
                    except Exception:
                        continue
            return False
        except ValueError:
            return False

    def _extract_src_dst(self, parts):
        i = 4
        if parts[i] in ['ip', 'tcp', 'udp', 'icmp']:
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
            elif parts[idx] == "any" or parts[idx] == "any4":
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
        src_ip,
        dst_ip,
        strict_mode=False,
        ignore_src_any=False,
        ignore_dst_any=False,
        src_mask_limit=None,
        dst_mask_limit=None
    ):
        matches = set()
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
                    matches.add(line)
            except Exception:
                continue
        return matches
class FortiOSParser:
    def __init__(self, config_text):
        self.config_text = config_text
        self.objects = {}       # {name: [ip_network or (start_ip, end_ip)]}
        self.groups = defaultdict(list)  # {group_name: [members]}
        self.policies = []      # list of policies
        self._parse_objects()
        self._parse_groups()
        self._parse_policies()

    def _parse_objects(self):
        # Parse blocks in config firewall address
        address_blocks = re.findall(r'edit "([^"]+)"(.*?)\n\s*next', self.config_text, re.S)
        for name, body in address_blocks:
            nets = []
            # Subnet
            m_subnet = re.search(r'set subnet (\S+) (\S+)', body)
            if m_subnet:
                ip, mask = m_subnet.groups()
                try:
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                    nets.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
                except ValueError:
                    pass
            # Range
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
        # Parse blocks in config firewall addrgrp
        group_blocks = re.findall(r'edit "([^"]+)"(.*?)\n\s*next', self.config_text, re.S)
        for group_name, body in group_blocks:
            if "set member" in body:
                members = re.findall(r'"([^"]+)"', body)
                self.groups[group_name].extend(m for m in members if m != group_name)

    def _resolve_group(self, name):
        results = []
        visited = set()
        def _resolve(n):
            if n in visited:
                return
            visited.add(n)
            if n in self.objects:
                results.extend(self.objects[n])
            elif n in self.groups:
                for m in self.groups[n]:
                    _resolve(m)
        _resolve(name)
        return results

    def _parse_policies(self):
        # Parse blocks in config firewall policy
        policy_blocks = re.findall(r'edit \d+(.*?)\n\s*next', self.config_text, re.S)
        for body in policy_blocks:
            if re.search(r'set status disable', body):
                continue
            src_list = re.findall(r'set srcaddr (.+)', body)
            dst_list = re.findall(r'set dstaddr (.+)', body)
            service_list = re.findall(r'set service (.+)', body)

            if src_list:
                src_list = re.findall(r'"([^"]+)"', src_list[0])
            else:
                src_list = []
            if dst_list:
                dst_list = re.findall(r'"([^"]+)"', dst_list[0])
            else:
                dst_list = []
            if service_list:
                service_list = re.findall(r'"([^"]+)"', service_list[0])
            else:
                service_list = []

            self.policies.append({
                'srcaddr': src_list,
                'dstaddr': dst_list,
                'service': service_list
            })

    def _ip_in_object(self, ip_str, obj_name, strict_mode):
        try:
            input_ip = ipaddress.ip_address(ip_str)
            input_net = ipaddress.ip_network(f"{ip_str}/32", strict=False)
            is_network_input = False
        except ValueError:
            try:
                input_net = ipaddress.ip_network(ip_str, strict=False)
                input_ip = None  # Treat as network input
                is_network_input = True
            except ValueError:
                return False

        if obj_name == "any":
            return True

        def check_object(entry):
            """Check single object entry (network or range)"""
            if isinstance(entry, tuple):
                # Range handling
                start_ip, end_ip = entry
                if input_ip is not None:  # Input is IP
                    if strict_mode:
                        return start_ip == input_ip and end_ip == input_ip
                    else:
                        return start_ip <= input_ip <= end_ip
                return False  # Ranges don't match networks
            else:
                # Network handling
                if input_ip is not None:  # Input is IP
                    if strict_mode:
                        # Strict: IP must exactly match network (only for /32)
                        return str(entry) == f"{input_ip}/32"
                    else:
                        # Non-strict: IP inside network
                        return input_ip in entry
                else:  # Input is network
                    # Networks ALWAYS match strictly (exact network match)
                    return entry == input_net

        if obj_name in self.objects:
            for entry in self.objects[obj_name]:
                if check_object(entry):
                    return True
        elif obj_name in self.groups:
            for entry in self._resolve_group(obj_name):
                if check_object(entry):
                    return True
        return False

    def search(self, src_ip, dst_ip, strict_mode=False):
        matches = set()
        for policy in self.policies:
            for src in policy['srcaddr']:
                for dst in policy['dstaddr']:
                    src_ok = True if src_ip == "any" else self._ip_in_object(src_ip, src, strict_mode)
                    dst_ok = True if dst_ip == "any" else self._ip_in_object(dst_ip, dst, strict_mode)
                    if src_ok and dst_ok:
                        matches.add(f"{src} > {dst} : {', '.join(policy['service'])}")
        return tuple(matches)  # ✅ Возвращаем tuple() вместо set()

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, strict_mode=False, base_dir=base_dir, encoding="utf-8"):
        """
        Searches for a file in base_dir, parses it, and returns ACL matches.
        """
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, filename)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                    except Exception as e:
                        raise Exception(f"Error reading {full_path}: {e}")

                    parser = cls(config_text)
                    return parser.search(src_ip, dst_ip, strict_mode)

        # print(f"⚠️ File {filename} not found in directory {base_dir}")
        return tuple()  # ✅ Возвращаем tuple() вместо list()
class HuaweiParser3:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.acls = {}                    # Старый стиль (коммутаторы)
        self.acl_headers = {}
        self.firewall_rules = []          # Новый стиль (Firewall)
        self.address_sets = {}
        self.parse()

    def _parse_address_set(self, start_idx):
        """Исправленный надёжный парсинг address-set для формата Huawei"""
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
                        # Правильная логика для твоего формата: address X IP mask MASK
                        if mask_idx >= 3 and mask_idx + 1 < len(parts):
                            ip_part = parts[mask_idx - 1]      # IP перед "mask"
                            mask_str = parts[mask_idx + 1]     # значение маски после "mask"
                            net = ipaddress.IPv4Network(f"{ip_part}/{mask_str}", strict=False)
                            specs.append(str(net))
                            # print(f"[DEBUG ADDRESS] SUCCESS: {line} → {net}")
                            i += 1
                            continue

                    # Fallback
                    for p in parts:
                        if p.count('.') == 3:
                            try:
                                ipaddress.IPv4Address(p)
                                specs.append(f"{p}/32")
                                # print(f"[DEBUG ADDRESS] fallback: {p}/32")
                            except:
                                pass
                except:
                    pass

            i += 1

        if name:
            self.address_sets[name] = specs
            # print(f"[DEBUG ADDRESS-SET] Parsed '{name}' → {specs}")

        return i

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, base_dir=base_dir, encoding="utf-8", strict_mode=False):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                    except Exception as e:
                        # print(f"[!] Ошибка при чтении {full_path}: {e}")
                        return ()
                    parser = cls(config_text)
                    return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
        # print(f"⚠️ Файл {filename} не найден в директории {base_dir}")
        return ()

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
                except:
                    pass
                    # print(f"[!] Ошибка разбора ACL: {line} — {e}")
                i += 1
                continue

            i += 1

    def _parse_firewall_rule(self, start_idx, rule_name):
        rule = {
            'name': rule_name.strip('"'),
            'source_addresses': [],      # будет содержать либо IP/сеть, либо имя address-set
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
                    rule['source_addresses'].append(parts[2])   # имя address-set
                elif len(parts) >= 2:
                    if len(parts) >= 4 and parts[2] == "mask":
                        rule['source_addresses'].append(self._mask_to_cidr(parts[1], parts[3]))
                    else:
                        rule['source_addresses'].append(f"{parts[1]}/32")

            elif line.startswith("destination-address "):
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "address-set":
                    rule['destination_addresses'].append(parts[2])   # имя address-set
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
        # ... (оставляем как было) ...
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

    # ====================== ОБЩАЯ ЛОГИКА ======================
    def _parse_search(self, text):
        if text == "any":
            return "any"
        if "/" in text:
            try:
                return str(ipaddress.ip_network(text, strict=True))
            except ValueError:
                return None
        if " " in text:
            parts = text.split()
            return self._wildcard_to_network_or_range(parts[0], parts[1])
        return f"{text}/32"
    def _get_min_max(self, spec):
        if spec == "any":
            return 0, 0xFFFFFFFF

        if spec is None or not isinstance(spec, str):
            return -1, -2

        # Если это имя address-set (не начинается с цифры и не "any")
        if not spec[0].isdigit():
            return -1, -2   # пока не поддерживаем диапазон address-set

        try:
            if "/" in spec:
                net = ipaddress.ip_network(spec, strict=False)
                return int(net.network_address), int(net.broadcast_address)
            else:
                ip = ipaddress.ip_address(spec)
                return int(ip), int(ip)
        except ValueError:
            return -1, -2

    def _spec_intersects(self, spec_search, spec_rule, strict_mode):
        """
        spec_search - запрос пользователя (IP, сеть, any)
        spec_rule   - значение из правила (IP/сеть или имя address-set)
        """
        if spec_search is None or spec_rule is None:
            return False

        # any логика
        if spec_search == "any" and spec_rule == "any":
            return True
        if spec_search == "any" or spec_rule == "any":
            return not strict_mode

        # === 1. В ПРАВИЛЕ лежит address-set ===
        if spec_rule in self.address_sets:
            # print(f"[DEBUG INTERSECT] address-set '{spec_rule}' contains: {self.address_sets[spec_rule]}")
            for addr in self.address_sets[spec_rule]:
                if self._ip_matches_spec(spec_search, addr, strict_mode):
                    # print(f"[DEBUG INTERSECT] MATCH! {spec_search} inside address-set '{spec_rule}'")
                    return True
            # print(f"[DEBUG INTERSECT] No match for {spec_search} in address-set '{spec_rule}'")
            return False

        # === 2. Пользователь ищет по имени address-set ===
        if spec_search in self.address_sets:
            return spec_search == spec_rule

        # === 3. Обычное сравнение IP/сеть <-> IP/сеть ===
        return self._ip_matches_spec(spec_search, spec_rule, strict_mode)
    def _ip_matches_spec(self, search, rule_spec, strict_mode):
        min1, max1 = self._get_min_max(search)
        min2, max2 = self._get_min_max(rule_spec)

        if min1 == -1 or min2 == -1:
            return False

        is_single_search = (min1 == max1)
        overlap = max1 >= min2 and max2 >= min1

        if strict_mode:
            return min1 == min2 and max1 == max2
        else:
            if is_single_search:
                return overlap
            else:
                return min1 == min2 and max1 == max2

    def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
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
                    if (self._spec_intersects(src_spec_search, src_spec, strict_mode) and
                        self._spec_intersects(dst_spec_search, dst_spec, strict_mode)):
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
            # print(
            #     f"[DEBUG RULE] '{rule['name']}' | src={rule['source_addresses']} | dst={rule['destination_addresses']} | services={rule['services']}")
            for s_addr, d_addr in product(src_addrs, dst_addrs):
                if s_addr == "any" and d_addr == "any":
                    continue

                if (self._spec_intersects(src_spec_search, s_addr, strict_mode) and
                        self._spec_intersects(dst_spec_search, d_addr, strict_mode)):
                    line = f"{rule['name']} {s_addr} {d_addr} {services_str} {action}"
                    results.append(line)

        return tuple(results)# class HuaweiParser2:
#     def __init__(self, config_text):
#         self.config_lines = config_text.splitlines()
#         self.acls = {}
#         self.acl_headers = {}
#         self.parse()
#
#     @classmethod
#     def from_local_file(cls, filename, src_ip, dst_ip, base_dir=base_dir, encoding="utf-8",
#                         strict_mode=False):
#         for root, _, files in os.walk(base_dir):
#             for file in files:
#                 if file == filename:
#                     full_path = os.path.join(root, file)
#                     try:
#                         with open(full_path, "r", encoding=encoding, errors="ignore") as f:
#                             config_text = f.read()
#                     except Exception as e:
#                         print(f"[!] Ошибка при чтении {full_path}: {e}")
#                         return ()
#                     parser = cls(config_text)
#                     return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
#         print(f"⚠️ Файл {filename} не найден в директории {base_dir}")
#         return ()
#
#     def parse(self):
#         current_acl = None
#         current_header = None
#         for raw in self.config_lines:
#             line = raw.strip()
#             if not line:
#                 continue
#
#             if line.startswith("acl number"):
#                 parts = line.split()
#                 if len(parts) >= 3:
#                     current_acl = parts[2]
#                     current_header = "acl number " + current_acl
#                     self.acls.setdefault(current_acl, {})
#                     self.acl_headers[current_acl] = current_header
#                 continue
#             if line.startswith("acl name"):
#                 parts = line.split()
#                 if len(parts) >= 3:
#                     name = parts[2]
#                     number = parts[3] if len(parts) > 3 else ""
#                     current_acl = number if number else name
#                     current_header = line
#                     self.acls.setdefault(current_acl, {})
#                     self.acl_headers[current_acl] = current_header
#                 continue
#
#             if current_acl and line.startswith("rule"):
#                 if "description" in line.lower():
#                     continue
#                 try:
#                     pairs = self._parse_rule(line)
#                     if not pairs:
#                         continue
#                     cleaned = []
#                     for src, dst in pairs:
#                         if src == "any" and dst == "any":
#                             continue
#                         cleaned.append((src, dst))
#                     if cleaned:
#                         self.acls[current_acl][line] = cleaned
#                 except Exception as e:
#                     print(f"[!] Ошибка разбора строки '{line}': {e}")
#
#     def _parse_rule(self, line):
#         parts = line.split()
#         src_spec = "any"
#         dst_spec = "any"
#
#         if "source" in parts:
#             i = parts.index("source")
#             src_spec = self._parse_addr_with_wildcard(parts, i + 1)
#
#         if "destination" in parts:
#             i = parts.index("destination")
#             dst_spec = self._parse_addr_with_wildcard(parts, i + 1)
#
#         return [(src_spec, dst_spec)]
#
#     def _parse_addr_with_wildcard(self, parts, idx):
#         if idx >= len(parts):
#             return "any"
#
#         ip = parts[idx]
#
#         wc = None
#         if idx + 1 < len(parts):
#             nxt = parts[idx + 1]
#             if self._looks_like_wildcard(nxt):
#                 wc = nxt
#
#         if wc is None:
#             return f"{ip}/32"
#
#         spec = self._wildcard_to_network_or_range(ip, wc)
#         return spec
#
#     def _looks_like_wildcard(self, s: str) -> bool:
#         if s.count(".") == 3:
#             try:
#                 ipaddress.IPv4Address(s)
#                 return True
#             except ValueError:
#                 return False
#         return s.isdigit()
#
#     def _wildcard_to_network_or_range(self, ip_str: str, wildcard_str: str):
#         ip = HPEParser.safe_ip_address(ip_str)
#         if ip is None:
#             return None
#         try:
#             if wildcard_str.count(".") == 3:
#                 w = int(ipaddress.IPv4Address(wildcard_str))
#             else:
#                 w = int(wildcard_str)
#                 if not (0 <= w <= 0xFFFFFFFF):
#                     raise ValueError("wildcard out of range")
#         except Exception:
#             return f"{ip_str}/32"
#
#         if w == 0:
#             return f"{ip_str}/32"
#
#         if (w & (w + 1)) == 0:
#             k = bin(w).count("1")
#             prefix = 32 - k
#             try:
#                 net = ipaddress.IPv4Network((ip_str, prefix), strict=True)
#                 return str(net)
#             except ValueError:
#                 ip_int = int(ipaddress.IPv4Address(ip_str))
#                 start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
#                 end = (ip_int | w) & 0xFFFFFFFF
#                 return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))
#
#         ip_int = int(ipaddress.IPv4Address(ip_str))
#         start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
#         end = (ip_int | w) & 0xFFFFFFFF
#         return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))
#
#     def _parse_search(self, text):
#         if text == "any":
#             return "any"
#         if "/" in text:
#             try:
#                 net = ipaddress.ip_network(text, strict=True)
#                 return str(net)
#             except ValueError:
#                 return None
#         if " " in text:
#             parts = text.split()
#             ip = parts[0]
#             wc = parts[1]
#             return self._wildcard_to_network_or_range(ip, wc)
#         return f"{text}/32"
#
#     def _get_min_max(self, spec):
#         if spec == "any":
#             return 0, 0xFFFFFFFF
#         if spec is None:
#             return None, None
#         if isinstance(spec, tuple) and spec[0] == "range":
#             _, start, end = spec
#             return int(start), int(end)
#         if "/" in spec:
#             net = ipaddress.ip_network(spec, strict=False)
#             return int(net.network_address), int(net.broadcast_address)
#         ip = ipaddress.ip_address(spec)
#         return int(ip), int(ip)
#
#     def _spec_intersects(self, spec1, spec2, strict_mode):
#         if spec1 is None or spec2 is None:
#             return False
#
#         if spec1 == "any" or spec2 == "any":
#             if spec1 == spec2 == "any":
#                 return True
#             return not strict_mode
#
#         min1, max1 = self._get_min_max(spec1)
#         min2, max2 = self._get_min_max(spec2)
#
#         is_network1 = max1 > min1
#         is_network2 = max2 > min2
#
#         overlap = max1 >= min2 and max2 >= min1
#
#         if is_network1:
#             return min1 == min2 and max1 == max2
#
#         if strict_mode:
#             return min1 == min2 and max1 == max2
#
#         return min2 <= min1 <= max2
#
#     def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
#         src_spec_search = self._parse_search(src_ip)
#         dst_spec_search = self._parse_search(dst_ip)
#
#         if src_spec_search is None or dst_spec_search is None:
#             return []
#
#         results = []
#         for acl_key, rules in self.acls.items():
#             matched_rules = []
#             for rule_line, pairs in rules.items():
#                 for src_spec, dst_spec in pairs:
#                     if self._spec_intersects(src_spec_search, src_spec, strict_mode) and self._spec_intersects(
#                             dst_spec_search, dst_spec, strict_mode):
#                         matched_rules.append(rule_line)
#                         break
#             if matched_rules:
#                 header = self.acl_headers.get(acl_key, f"acl {acl_key}")
#                 results.append(header)
#                 for r in matched_rules:
#                     results.append(f"  {r}")
#         return tuple(results)
class HuaweiParser:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.acls = {}
        self.acl_headers = {}
        self.parse()

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, base_dir=base_dir, encoding="utf-8",
                        strict_mode=False):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                    except Exception as e:
                        # print(f"[!] Ошибка при чтении {full_path}: {e}")
                        return ()
                    parser = cls(config_text)
                    return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
        # print(f"⚠️ Файл {filename} не найден в директории {base_dir}")
        return ()

    def parse(self):
        current_acl = None
        current_header = None
        for raw in self.config_lines:
            line = raw.strip()
            if not line:
                continue

            if line.startswith("acl number"):
                parts = line.split()
                if len(parts) >= 3:
                    current_acl = parts[2]
                    current_header = "acl number " + current_acl
                    self.acls.setdefault(current_acl, {})
                    self.acl_headers[current_acl] = current_header
                continue
            if line.startswith("acl name"):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[2]
                    number = parts[3] if len(parts) > 3 else ""
                    current_acl = number if number else name
                    current_header = line
                    self.acls.setdefault(current_acl, {})
                    self.acl_headers[current_acl] = current_header
                continue

            if current_acl and line.startswith("rule"):
                if "description" in line.lower():
                    continue
                try:
                    pairs = self._parse_rule(line)
                    if not pairs:
                        continue
                    cleaned = []
                    for src, dst in pairs:
                        if src == "any" and dst == "any":
                            continue
                        cleaned.append((src, dst))
                    if cleaned:
                        self.acls[current_acl][line] = cleaned
                except:
                    pass
                    # print(f"[!] Ошибка разбора строки '{line}': {e}")

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
        # print(f"[PARSE RULE] rule_line={line!r} → src_spec={src_spec!r}, dst_spec={dst_spec!r}")
        return [(src_spec, dst_spec)]

    def _parse_addr_with_wildcard(self, parts, idx):
        if idx >= len(parts):
            return "any"

        ip = parts[idx]

        wc = None
        if idx + 1 < len(parts):
            nxt = parts[idx + 1]
            if self._looks_like_wildcard(nxt):
                wc = nxt

        if wc is None:
            return f"{ip}/32"

        spec = self._wildcard_to_network_or_range(ip, wc)
        return spec

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
                    raise ValueError("wildcard out of range")
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
                ip_int = int(ipaddress.IPv4Address(ip_str))
                start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
                end = (ip_int | w) & 0xFFFFFFFF
                return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))

        ip_int = int(ipaddress.IPv4Address(ip_str))
        start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
        end = (ip_int | w) & 0xFFFFFFFF
        return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))

    def _parse_search(self, text):
        if text == "any":
            return "any"
        if "/" in text:
            try:
                net = ipaddress.ip_network(text, strict=True)
                return str(net)
            except ValueError:
                return None
        if " " in text:
            parts = text.split()
            ip = parts[0]
            wc = parts[1]
            return self._wildcard_to_network_or_range(ip, wc)
        return f"{text}/32"

    # def _get_min_max(self, spec):
    #     if spec == "any":
    #         return 0, 0xFFFFFFFF
    #     if spec is None:
    #         return None, None
    #     if isinstance(spec, tuple) and spec[0] == "range":
    #         _, start, end = spec
    #         return int(start), int(end)
    #     if "/" in spec:
    #         net = ipaddress.ip_network(spec, strict=False)
    #         return int(net.network_address), int(net.broadcast_address)
    #     ip = ipaddress.ip_address(spec)
    #     return int(ip), int(ip)
    def _get_min_max(self, spec):
        if spec == "any":
            return 0, 0xFFFFFFFF

        if spec is None:
            return None, None

        if isinstance(spec, tuple) and spec[0] == "range":
            _, start, end = spec
            return int(start), int(end)

        # Если строка не начинается с цифры — это явно не IP → считаем невалидной
        if not spec or not spec[0].isdigit():
            return -1, -2

        try:
            if "/" in spec:
                net = ipaddress.ip_network(spec, strict=False)
                return int(net.network_address), int(net.broadcast_address)
            else:
                ip = ipaddress.ip_address(spec)
                return int(ip), int(ip)
        except ValueError:
            return -1, -2

    # def _spec_intersects(self, spec1, spec2, strict_mode):
    #     if spec1 is None or spec2 is None:
    #         return False
    #
    #     # 1. any → any — всегда совпадает (независимо от strict_mode)
    #     if spec1 == "any" and spec2 == "any":
    #         return True
    #
    #     # 2. any → конкретное или конкретное → any
    #     if spec1 == "any" or spec2 == "any":
    #         return not strict_mode
    #
    #     # 3. Оба конкретные значения
    #     min1, max1 = self._get_min_max(spec1)
    #     min2, max2 = self._get_min_max(spec2)
    #
    #     is_single_search = (min1 == max1)   # поиск — одиночный IP
    #     overlap = max1 >= min2 and max2 >= min1
    #
    #     if strict_mode:
    #         # strict_mode=True → только ТОЧНОЕ совпадение
    #         return min1 == min2 and max1 == max2
    #     else:
    #         # strict_mode=False
    #         if is_single_search:
    #             # поиск — одиночный IP → разрешаем вхождение в любую сеть правила
    #             return overlap
    #         else:
    #             # поиск — сеть → только точное совпадение сети
    #             return min1 == min2 and max1 == max2
    # def _spec_intersects(self, spec1, spec2, strict_mode):
    #     if spec1 is None or spec2 is None:
    #         return False
    #
    #     print(f"[DEBUG ANY] spec1={spec1!r}, spec2={spec2!r}, strict_mode={strict_mode}")
    #
    #     if "any" in (spec1, spec2) and "any" in (spec2, spec1):
    #         print("[DEBUG] any-any FORCED MATCH")
    #         return True
    #
    #     # 3. Два конкретных значения → обычная логика
    #     min1, max1 = self._get_min_max(spec1)
    #     min2, max2 = self._get_min_max(spec2)
    #
    #     is_network1 = max1 > min1
    #     is_network2 = max2 > min2
    #
    #     overlap = max1 >= min2 and max2 >= min1
    #
    #     if is_network1:
    #         return min1 == min2 and max1 == max2
    #
    #     if strict_mode:
    #         return min1 == min2 and max1 == max2
    #
    #     return min2 <= min1 <= max2

    # def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
    #     src_spec_search = self._parse_search(src_ip)
    #     dst_spec_search = self._parse_search(dst_ip)
    #
    #     if src_spec_search is None or dst_spec_search is None:
    #         return []
    #
    #     results = []
    #     for acl_key, rules in self.acls.items():
    #         matched_rules = []
    #         for rule_line, pairs in rules.items():
    #             for src_spec, dst_spec in pairs:
    #                 if self._spec_intersects(src_spec_search, src_spec, strict_mode) and self._spec_intersects(
    #                         dst_spec_search, dst_spec, strict_mode):
    #                     matched_rules.append(rule_line)
    #                     break
    #         if matched_rules:
    #             header = self.acl_headers.get(acl_key, f"acl {acl_key}")
    #             results.append(header)
    #             for r in matched_rules:
    #                 results.append(f"  {r}")
    #     for src_spec, dst_spec in pairs:
    #         if (self._spec_intersects(src_spec_search, src_spec, strict_mode) and
    #                 self._spec_intersects(dst_spec_search, dst_spec, strict_mode)):
    #             print(f"[MATCH] ACL={acl_key} | rule={rule_line} | "
    #                   f"src_rule={src_spec} | dst_rule={dst_spec}")
    #
    #             matched_rules.append(rule_line)
    #             break
    #     return tuple(results)
    def _spec_intersects(self, spec1, spec2, strict_mode):
        """
        spec1 — искомое (от пользователя: IP, сеть, any)
        spec2 — из правила конфига
        """
        if spec1 is None or spec2 is None:
            return False

        if spec1 == "any":
            return True

        # rule = any
        if spec2 == "any":
            return not strict_mode

        # if "any" in (spec1, spec2) and "any" in (spec2, spec1):
        #     return True

        # # any → any — всегда True
        # if spec1 == "any" and spec2 == "any":
        #      # strict_mode=False
        #      # print('условие 1')
        #      return True
        #
        # # any → конкретное или наоборот
        # if spec1 == "any" or spec2 == "any":
        #     # print('условие 2')
        #     return not strict_mode

        # Получаем диапазоны
        min1, max1 = self._get_min_max(spec1)
        min2, max2 = self._get_min_max(spec2)

        # Типы
        is_single_search = (min1 == max1)  # поиск — одиночный IP
        is_single_rule   = (min2 == max2)  # правило — одиночный IP
        is_network_rule  = (min2 < max2)   # правило — сеть

        overlap = max1 >= min2 and max2 >= min1

        if strict_mode:
            # strict=true → ТОЛЬКО точное совпадение
            return min1 == min2 and max1 == max2
        else:
            # strict=false
            if is_single_search:
                # ищем одиночный IP → разрешаем вхождение в любую сеть/одиночный IP правила
                return overlap
            else:
                # ищем сеть → только точное совпадение сети
                return min1 == min2 and max1 == max2
    def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
        src_spec_search = self._parse_search(src_ip)
        dst_spec_search = self._parse_search(dst_ip)

        if src_spec_search is None or dst_spec_search is None:
            return ()

        results = []
        for acl_key, rules in self.acls.items():
            matched_rules = []
            for rule_line, pairs in rules.items():
                for src_spec, dst_spec in pairs:
                    intersects_src = self._spec_intersects(src_spec_search, src_spec, strict_mode)
                    intersects_dst = self._spec_intersects(dst_spec_search, dst_spec, strict_mode)

                    if intersects_src and intersects_dst:
                        # Отладка здесь — внутри цикла, где все переменные доступны
                        # print(f"[MATCH] ACL={acl_key} | rule={rule_line} | "
                        #       f"src_search={src_spec_search!r} → src_rule={src_spec!r} | "
                        #       f"dst_search={dst_spec_search!r} → dst_rule={dst_spec!r}")

                        matched_rules.append(rule_line)
                        break  # нашли совпадение в этом rule — выходим из цикла пар

            if matched_rules:
                header = self.acl_headers.get(acl_key, f"acl {acl_key}")
                results.append(header)
                for r in matched_rules:
                    results.append(f"  {r}")

        # print(f"[SUMMARY] Найдено {len(results)} строк в {len(self.acls)} ACL")
        return tuple(results)
class CiscoNexusParser:
    def __init__(self, lines):
        self.lines = lines
        self.object_groups = defaultdict(list)  # name -> [networks]
        self.acl_lines = []  # list of (acl_name, line)
        self.parse()

    def parse(self):
        current_group = None
        current_acl = None
        in_group = False
        in_acl = False
        current_values = []

        for line in self.lines:
            original_line = line  # Save for potential use
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
                if parts and (parts[0] in ["permit", "deny"] or (
                        parts[0].isdigit() and len(parts) > 1 and parts[1] in ["permit", "deny"])):
                    self.acl_lines.append((current_acl, original_line))  # Use original_line to preserve indentation
                elif line.startswith("statistics per-entry"):  # Ignore statistics
                    continue
                elif line == "exit" or line == "}":
                    in_acl = False
                    current_acl = None
                continue

        # Close any open sections at the end
        if in_group and current_group:
            self.object_groups[current_group] = current_values
        # No need for in_acl close, as lines are added

    @classmethod
    def from_local_file(cls, filename, src_ip=None, dst_ip=None, strict_mode=False, base_dir=base_dir,
                        encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            lines = f.readlines()  # Use readlines to preserve original lines with indentation
                    except Exception as e:
                        # print(f"[!] Ошибка чтения {full_path}: {e}")
                        continue
                    parser = cls(lines)
                    return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
        # print(f"⚠️ Файл {filename} не найден в директории {base_dir}")
        return []

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

    def _matches(self, input_str, candidates, strict_mode):
        if not input_str or input_str == "any":
            return True
        try:
            if '/' in input_str:
                input_net = ipaddress.ip_network(input_str, strict=False)
                for cand in candidates:
                    cand_net = self._cand_to_net(cand)
                    if cand_net:
                        if strict_mode:
                            if input_net == cand_net:
                                return True
                        else:
                            if input_net.overlaps(cand_net):
                                return True
                return False
            else:
                # IP
                input_ip = ipaddress.ip_address(input_str)
                input_net_32 = ipaddress.ip_network(f"{input_ip}/32", strict=False)
                for cand in candidates:
                    cand_net = self._cand_to_net(cand)
                    if cand_net:
                        if strict_mode:
                            if cand_net == input_net_32:
                                return True
                        else:
                            if input_ip in cand_net:
                                return True
                return False
        except ValueError:
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
        return token in ['eq', 'gt', 'lt', 'neq', 'range']

    def _extract_src_dst(self, parts):
        idx = 0
        # Skip sequence number
        if parts and parts[0].isdigit():
            idx += 1
        # Skip action (permit/deny)
        if idx < len(parts) and parts[idx] in ['permit', 'deny']:
            idx += 1
        # Skip protocol (ip, tcp, udp, icmp, etc.)
        if idx < len(parts) and parts[idx] not in ['any', 'host', 'object-group',
                                                   'addrgroup'] and not self._is_ip_or_net(parts[idx]):
            idx += 1

        def parse_entry(idx):
            if idx >= len(parts):
                return None, idx
            val = parts[idx]
            if val in ["object-group", "addrgroup"]:
                if idx + 1 < len(parts):
                    return parts[idx + 1], idx + 2
                return None, idx + 1
            elif val == "host":
                if idx + 1 < len(parts):
                    return f"{parts[idx + 1]}/32", idx + 2
                return None, idx + 1
            elif val == "any":
                return "any", idx + 1
            elif '/' in val:  # CIDR
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    return str(net), idx + 1
                except ValueError:
                    return None, idx + 1
            elif self._is_ip_or_net(val):
                # Check for subnet mask or wildcard
                if idx + 1 < len(parts) and self._is_ip_or_net(parts[idx + 1]):
                    try:
                        net = ipaddress.ip_network((val, parts[idx + 1]), strict=False)
                        return str(net), idx + 2
                    except ValueError:
                        return f"{val}/32", idx + 1
                else:
                    return f"{val}/32", idx + 1
            return None, idx + 1

        # Parse src
        src_entry, idx = parse_entry(idx)

        # Skip src ports (eq X, range X Y, etc.), including symbolic ports
        while idx < len(parts) and self._is_port_operator(parts[idx]):
            op = parts[idx]
            idx += 1
            if op == 'range':
                # Skip two ports (numeric or symbolic)
                if idx < len(parts):
                    idx += 1  # first port
                if idx < len(parts):
                    idx += 1  # second port
            else:
                # eq/gt/lt/neq: skip one port
                if idx < len(parts):
                    idx += 1

        # Parse dst
        dst_entry, idx = parse_entry(idx)

        # Skip dst ports similarly
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
        if not entry or entry == "any":
            return ["any"]
        if "/" in entry or self._is_ip_or_net(entry):
            return [entry]
        if entry in self.object_groups:
            return self.object_groups[entry]
        return []

    def find_acl_matches(self, src_ip=None, dst_ip=None, strict_mode=False):
        matches = []
        current_acl = None
        for acl_name, line in self.acl_lines:
            parts = line.strip().split()  # Strip for parsing
            if len(parts) < 4:
                continue
            try:
                src_entry, dst_entry = self._extract_src_dst(parts)
                src_candidates = self._resolve_entry(src_entry)
                dst_candidates = self._resolve_entry(dst_entry)

                if src_candidates == ["any"] and dst_candidates == ["any"]:
                    continue

                src_ok = src_ip is None or self._matches(src_ip, src_candidates, strict_mode)
                dst_ok = dst_ip is None or self._matches(dst_ip, dst_candidates, strict_mode)

                if src_ok and dst_ok:
                    if acl_name != current_acl:
                        if current_acl is not None:  # Add empty line between ACLs
                            matches.append("")
                        matches.append(f"ip access-list {acl_name}")
                        current_acl = acl_name
                    matches.append(line.rstrip())  # Remove trailing \n
            except:
                # print(f"[!] Ошибка: {e} в строке: {line}")
                continue
        return tuple(matches)
class JuniperACLParser:
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
            return ipaddress.ip_network(cand, strict=False)
        except ValueError:
            return None

    def _matches(self, input_str, ip_list, strict_mode):
        if input_str == "any":
            return True

        try:
            if '/' in input_str:  # network
                input_net = ipaddress.ip_network(input_str, strict=False)
                for net in ip_list:
                    if net == "any":
                        if strict_mode:
                            continue
                        else:
                            return True
                    cand_net = self._cand_to_net(net)
                    if cand_net and cand_net == input_net:
                        return True
                return False
            else:  # IP
                ip_obj = ipaddress.ip_address(input_str)
                input_net_32 = ipaddress.ip_network(str(ip_obj) + '/32', strict=False)
                for net in ip_list:
                    if net == "any":
                        if strict_mode:
                            continue
                        else:
                            return True
                    if strict_mode:
                        cand_net = self._cand_to_net(net)
                        if cand_net and cand_net == input_net_32:
                            return True
                    else:
                        try:
                            if ip_obj in ipaddress.ip_network(net, strict=False):
                                return True
                        except ValueError:
                            continue
                return False
        except ValueError:
            return False

    def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
        if dst_ip not in (None, "any") and strict_mode:
            return tuple()  # No strict match for dst in Juniper ACLs
        results = []
        for filt, terms in self.filters.items():
            if filt == "None":  # Игнорируем фильтр с именем None
                continue
            matched = []
            for term, rules in terms.items():
                for rule in rules:
                    if not rule["action"]:
                        continue
                    # Пропускаем правила с src=any и dst=any
                    if rule["src"] == ["any"] and rule["dst"] == ["any"]:
                        continue
                    src_ok = self._matches(src_ip, rule["src"], strict_mode)
                    dst_ok = self._matches(dst_ip, rule["dst"], strict_mode)
                    if src_ok and dst_ok:
                        src = ", ".join(rule["src"]) if rule["src"] != ["any"] else "any"
                        dst = ", ".join(rule["dst"]) if rule["dst"] != ["any"] else "any"
                        matched.append(f"term {term} {rule['action']} ip source {src} destination {dst}")
            if matched:
                results.append(f"filter {filt}:")
                results.extend("  " + m for m in matched)
        return tuple(results)

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, strict_mode=False, base_dir=base_dir,
                        encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                        config_text = f.read()
                    parser = cls(config_text)
                    return tuple(parser.find_acl_matches(src_ip, dst_ip, strict_mode))
        # print(f"⚠️ Файл {filename} не найден в директории {base_dir}")
        return tuple()
class EltexACLParser:
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
                if mask:
                    net = str(ipaddress.ip_network((ip, mask), strict=False))
                else:
                    net = str(ipaddress.ip_network(f"{ip}/32", strict=False))
                self.acls[current_acl].append({
                    "action": action,
                    "source": net,
                    "service": service or "any",
                    "raw": line
                })

    def _match(self, ip, network, strict):
        try:
            if strict:
                return ipaddress.ip_network(ip, strict=False) == ipaddress.ip_network(network, strict=False)
            else:
                return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
        except ValueError:
            return False

    def find_matches(self, src_ip, dst_ip=None, strict_mode=False):
        if dst_ip not in (None, "any") and strict_mode:
            return set()  # No strict match for dst in Eltex ACLs

        matches = []
        for acl, rules in self.acls.items():
            matched_rules = []
            for rule in rules:
                if src_ip == "any" or self._match(src_ip, rule["source"], strict_mode):
                    matched_rules.append(f" {rule['raw']}")  # Add space before rule
            if matched_rules:  # Only include ACL if it has matching rules
                matches.append(f"management access-list {acl}\n" + "\n".join(matched_rules))
        return set(matches)

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip=None,
                        strict_mode=False, base_dir=base_dir, encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    with open(os.path.join(root, file), "r", encoding=encoding, errors="ignore") as f:
                        parser = cls(f.read())
                        return parser.find_matches(src_ip, dst_ip, strict_mode)
        return set()
# class EltexESRParse2:
#     def __init__(self, config_text):
#         self.config_lines = [line.rstrip() for line in config_text.splitlines()]
#         self.zone_pairs = defaultdict(list)          # zone_pair → list[list[str]] — блоки правил
#         self.network_groups = defaultdict(list)      # имя группы → [префиксы]
#         self.service_groups = defaultdict(list)      # имя группы → [порты/диапазоны]
#         self.parse()
#
#     def parse(self):
#         i = 0
#         n = len(self.config_lines)
#         current_zone = None
#         current_rule_block = None
#
#         while i < n:
#             line = self.config_lines[i]
#             stripped = line.strip()
#
#             # Новый zone-pair
#             m = re.match(r'^security\s+zone-pair\s+(\S+)\s+(\S+)', stripped)
#             if m:
#                 if current_rule_block:
#                     self.zone_pairs[current_zone].append(current_rule_block)
#                 current_zone = f"{m.group(1)} {m.group(2)}"
#                 current_rule_block = None
#                 i += 1
#                 continue
#
#             # Новый rule внутри текущего zone-pair
#             if current_zone and re.match(r'^\s*rule\s+\d+', stripped):
#                 if current_rule_block:
#                     self.zone_pairs[current_zone].append(current_rule_block)
#                 current_rule_block = [line]
#                 i += 1
#                 continue
#
#             # Продолжаем текущий rule или пропускаем
#             if current_zone and current_rule_block is not None:
#                 # Если строка выглядит как начало нового объекта — завершаем блок
#                 if stripped.startswith(('object-group ', 'security zone-pair ', 'nat ', 'ip ', 'clock ', 'ntp ', 'lldp ', 'hostname ', '#!')):
#                     self.zone_pairs[current_zone].append(current_rule_block)
#                     current_rule_block = None
#                 else:
#                     current_rule_block.append(line)
#             elif stripped.startswith("object-group network "):
#                 # Парсим network group
#                 parts = stripped.split(maxsplit=2)
#                 if len(parts) >= 3:
#                     group_name = parts[2]
#                     i += 1
#                     while i < n:
#                         l = self.config_lines[i].strip()
#                         if l.startswith("ip prefix "):
#                             self.network_groups[group_name].append(l.split("ip prefix ", 1)[1].strip())
#                         elif l.startswith(("exit", "!", "object-group", "security zone-pair")):
#                             break
#                         i += 1
#                     continue
#             elif stripped.startswith("object-group service "):
#                 # Парсим service group (порты)
#                 parts = stripped.split(maxsplit=2)
#                 if len(parts) >= 3:
#                     group_name = parts[2]
#                     i += 1
#                     while i < n:
#                         l = self.config_lines[i].strip()
#                         if l.startswith("port-range "):
#                             self.service_groups[group_name].append(l.split("port-range ", 1)[1].strip())
#                         elif l.startswith(("exit", "!", "object-group", "security zone-pair", "description")):
#                             if l.startswith("description"):
#                                 i += 1
#                                 continue
#                             break
#                         i += 1
#                     continue
#
#             i += 1
#
#         # Сохраняем последний блок, если остался открытым
#         if current_rule_block and current_zone:
#             self.zone_pairs[current_zone].append(current_rule_block)
#     @classmethod
#     def from_local_file(cls, filename, src_ip, dst_ip=None,
#                         strict_mode=False, base_dir=base_dir, encoding="utf-8"):
#         for root, _, files in os.walk(base_dir):
#             for file in files:
#                 if file == filename:
#                     with open(os.path.join(root, file), "r", encoding=encoding, errors="ignore") as f:
#                         parser = cls(f.read())
#                         return parser.find_matches(src_ip, dst_ip, strict_mode)
#         return tuple()
#
#     # Остальные методы (_expand_network_group, _ip_in_networks, find_matches, from_local_file)
#     # остаются как в предыдущей версии — они уже рабочие
class EltexESRParser:
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
                    # сохранить предыдущий, если был
                    self.zone_pairs[current_zone_pair].append(current_rule_lines[:])
                current_rule_lines = [line]
                current_rule = line
                i += 1
                continue

            if current_zone_pair and current_rule_lines:
                # продолжаем собирать строки внутри rule
                if line.strip() in ("exit", "!"):
                    # конец rule
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

        # не забыть сохранить последний rule, если остался открытым
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
                except:
                    pass

        recurse(group_name)
        return list(result) if result else ["any"]

    def _expand_service_group(self, group_name):
        """Возвращает список портов/диапазонов (пока как строки)"""
        return self.service_groups.get(group_name, ["any"])
# v1
#     def _ip_in_networks(self, ip_str, networks, strict_mode=False):
#         try:
#             if ip_str == "any":
#                 return True
#             ip = ipaddress.ip_address(ip_str)
#             ip_net32 = ipaddress.ip_network(str(ip) + "/32", strict=False)
#             for net_str in networks:
#                 if net_str == "any":
#                     if not strict_mode:
#                         return True
#                     continue
#                 try:
#                     net = ipaddress.ip_network(net_str, strict=False)
#                     if strict_mode:
#                         if net == ip_net32:
#                             return True
#                     else:
#                         if ip in net:
#                             return True
#                 except:
#                     continue
#             return False
#         except:
#             return False
    # v1
    # def find_matches(self, src_ip, dst_ip=None, strict_mode=False):
    #     """
    #     Возвращает блоки rule, которые подходят под src_ip и dst_ip.
    #
    #     При strict_mode=True:
    #     - src_ip должен точно совпадать с сетью (не подсеть)
    #     - dst_ip должен точно совпадать (если указан)
    #
    #     При strict_mode=False:
    #     - обычное вхождение IP в сеть
    #     """
    #     results = []
    #
    #     for zone_pair, rule_blocks in self.zone_pairs.items():
    #         matched_rules = []
    #
    #         for rule_lines in rule_blocks:
    #             src_groups = []
    #             dst_groups = []
    #             action = None
    #             enabled = False
    #
    #             for ln in rule_lines:
    #                 ln = ln.strip()
    #                 if ln.startswith("action "):
    #                     action = ln.split("action ", 1)[1].strip()
    #                 elif ln.startswith("match source-address object-group "):
    #                     src_groups.append(ln.split("object-group ", 1)[1].strip())
    #                 elif ln.startswith("match destination-address object-group "):
    #                     dst_groups.append(ln.split("object-group ", 1)[1].strip())
    #                 elif ln == "enable":
    #                     enabled = True
    #
    #             if not enabled or not action:
    #                 continue
    #
    #             # Проверяем source
    #             src_match = False
    #             if not src_groups:
    #                 src_match = True  # нет ограничения = any
    #             else:
    #                 for g in src_groups:
    #                     nets = self._expand_network_group(g)
    #                     if self._ip_in_networks(src_ip, nets, strict_mode):
    #                         src_match = True
    #                         break
    #
    #             # Проверяем destination
    #             dst_match = False
    #             if dst_ip is None or dst_ip == "any":
    #                 dst_match = True
    #             elif not dst_groups:
    #                 dst_match = True  # нет ограничения
    #             else:
    #                 for g in dst_groups:
    #                     nets = self._expand_network_group(g)
    #                     if self._ip_in_networks(dst_ip, nets, strict_mode):
    #                         dst_match = True
    #                         break
    #
    #             if src_match and dst_match:
    #                 # Добавляем весь блок rule
    #                 matched_rules.extend(rule_lines)
    #
    #         if matched_rules:
    #             results.append(f"security zone-pair {zone_pair}")
    #             results.extend(matched_rules)
    #             results.append("  exit")  # для красоты
    #
    #     return tuple(results)
    #v2+v3 (стабильный)
    # def find_matches(self, src_ip, dst_ip=None, strict_mode=False):
    #     """
    #     Возвращает блоки rule, которые подходят под src_ip и dst_ip.
    #
    #     При strict_mode=True:
    #     - src_ip должен точно совпадать с сетью (не подсеть)
    #     - если в правиле нет match source-address → правило НЕ подходит (если src_ip != "any")
    #     - аналогично для dst_ip
    #
    #     При strict_mode=False:
    #     - обычное вхождение IP в сеть
    #     - отсутствие match source-address/destination-address = any (подходит)
    #     """
    #     results = []
    #
    #     # Если src_ip не "any" и strict_mode=True → требуем наличие хотя бы одного match source-address
    #     require_src_match = strict_mode and src_ip != "any"
    #     require_dst_match = strict_mode and dst_ip and dst_ip != "any"
    #
    #     for zone_pair, rule_blocks in self.zone_pairs.items():
    #         matched_blocks = []
    #
    #         for rule_lines in rule_blocks:
    #             src_groups = []
    #             dst_groups = []
    #             action = None
    #             enabled = False
    #
    #             for ln in rule_lines:
    #                 s = ln.strip()
    #                 if s.startswith("action "):
    #                     action = s.split("action ", 1)[1].strip()
    #                 elif s.startswith("match source-address object-group "):
    #                     src_groups.append(s.split("object-group ", 1)[1].strip())
    #                 elif s.startswith("match destination-address object-group "):
    #                     dst_groups.append(s.split("object-group ", 1)[1].strip())
    #                 elif s == "enable":
    #                     enabled = True
    #
    #             if not enabled or not action:
    #                 continue
    #
    #             if not src_groups and not dst_groups:
    #                 continue
    #
    #             # Проверяем source
    #             src_ok = False
    #             if not src_groups:
    #                 # Нет ограничения по source → any
    #                 src_ok = not require_src_match  # в strict_mode с конкретным IP → False
    #             else:
    #                 for g in src_groups:
    #                     nets = self._expand_network_group(g)
    #                     if self._ip_in_networks(src_ip, nets, strict_mode):
    #                         src_ok = True
    #                         break
    #
    #             # Проверяем destination
    #             dst_ok = False
    #             if dst_ip is None or dst_ip == "any":
    #                 dst_ok = True
    #             elif not dst_groups:
    #                 # Нет ограничения по destination → any
    #                 dst_ok = not require_dst_match
    #             else:
    #                 for g in dst_groups:
    #                     nets = self._expand_network_group(g)
    #                     if self._ip_in_networks(dst_ip, nets, strict_mode):
    #                         dst_ok = True
    #                         break
    #
    #             if src_ok and dst_ok:
    #                 matched_blocks.extend(rule_lines)
    #
    #         if matched_blocks:
    #             results.append(f"security zone-pair {zone_pair}")
    #             results.extend(matched_blocks)
    #             results.append("  exit")
    #
    #     return tuple(results)


    # v2 _ip_in_networks (для сетей)
    # def _ip_in_networks(self, query_str, networks, strict_mode=False):
    #     """
    #     query_str может быть:
    #       - IP:          "10.59.28.17"      → считается как /32
    #       - сеть:        "192.168.20.0/24"  → ищем точное совпадение сети (всегда строго)
    #       - хост-сеть:   "185.10.60.70/32"  → считается как обычный IP (/32)
    #
    #     networks — список строк из object-group (например ["10.59.1.32/28", "10.59.46.17/32"])
    #     """
    #     if query_str == "any":
    #         return True
    #
    #     try:
    #         query_net = ipaddress.ip_network(query_str, strict=False)
    #         is_network_search = (query_net.prefixlen != 32)  # если не /32 — это поиск сети → всегда строго
    #
    #         for net_str in networks:
    #             if net_str == "any":
    #                 # any в группе → подходит только если НЕ strict-режим И НЕ поиск по сети
    #                 if is_network_search or strict_mode:
    #                     continue
    #                 return True
    #
    #             try:
    #                 net = ipaddress.ip_network(net_str, strict=False)
    #
    #                 if is_network_search:
    #                     # Поиск сети → только точное совпадение
    #                     if net == query_net:
    #                         return True
    #                 else:
    #                     # Поиск IP (/32) → обычная логика
    #                     if strict_mode:
    #                         if net == query_net:  # точное совпадение /32
    #                             return True
    #                     else:
    #                         # вхождение IP в сеть
    #                         ip = ipaddress.ip_address(query_net.network_address)
    #                         if ip in net:
    #                             return True
    #             except ValueError:
    #                 continue
    #
    #         return False
    #     except ValueError:
    #         # если query_str вообще не IP и не сеть — считаем не подходящим
    #         return False

    # v3 11-03-26
    def _ip_in_networks(self, query_str, networks, strict_mode=False, is_network_search=False):
        """
        query_str — строка запроса (IP или сеть)
        is_network_search — True, если это поиск по сети (маска != 32)
        """
        if query_str == "any":
            return True

        try:
            query_net = ipaddress.ip_network(query_str, strict=False)

            for net_str in networks:
                if net_str == "any":
                    # any в группе → подходит только если НЕ поиск сети и НЕ strict-режим для IP
                    if is_network_search or (strict_mode and not is_network_search):
                        continue
                    return True

                try:
                    net = ipaddress.ip_network(net_str, strict=False)

                    if is_network_search:
                        # Поиск сети → ТОЛЬКО точное совпадение
                        if net == query_net:
                            return True
                    else:
                        # Поиск IP
                        ip = ipaddress.ip_address(query_net.network_address)
                        if strict_mode:
                            # Точное совпадение подсети
                            if net == query_net:
                                return True
                        else:
                            # Вхождение IP в сеть
                            if ip in net:
                                return True
                except ValueError:
                    continue

            return False
        except ValueError:
            return False

    #     v1
    # def find_matches(self, src_ip, dst_ip=None, strict_mode=False):
    #     """
    #     Логика поиска с учётом strict_mode:
    #
    #     strict_mode=True:
    #     - Правило попадает ТОЛЬКО если есть match source-address и src_ip ТОЧНО равен одной из подсетей в группе
    #     - Если dst_ip задан и не "any" — аналогично требуется match destination-address и точное совпадение
    #     - Правила без match source-address (или без match destination-address при поиске dst) — полностью игнорируются
    #     - Все строки description игнорируются
    #
    #     strict_mode=False:
    #     - обычное вхождение IP в сеть (или any)
    #     - отсутствие match source/destination = any (разрешено)
    #     """
    #     results = []
    #
    #     # Флаги: требовать ли наличие match source/destination в строгом режиме
    #     require_src = strict_mode and src_ip != "any"
    #     require_dst = strict_mode and dst_ip and dst_ip != "any"
    #
    #     for zone_pair, rule_blocks in self.zone_pairs.items():
    #         matched_blocks = []
    #
    #         for rule_lines in rule_blocks:
    #             src_groups = []
    #             dst_groups = []
    #             action = None
    #             enabled = False
    #             has_description = False
    #
    #             filtered_rule_lines = []
    #
    #             for ln in rule_lines:
    #                 s = ln.strip()
    #                 if s.startswith("description "):
    #                     has_description = True
    #                     continue  # пропускаем строку description
    #                 filtered_rule_lines.append(ln)
    #
    #                 if s.startswith("action "):
    #                     action = s.split("action ", 1)[1].strip()
    #                 elif s.startswith("match source-address object-group "):
    #                     src_groups.append(s.split("object-group ", 1)[1].strip())
    #                 elif s.startswith("match destination-address object-group "):
    #                     dst_groups.append(s.split("object-group ", 1)[1].strip())
    #                 elif s == "enable":
    #                     enabled = True
    #
    #             if not enabled or not action:
    #                 continue
    #
    #             # В strict_mode: если требуется source-match, но его нет — пропускаем правило
    #             if require_src and not src_groups:
    #                 continue
    #
    #             # Аналогично для destination
    #             if require_dst and not dst_groups:
    #                 continue
    #
    #             # Проверяем source
    #             src_ok = False
    #             if not src_groups:
    #                 # Нет ограничения → any
    #                 src_ok = not require_src  # в strict_mode с конкретным IP → False
    #             else:
    #                 for g in src_groups:
    #                     nets = self._expand_network_group(g)
    #                     if self._ip_in_networks(src_ip, nets, strict_mode):
    #                         src_ok = True
    #                         break
    #
    #             # Проверяем destination
    #             dst_ok = False
    #             if dst_ip is None or dst_ip == "any":
    #                 dst_ok = True
    #             elif not dst_groups:
    #                 dst_ok = not require_dst
    #             else:
    #                 for g in dst_groups:
    #                     nets = self._expand_network_group(g)
    #                     if self._ip_in_networks(dst_ip, nets, strict_mode):
    #                         dst_ok = True
    #                         break
    #
    #             if src_ok and dst_ok:
    #                 # Добавляем отфильтрованные строки (без description)
    #                 matched_blocks.extend(filtered_rule_lines)
    #
    #         if matched_blocks:
    #             results.append(f"security zone-pair {zone_pair}")
    #             results.extend(matched_blocks)
    #             results.append("  exit")
    #
    #     return tuple(results)



    # v4 (стабильный)
    # def find_matches(self, src_ip, dst_ip=None, strict_mode=False):
    #     """
    #     Логика поиска:
    #
    #     - Если src_ip или dst_ip — сеть (маска != 32) → поиск СТРОГОГО совпадения сети (независимо от strict_mode)
    #     - Если src_ip / dst_ip — IP (/32 или без маски) → обычная проверка:
    #         strict_mode=True  → точное совпадение подсети
    #         strict_mode=False → вхождение в подсеть
    #     - Правила без match source-address И без match destination-address — полностью игнорируются
    #     - description-строки пропускаются
    #     """
    #     results = []
    #
    #     # Флаги: требовать наличие match в строгом режиме для IP-поиска
    #     require_src = strict_mode and src_ip != "any" and '/' not in src_ip or (
    #         src_ip.endswith('/32') if '/' in src_ip else False)
    #     require_dst = strict_mode and dst_ip and dst_ip != "any" and '/' not in dst_ip or (
    #         dst_ip.endswith('/32') if dst_ip and '/' in dst_ip else False)
    #
    #     for zone_pair, rule_blocks in self.zone_pairs.items():
    #         matched_blocks = []
    #
    #         for rule_lines in rule_blocks:
    #             src_groups = []
    #             dst_groups = []
    #             action = None
    #             enabled = False
    #             filtered_rule_lines = []
    #
    #             for ln in rule_lines:
    #                 s = ln.strip()
    #                 if s.startswith("description "):
    #                     continue  # пропускаем description
    #                 filtered_rule_lines.append(ln)
    #
    #                 if s.startswith("action "):
    #                     action = s.split("action ", 1)[1].strip()
    #                 elif s.startswith("match source-address object-group "):
    #                     src_groups.append(s.split("object-group ", 1)[1].strip())
    #                 elif s.startswith("match destination-address object-group "):
    #                     dst_groups.append(s.split("object-group ", 1)[1].strip())
    #                 elif s == "enable":
    #                     enabled = True
    #
    #             if not enabled or not action:
    #                 continue
    #
    #             # Игнорируем any-any правила полностью
    #             if not src_groups and not dst_groups:
    #                 continue
    #
    #             # В strict_mode: если требуется source-match, но его нет — пропускаем
    #             if require_src and not src_groups:
    #                 continue
    #
    #             # Аналогично для destination
    #             if require_dst and not dst_groups:
    #                 continue
    #
    #             # Проверяем source
    #             src_ok = False
    #             if not src_groups:
    #                 src_ok = not require_src
    #             else:
    #                 for g in src_groups:
    #                     nets = self._expand_network_group(g)
    #                     if self._ip_in_networks(src_ip, nets, strict_mode):
    #                         src_ok = True
    #                         break
    #
    #             # Проверяем destination
    #             dst_ok = False
    #             if dst_ip is None or dst_ip == "any":
    #                 dst_ok = True
    #             elif not dst_groups:
    #                 dst_ok = not require_dst
    #             else:
    #                 for g in dst_groups:
    #                     nets = self._expand_network_group(g)
    #                     if self._ip_in_networks(dst_ip, nets, strict_mode):
    #                         dst_ok = True
    #                         break
    #
    #             if src_ok and dst_ok:
    #                 matched_blocks.extend(filtered_rule_lines)
    #
    #         if matched_blocks:
    #             results.append(f"security zone-pair {zone_pair}")
    #             results.extend(matched_blocks)
    #             results.append("  exit")
    #
    #     return tuple(results)

    # v5 (правка для сети)
    # def find_matches(self, src_ip, dst_ip=None, strict_mode=False):
    #     """
    #     Логика поиска:
    #
    #     - Если src_ip — сеть (маска != 32) → ищем ТОЧНОЕ совпадение сети в match source-address
    #       Правило без match source-address → полностью игнорируется
    #     - Если src_ip — IP (/32 или без маски):
    #         strict_mode=True  → точное совпадение подсети + требуется match source-address
    #         strict_mode=False → вхождение + any разрешено
    #     - Аналогично для dst_ip
    #     - description-строки пропускаются
    #     """
    #     results = []
    #
    #     # Определяем тип поиска для source и destination
    #     src_is_network = '/' in src_ip and not src_ip.endswith('/32')
    #     dst_is_network = dst_ip and '/' in dst_ip and not dst_ip.endswith('/32')
    #
    #     # Требуем наличие match source-address, если ищем конкретный src (IP или сеть)
    #     require_src = src_ip != "any"  # всегда требуем для любого конкретного src
    #     require_dst = dst_ip and dst_ip != "any"
    #
    #     for zone_pair, rule_blocks in self.zone_pairs.items():
    #         matched_blocks = []
    #
    #         for rule_lines in rule_blocks:
    #             src_groups = []
    #             dst_groups = []
    #             action = None
    #             enabled = False
    #             filtered_rule_lines = []
    #
    #             for ln in rule_lines:
    #                 s = ln.strip()
    #                 if s.startswith("description "):
    #                     continue
    #                 filtered_rule_lines.append(ln)
    #
    #                 if s.startswith("action "):
    #                     action = s.split("action ", 1)[1].strip()
    #                 elif s.startswith("match source-address object-group "):
    #                     src_groups.append(s.split("object-group ", 1)[1].strip())
    #                 elif s.startswith("match destination-address object-group "):
    #                     dst_groups.append(s.split("object-group ", 1)[1].strip())
    #                 elif s == "enable":
    #                     enabled = True
    #
    #             if not enabled or not action:
    #                 continue
    #
    #             # Игнорируем any-any полностью
    #             if not src_groups and not dst_groups:
    #                 continue
    #
    #             # Если ищем конкретный src (IP или сеть) — требуем наличие match source-address
    #             if require_src and not src_groups:
    #                 continue
    #
    #             # Если ищем конкретный dst — требуем наличие match destination-address
    #             if require_dst and not dst_groups:
    #                 continue
    #
    #             # Проверяем source
    #             src_ok = False
    #             if not src_groups:
    #                 src_ok = not require_src
    #             else:
    #                 for g in src_groups:
    #                     nets = self._expand_network_group(g)
    #                     if self._ip_in_networks(src_ip, nets, strict_mode):
    #                         src_ok = True
    #                         break
    #
    #             # Проверяем destination
    #             dst_ok = False
    #             if dst_ip is None or dst_ip == "any":
    #                 dst_ok = True
    #             elif not dst_groups:
    #                 dst_ok = not require_dst
    #             else:
    #                 for g in dst_groups:
    #                     nets = self._expand_network_group(g)
    #                     if self._ip_in_networks(dst_ip, nets, strict_mode):
    #                         dst_ok = True
    #                         break
    #
    #             if src_ok and dst_ok:
    #                 matched_blocks.extend(filtered_rule_lines)
    #
    #         if matched_blocks:
    #             results.append(f"security zone-pair {zone_pair}")
    #             results.extend(matched_blocks)
    #             results.append("  exit")
    #
    #     return tuple(results)

    # v6 11-03-26
    def find_matches(self, src_ip, dst_ip=None, strict_mode=False):
        """
        Логика поиска:

        1. Поиск по сети (маска != 32):
           - Требуется наличие match source-address
           - ТОЛЬКО точное совпадение сети (==) в группе или prefix
           - Правила без match source-address → полностью игнорируются

        2. Поиск по IP (/32 или без маски):
           - strict_mode=True  → точное совпадение подсети + требуется match source-address
           - strict_mode=False → вхождение в подсеть + any разрешено (если есть match или нет ограничения)

        3. Правила без match source-address И без match destination-address — полностью игнорируются
        4. description — пропускаются
        """
        results = []

        # Определяем тип запроса
        src_is_network = '/' in src_ip and not src_ip.endswith('/32')
        dst_is_network = dst_ip and '/' in dst_ip and not dst_ip.endswith('/32')

        # Требуем match source-address для любого конкретного src (IP или сеть)
        require_src = src_ip != "any"
        require_dst = dst_ip and dst_ip != "any"

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
                        # Прямой prefix в правиле — рассматриваем как группу с одним префиксом
                        prefix = s.split("prefix ", 1)[1].strip()
                        src_groups.append(prefix)  # временно добавляем как "группу"
                    elif s == "enable":
                        enabled = True

                if not enabled or not action:
                    continue

                # Игнорируем any-any полностью
                if not src_groups and not dst_groups:
                    continue

                # Если ищем конкретный src — требуем наличие match source-address (или prefix)
                if require_src and not src_groups:
                    continue

                # Если ищем конкретный dst — требуем match destination-address
                if require_dst and not dst_groups:
                    continue

                # Проверяем source
                src_ok = False
                if not src_groups:
                    src_ok = not require_src
                else:
                    for g in src_groups:
                        # Если g — строка префикса (из match prefix), а не имя группы
                        if '/' in g and not g.startswith("object-group"):
                            nets = [g]
                        else:
                            nets = self._expand_network_group(g)
                        if self._ip_in_networks(src_ip, nets, strict_mode, src_is_network):
                            src_ok = True
                            break

                # Проверяем destination
                dst_ok = False
                if dst_ip is None or dst_ip == "any":
                    dst_ok = True
                elif not dst_groups:
                    dst_ok = not require_dst
                else:
                    for g in dst_groups:
                        nets = self._expand_network_group(g)
                        if self._ip_in_networks(dst_ip, nets, strict_mode, dst_is_network):
                            dst_ok = True
                            break

                if src_ok and dst_ok:
                    matched_blocks.extend(filtered_rule_lines)

            if matched_blocks:
                results.append(f"security zone-pair {zone_pair}")
                results.extend(matched_blocks)
                results.append("  exit")

        return tuple(results)
    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip=None,
                        strict_mode=False, base_dir=base_dir, encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    with open(os.path.join(root, file), "r", encoding=encoding, errors="ignore") as f:
                        parser = cls(f.read())
                        return parser.find_matches(src_ip, dst_ip, strict_mode)
        return tuple()
class HPEParser:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.acls = {}
        self.acl_headers = {}
        self.parse()

    @staticmethod
    def safe_ip_network(addr_str: str, strict: bool = True) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        if not addr_str or addr_str.lower() == "any":
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
        if addr_spec.lower() == "any":
            return "any"

        net = HPEParser.safe_ip_network(addr_spec, strict=True)  # ← через имя класса
        if net is not None:
            return str(net)

        ip = HPEParser.safe_ip_address(addr_spec)
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
                # Сохраняем ВСЮ оригинальную строку как заголовок (это главное изменение)
                current_header = line.strip()

                parts = line.split()

                if line.startswith("acl number") and len(parts) >= 3:
                    current_acl = parts[2]  # номер — ключ словаря
                    self.acls.setdefault(current_acl, {})
                    self.acl_headers[current_acl] = current_header  # ← полная строка!

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

                    # извлекаем только часть правила (после номера)
                    rule_part = " ".join(parts[num_idx + 1:]) if len(parts) > num_idx + 1 else ""
                    if not rule_part or "comment" in line.lower():
                        continue
                    try:
                        pairs = self._parse_office_rule(rule_part)
                        self.acls[current_acl][line] = pairs
                        cleaned = []
                        for src, dst in pairs:
                            if src == "any" and dst == "any":
                                continue
                            cleaned.append((src, dst))
                        if cleaned:
                            self.acls[current_acl][line] = cleaned
                    except:
                        pass
                        # print(f"[!] Ошибка разбора строки '{line}': {e}")
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

            # === Правила Comware (строки, начинающиеся с rule) ===
            if current_acl and line.startswith("rule "):
                if "comment" in line.lower():
                    continue
                try:
                    pairs = self._parse_rule(line)
                    if not pairs:
                        continue
                    cleaned = []
                    for src, dst in pairs:
                        if src == "any" and dst == "any":
                            # print('any-any')
                            continue
                        cleaned.append((src, dst))
                    if cleaned:
                        self.acls[current_acl][line] = cleaned
                except:
                    pass
                    # print(f"[!] Ошибка разбора строки '{line}': {e}")
                continue

            # === Правила OfficeConnect именованного ACL (permit/deny ...) ===
            if current_acl and line.lstrip().lower().startswith(("permit ", "deny ")):
                rule_line = line.strip()
                if "comment" in rule_line.lower():
                    continue
                try:
                    pairs = self._parse_office_rule(rule_line)
                    if not pairs:
                        continue
                    cleaned = []
                    for src, dst in pairs:
                        if src == "any" and dst == "any":
                            continue
                        cleaned.append((src, dst))
                    if cleaned:
                        self.acls[current_acl][rule_line] = cleaned
                except:
                    pass
                    # print(f"[!] Ошибка разбора строки '{rule_line}': {e}")

    # ====================== Huawei/Comware парсинг правил ======================
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

        if not ip.replace(".", "").isdigit() and not ip.startswith("::"):
            return "BS"

        wc = None
        if idx + 1 < len(parts):
            nxt = parts[idx + 1]
            if self._looks_like_wildcard(nxt):
                wc = nxt

        if wc is None:
            return f"{ip}/32"

        spec = self._wildcard_to_network_or_range(ip, wc)
        return spec

    def _looks_like_wildcard(self, s: str) -> bool:
        if s.count(".") == 3:
            try:
                ipaddress.IPv4Address(s)
                return True
            except ValueError:
                return False
        return s.isdigit()

    def _wildcard_to_network_or_range(self, ip_str: str, wildcard_str: str):
        ip = HPEParser.safe_ip_address(ip_str)
        if ip is None:
            return None
        try:
            if wildcard_str.count(".") == 3:
                w = int(ipaddress.IPv4Address(wildcard_str))
            else:
                w = int(wildcard_str)
                if not (0 <= w <= 0xFFFFFFFF):
                    raise ValueError("wildcard out of range")
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
                ip_int = int(ipaddress.IPv4Address(ip_str))
                start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
                end = (ip_int | w) & 0xFFFFFFFF
                return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))

        ip_int = int(ipaddress.IPv4Address(ip_str))
        start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
        end = (ip_int | w) & 0xFFFFFFFF
        return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))

    # ====================== OfficeConnect парсинг правил ======================
    def _parse_office_rule(self, rule_str):
        parts = rule_str.split()
        if not parts or parts[0].lower() not in ("permit", "deny"):
            return []

        idx = 1
        # пропускаем протокол (tcp, udp, ip, icmp и т.д.)
        if idx < len(parts) and parts[idx].lower() in ("ip", "tcp", "udp", "icmp", "esp", "ah", "gre", "pim", "igmp"):
            idx += 1

        # source
        src_spec, consumed = self._parse_office_addr(parts, idx)
        idx += consumed

        # destination (если есть)
        if idx < len(parts):
            dst_spec, _ = self._parse_office_addr(parts, idx)
        else:
            dst_spec = "any"

        return [(src_spec, dst_spec)]

    def _parse_office_addr(self, parts, start_idx):
        if start_idx >= len(parts):
            return "any", 0

        token = parts[start_idx].lower()
        if token == "any":
            return "any", 1

        if token == "host":
            if start_idx + 1 < len(parts):
                ip = parts[start_idx + 1]
                return f"{ip}/32", 2
            return "any", 1

        # IP + возможный wildcard
        ip = parts[start_idx]
        consumed = 1
        if start_idx + 1 < len(parts) and self._looks_like_wildcard(parts[start_idx + 1]):
            wc = parts[start_idx + 1]
            consumed = 2
            spec = self._wildcard_to_network_or_range(ip, wc)
            return spec, consumed

        return f"{ip}/32", 1

    # ====================== Общие методы поиска (точно как в Huawei) ======================
    def _parse_search(self, text):
        if not text or text.lower() == "any":
            return "any"

            # Пробуем как сеть
        normalized = HPEParser.normalize_to_network(text)
        if normalized is not None:
            return normalized

        # Пробуем формат IP wildcard (старый способ)
        if " " in text:
            parts = text.split(maxsplit=1)
            if len(parts) == 2:
                ip_part, wc_part = parts
                ip = HPEParser.safe_ip_address(ip_part)
                if ip is None:
                    return None
                # дальше ваша логика wildcard → сеть/диапазон
                try:
                    return self._wildcard_to_network_or_range(ip_part, wc_part)
                except:
                    pass

        return None

        if text == "any":
            return "any"
        if "/" in text:
            try:
                net = ipaddress.ip_network(text, strict=True)
                return str(net)
            except ValueError:
                return None
        if " " in text:
            parts = text.split()
            ip = parts[0]
            wc = parts[1]
            return self._wildcard_to_network_or_range(ip, wc)
        return f"{text}/32"

    def _get_min_max(self, spec):
        if spec == "any":
            return 0, 0xFFFFFFFF
        if spec is None:
            return None, None
        if isinstance(spec, tuple) and spec[0] == "range":
            _, start, end = spec
            return int(start), int(end)

        net = HPEParser.safe_ip_network(spec, strict=False)
        if net is not None:
            return int(net.network_address), int(net.broadcast_address)

        ip = HPEParser.safe_ip_address(spec)
        if ip is not None:
            return int(ip), int(ip)

        return None, None

        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            return int(net.network_address), int(net.broadcast_address)
        ip = ipaddress.ip_address(spec)
        return int(ip), int(ip)

    def _spec_intersects(self, spec1, spec2, strict_mode):
        if spec1 is None or spec2 is None:
            return False

        if spec1 == "any" or spec2 == "any":
            if spec1 == spec2 == "any":
                return True
            return not strict_mode

        min1, max1 = self._get_min_max(spec1)
        min2, max2 = self._get_min_max(spec2)

        # ← Самое важное исправление
        if min1 is None or max1 is None or min2 is None or max2 is None:
            return False

        is_network1 = max1 > min1
        is_network2 = max2 > min2

        overlap = max1 >= min2 and max2 >= min1

        if is_network1:
            return min1 == min2 and max1 == max2

        if strict_mode:
            return min1 == min2 and max1 == max2

        return min2 <= min1 <= max2


    def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
        # Если src или dst не задан — считаем any (как просил пользователь)
        if src_ip is None or str(src_ip).strip() == "":
            src_ip = "any"
        else:
            src_ip = str(src_ip).strip()

        if dst_ip is None or str(dst_ip).strip() == "":
            dst_ip = "any"
        else:
            dst_ip = str(dst_ip).strip()

        src_ip = str(src_ip).strip() if src_ip else "any"
        dst_ip = str(dst_ip).strip() if dst_ip else "any"

        # src_spec_search = self._parse_search(src_ip)
        # dst_spec_search = self._parse_search(dst_ip)

        src_spec_search = self._parse_search(src_ip)
        dst_spec_search = self._parse_search(dst_ip)

        if src_spec_search is None or dst_spec_search is None:
            return []

        results = []
        for acl_key, rules in self.acls.items():
            matched_rules = []
            for rule_line, pairs in rules.items():
                for src_spec, dst_spec in pairs:
                    if (self._spec_intersects(src_spec_search, src_spec, strict_mode) and
                            self._spec_intersects(dst_spec_search, dst_spec, strict_mode)):
                        matched_rules.append(rule_line)
                        break
            if matched_rules:
                header = self.acl_headers.get(acl_key, f"acl {acl_key}")
                results.append(header)
                for r in matched_rules:
                    results.append(f"  {r}")
        return tuple(results)
    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, base_dir=base_dir, encoding="utf-8",
                        strict_mode=False):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                    except Exception as e:
                        # print(f"[!] Ошибка при чтении {full_path}: {e}")
                        return ()
                    parser = cls(config_text)
                    return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
        # print(f"⚠️ Файл {filename} не найден в директории {base_dir}")
        return ()