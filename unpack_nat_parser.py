import ipaddress
import re

from fastapi import HTTPException


class CiscoASA_NAT_Parser:
    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        # Используем единое название self.all_objects
        self.all_objects = self.parse_all_object_networks()

    def parse_all_object_networks(self):
        """Автономный сбор объектов сети: сохраняем чистые объекты IPv4Network напрямую"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object network"):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[2]
                    obj_items = []
                    j = i + 1
                    while j < len(self.lines) and self.lines[j].startswith(" "):
                        sub_line = self.lines[j].strip()
                        sub_parts = sub_line.split()
                        if sub_parts:
                            sub_cmd = sub_parts[0]
                            if sub_cmd == "host" and len(sub_parts) >= 2:
                                try:
                                    net = ipaddress.ip_network(f"{sub_parts[1]}/32", strict=False)
                                    obj_items.append(net)
                                except ValueError:
                                    pass
                            elif sub_cmd == "subnet" and len(sub_parts) >= 3:
                                try:
                                    net = ipaddress.IPv4Network((sub_parts[1], sub_parts[2]), strict=False)
                                    obj_items.append(net)
                                except ValueError:
                                    pass
                        j += 1
                    if obj_items:
                        objects[name] = obj_items
                        # print(f"[PARSER OBJECTS] Объект '{name}' содержит сети: {[str(n) for n in obj_items]}")
                    i = j - 1
            i += 1
        return objects

    def parse_all_nat_rules(self):
        rules = []
        for idx, line in enumerate(self.lines):
            line_str = line.strip()

            # Пропускаем строки, если правило явно помечено как неактивное (inactive)
            if "inactive" in line_str.lower():
                continue

            # 1. Обрабатываем глобальные Twice NAT (которые содержат source или destination)
            if line_str.startswith("nat ("):
                if "source" in line_str or "destination" in line_str:
                    rule_info = self._parse_twice_nat_line(line_str, idx + 1)
                    if rule_info:
                        rules.append(rule_info)

            # 2. Обрабатываем Object NAT строго внутри блоков object network
            elif line_str.startswith("object network"):
                parts = line_str.split()
                obj_name = parts[2] if len(parts) >= 3 else "unknown"

                j = idx + 1
                while j < len(self.lines) and self.lines[j].startswith(" "):
                    sub_line = self.lines[j].strip()

                    # Проверяем вложенную строку NAT на наличие inactive
                    if sub_line.startswith("nat (") and "inactive" not in sub_line.lower():
                        rule_info = self._parse_object_nat_line(obj_name, sub_line, j, idx + 1)
                        if rule_info:
                            rules.append(rule_info)
                    j += 1

        return rules
    def rule_matches_query(self, rule, query_str):
        """Интеллектуальный поиск: текст, IP/подсети и порты (например, tcp/443)"""
        if not query_str:
            return True

        query_lower = query_str.lower().strip()
        raw = rule.get("raw_line", "").lower()
        real_iface = rule.get("real_interface", "").lower()
        mapped_iface = rule.get("mapped_interface", "").lower()
        obj_name = rule.get("object_name", "").lower()

        # 1. ПРОВЕРКА ПОИСКА ПО ПОРТАМ (формат вроде tcp/443, udp/53 или просто порт)
        is_port_query = False
        target_proto = None
        target_port = None

        if "/" in query_lower and not any(c in query_lower for c in ". "):
            parts = query_lower.split("/")
            if len(parts) == 2 and parts[0] in ["tcp", "udp"] and parts[1].isdigit():
                target_proto = parts[0]
                target_port = int(parts[1])
                is_port_query = True

        if is_port_query:
            rule_text = rule.get("details", "") or rule.get("raw_line", "").lower()

            # Проверяем наличие протокола в правиле
            if target_proto in rule_text:
                # Ищем числовые порты или сервисы в строке правила
                words = rule_text.split()
                i = 0
                while i < len(words):
                    word = words[i].strip("()=,")
                    # Проверяем прямой порт (например, service tcp https 443 -> если это число или имя)
                    if word.isdigit() and int(word) == target_port:
                        return True
                    # Есливстретили слово диапазона типа range 10000 20000
                    if word == "range" and i + 2 < len(words):
                        try:
                            p_start = int(words[i + 1])
                            p_end = int(words[i + 2])
                            if p_start <= target_port <= p_end:
                                return True
                        except ValueError:
                            pass
                    i += 1

                # Если в запросе стандартный порт вроде 443, а в конфиге написано имя service ... https https
                if target_port == 443 and ("https" in rule_text):
                    return True
                if target_port == 80 and ("www" in rule_text or "http" in rule_text):
                    return True

            return False  # Если искали конкретный порт, но он не сошелся — правило не подходит

        # 2. ПРОВЕРКА ПОИСКА ПО IP / ПОДСЕТЯМ (ваша текущая логика)
        is_ip_query = False
        target_net = None

        try:
            target_net = ipaddress.ip_network(query_lower, strict=False)
            is_ip_query = True
        except ValueError:
            is_ip_query = False

        if is_ip_query:
            if obj_name and obj_name in self.all_objects:
                for net in self.all_objects[obj_name]:
                    if target_net.overlaps(net) or target_net.subnet_of(net):
                        return True

            rule_text = rule.get("details", "") or rule.get("raw_line", "")
            for word in rule_text.split():
                clean_word = word.strip("()=,")
                if clean_word in self.all_objects:
                    for net in self.all_objects[clean_word]:
                        if target_net.overlaps(net) or target_net.subnet_of(net):
                            return True

                try:
                    word_ip = ipaddress.ip_network(clean_word, strict=False)
                    if target_net.overlaps(word_ip):
                        return True
                except ValueError:
                    pass

            return False

        # 3. ОБЫЧНЫЙ ТЕКСТОВЫЙ ПОИСК (например, "https", имя объекта, интерфейс)
        if (query_lower == real_iface) or (query_lower == mapped_iface) or (query_lower in obj_name) or (
                query_lower in raw):
            return True

        return False

    def _determine_detailed_type(self, line_str, is_object_block=True):
        line_lower = line_str.lower()

        # Если это блок Object NAT или строка без явных source/destination на верхнем уровне
        if is_object_block or ("source" not in line_lower and "destination" not in line_lower):
            if "static" in line_lower:
                return "Object NAT (Static)"
            elif "dynamic" in line_lower:
                return "Object NAT (Dynamic)"
            return "Object NAT"
        else:
            # Глобальные правила nat (...) source / destination
            has_source = "source" in line_lower
            has_destination = "destination" in line_lower
            has_after_auto = "after-auto" in line_lower

            # Полноценный Twice NAT только если есть оба направления
            is_twice = has_source and has_destination

            if not is_twice:
                # Одностороннее глобальное правило — это Standard NAT
                base_type = "Standard NAT"
                if "source static" in line_lower:
                    base_type = "Standard NAT (Static Source)"
                elif "source dynamic" in line_lower:
                    base_type = "Standard NAT (Dynamic Source)"
                elif "dynamic" in line_lower:
                    base_type = "Standard NAT (Dynamic Interface)"

                if has_after_auto:
                    base_type += " (After-Auto)"
                return base_type
            else:
                # Настоящий Twice NAT с source и destination
                src_type = "Static Source" if "source static" in line_lower else (
                    "Dynamic Source" if "source dynamic" in line_lower else None)
                dst_type = "Static Destination" if "destination static" in line_lower else (
                    "Dynamic Destination" if "destination dynamic" in line_lower else None)

                sub_parts = [p for p in [src_type, dst_type] if p]
                base_type = f"Twice NAT ({' + '.join(sub_parts)})" if sub_parts else "Twice NAT"

                if has_after_auto:
                    base_type += " (After-Auto)"
                return base_type
    def _parse_twice_nat_line(self, line_str, line_num):
        try:
            interfaces_part = line_str[line_str.find("(") + 1: line_str.find(")")]
            interfaces = [i.strip() for i in interfaces_part.split(",")]
            return {
                "line_number": line_num,
                "raw_line": line_str,
                "nat_type": self._determine_detailed_type(line_str, is_object_block=False),
                "real_interface": interfaces[0] if len(interfaces) > 0 else "",
                "mapped_interface": interfaces[1] if len(interfaces) > 1 else "",
                "details": line_str
            }
        except Exception:
            return None

    def _parse_standalone_object_nat_line(self, line_str, line_num):
        try:
            interfaces_part = line_str[line_str.find("(") + 1: line_str.find(")")]
            interfaces = [i.strip() for i in interfaces_part.split(",")]
            return {
                "line_number": line_num,
                "raw_line": line_str,
                "nat_type": self._determine_detailed_type(line_str, is_object_block=True),
                "real_interface": interfaces[0] if len(interfaces) > 0 else "",
                "mapped_interface": interfaces[1] if len(interfaces) > 1 else "",
                "details": line_str
            }
        except Exception:
            return None

    def _parse_object_nat_line(self, obj_name, line_str, sub_line_idx, obj_start_line_num):
        try:
            interfaces_part = line_str[line_str.find("(") + 1: line_str.find(")")]
            interfaces = [i.strip() for i in interfaces_part.split(",")]
            return {
                "line_number": obj_start_line_num,
                "raw_line": f"object network {obj_name}\n  {line_str}",
                "nat_type": self._determine_detailed_type(line_str, is_object_block=True),
                "real_interface": interfaces[0] if len(interfaces) > 0 else "",
                "mapped_interface": interfaces[1] if len(interfaces) > 1 else "",
                "object_name": obj_name,
                "details": line_str
            }
        except Exception:
            return None


class CiscoIOS_NAT_Parser:
    def __init__(self, config_text: str):
        self.config_text = config_text
        self.lines = config_text.splitlines()
        # Словарь для хранения содержимого ACL: {"kspd_to_acs": ["permit ip host 10.168.3.62 ..."]}
        self.access_lists = self._parse_access_lists()

    def _parse_access_lists(self):
        """Извлекает все ip access-list из конфигурации"""
        acls = {}
        current_acl = None

        acl_header_pat = re.compile(r'^\s*ip\s+access-list\s+(?:extended|standard)\s+([^\s]+)', re.IGNORECASE)

        for line in self.lines:
            raw = line.strip()
            header_match = acl_header_pat.match(raw)

            if header_match:
                current_acl = header_match.group(1)
                acls[current_acl] = []
                continue

            # Если мы внутри блока ACL (строки начинаются с permit или deny)
            if current_acl and (raw.lower().startswith('permit') or raw.lower().startswith('deny')):
                acls[current_acl].append(raw)

        return acls

    def parse_all_nat_rules(self):
        rules = []

        static_pat = re.compile(r'^\s*(ip\s+nat\s+inside\s+source\s+static\s.+)', re.IGNORECASE)
        overload_pat = re.compile(r'^\s*(ip\s+nat\s+inside\s+source\s+list\s+([^\s]+).*)', re.IGNORECASE)
        pool_pat = re.compile(r'^\s*(ip\s+nat\s+pool\s.+)', re.IGNORECASE)

        for line in self.lines:
            raw = line.strip()
            if not raw or raw.startswith('!'):
                continue

            nat_type = "Unknown"
            acl_name = None

            if static_pat.match(raw):
                nat_type = "Static NAT/PAT"
            elif overload_match := overload_pat.match(raw):
                nat_type = "Dynamic NAT/PAT (Overload)"
                acl_name = overload_match.group(2)  # Имя ACL, например kspd_to_acs
            elif pool_pat.match(raw):
                nat_type = "NAT Pool"
            else:
                continue

            # Подтягиваем строки связанного ACL, если он есть
            acl_lines = self.access_lists.get(acl_name, []) if acl_name else []

            rules.append({
                "nat_type": nat_type,
                "real_interface": "inside",  # Фиксировано для IOS
                "mapped_interface": "outside",  # Фиксировано для IOS
                "raw_line": raw,
                "acl_name": acl_name,
                "acl_lines": acl_lines  # Распакованное содержимое ACL
            })

        return rules

    def rule_matches_query(self, rule, query: str) -> bool:
        """Интеллектуальный поиск по строке NAT и содержимому связанного ACL (с поддержкой подсетей)"""
        if not query or query.lower() == "any":
            return True

        q = query.strip().lower()
        raw_line = rule["raw_line"].lower()

        # 1. Прямое вхождение в саму строку NAT (например, поиск по IP интерфейса или названию ACL)
        if q in raw_line:
            return True

        # 2. Проверка по содержимому связанного ACL (если оно есть)
        acl_lines = rule.get("acl_lines", [])
        for acl_line in acl_lines:
            acl_lower = acl_line.lower()

            # Текстовое вхождение (например, имя хоста или часть строки)
            if q in acl_lower:
                return True

            # Интеллектуальная проверка IP-адресов и подсетей через ipaddress
            if self._ip_matches_acl_line(q, acl_line):
                return True

        return False

    def _ip_matches_acl_line(self, query_ip_str: str, acl_line: str) -> bool:
        """Проверяет, попадает ли искомый IP/подсеть в правило ACL"""
        try:
            # Превращаем запрос в объект сети (например, '10.191.224.9' или '10.191.224.0/24')
            query_net = ipaddress.ip_network(query_ip_str, strict=False)
        except ValueError:
            return False  # Если запрос не является валидным IP/сетью

        # Ищем все IP-адреса и маски/сети внутри строки ACL (например, хост 10.168.3.62 или сеть 10.191.224.0 0.0.3.255)
        # В IOS маски часто пишутся через wildcard (например, 0.0.3.255)
        words = acl_line.split()

        # Простой проход по словам в поисках IP
        for i, word in enumerate(words):
            if word == "host" and i + 1 < len(words):
                try:
                    host_ip = ipaddress.ip_address(words[i + 1])
                    if host_ip in query_net or query_net.overlaps(ipaddress.ip_network(str(host_ip))):
                        return True
                except ValueError:
                    continue
            else:
                try:
                    # Пробуем распарсить слово как стандартный IP
                    ip_obj = ipaddress.ip_address(word)

                    # Проверяем следующее слово на предмет wildcard-маски Cisco (например, 0.0.3.255)
                    net_obj = None
                    if i + 1 < len(words):
                        next_word = words[i + 1]
                        # Проверяем, похоже ли следующее слово на маску (содержит точки)
                        if "." in next_word and not next_word.startswith("eq") and not next_word.startswith("range"):
                            try:
                                # Конвертируем wildcard Cisco в CIDR маску (инвертируем биты или используем как есть, если это обычная маска)
                                # Для простоты вычисления пересечения сетей:
                                wildcard_bytes = [255 - int(b) for b in next_word.split('.')]
                                cidr_mask = sum(bin(b).count('1') for b in wildcard_bytes)
                                net_obj = ipaddress.ip_network(f"{word}/{cidr_mask}", strict=False)
                            except Exception:
                                pass

                    if not net_obj:
                        net_obj = ipaddress.ip_network(str(ip_obj), strict=False)

                    # Проверяем пересечение сетей или вхождение
                    if query_net.overlaps(net_obj):
                        return True
                except ValueError:
                    continue

        return False



class CiscoIOSXE_NAT_Parser:
    def __init__(self, config_text: str):
        self.config_text = config_text
        self.lines = config_text.splitlines()
        self.access_lists = self._parse_access_lists()
        self.route_maps = self._parse_route_maps()
        self.pools = self._parse_pools()  # Сохраняем пулы NAT

    def _parse_access_lists(self):
        acls = {}
        current_acl = None
        named_acl_pat = re.compile(r'^\s*ip\s+access-list\s+(?:extended|standard)\s+([^\s]+)', re.IGNORECASE)
        numbered_acl_pat = re.compile(r'^\s*access-list\s+(\d+)\s+(permit|deny)\s+(.+)', re.IGNORECASE)

        for line in self.lines:
            raw = line.strip()
            if not raw or raw.startswith('!'):
                continue
            named_match = named_acl_pat.match(raw)
            if named_match:
                current_acl = named_match.group(1)
                acls[current_acl] = []
                continue
            if current_acl and (raw.lower().startswith('permit') or raw.lower().startswith('deny')):
                acls[current_acl].append(raw)
                continue
            num_match = numbered_acl_pat.match(raw)
            if num_match:
                acl_num = num_match.group(1)
                if acl_num not in acls:
                    acls[acl_num] = []
                acls[acl_num].append(raw)
                current_acl = None
        return acls

    def _parse_route_maps(self):
        rmaps = {}
        current_rm = None
        rm_pat = re.compile(r'^\s*route-map\s+([^\s]+)', re.IGNORECASE)
        match_acl_pat = re.compile(r'^\s*match\s+ip\s+address\s+(?:acl-|access-list\s+)?([^\s]+)', re.IGNORECASE)

        for line in self.lines:
            raw = line.strip()
            rm_match = rm_pat.match(raw)
            if rm_match:
                current_rm = rm_match.group(1)
                rmaps[current_rm] = []
                continue
            if current_rm:
                match_m = match_acl_pat.match(raw)
                if match_m:
                    rmaps[current_rm].append(match_m.group(1))
        return rmaps

    def _parse_pools(self):
        """Извлекает диапазоны IP-адресов из ip nat pool"""
        pools = {}
        pool_pat = re.compile(r'^\s*ip\s+nat\s+pool\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)', re.IGNORECASE)
        for line in self.lines:
            match = pool_pat.match(line.strip())
            if match:
                p_name = match.group(1)
                try:
                    start_ip = ipaddress.ip_address(match.group(2))
                    end_ip = ipaddress.ip_address(match.group(3))
                    pools[p_name] = (start_ip, end_ip)
                except ValueError:
                    pass
        return pools

    def parse_all_nat_rules(self):
        rules = []
        static_in_pat = re.compile(r'^\s*(ip\s+nat\s+inside\s+source\s+static\s.+)', re.IGNORECASE)
        static_out_pat = re.compile(r'^\s*(ip\s+nat\s+outside\s+source\s+static\s.+)', re.IGNORECASE)
        routemap_pat = re.compile(r'^\s*(ip\s+nat\s+inside\s+source\s+route-map\s+([^\s]+).*)', re.IGNORECASE)
        list_pat = re.compile(r'^\s*(ip\s+nat\s+inside\s+source\s+list\s+([^\s]+).*)', re.IGNORECASE)

        for line in self.lines:
            raw = line.strip()
            if not raw or raw.startswith('!'):
                continue
            if raw.startswith('p nat'):
                raw = 'ip ' + raw

            if raw.lower().startswith('ip nat pool'):
                continue  # Пулы не выводим как отдельные правила, но они сохранены в self.pools

            nat_type = "Unknown"
            linked_acl_names = []
            used_pool_name = None
            real_iface = "inside"
            mapped_iface = "outside"

            if static_in_pat.match(raw):
                # Проверяем наличие TCP/UDP портов в строке
                if " tcp " in raw.lower() or " udp " in raw.lower():
                    nat_type = "Static Inside NAT/PAT"
                else:
                    nat_type = "Static Inside NAT"
            elif static_out_pat.match(raw):
                if " tcp " in raw.lower() or " udp " in raw.lower():
                    nat_type = "Static Outside NAT/PAT"
                else:
                    nat_type = "Static Outside NAT"
                real_iface = "outside"
                mapped_iface = "inside"
            elif rm_match := routemap_pat.match(raw):
                nat_type = "Dynamic NAT (Route-Map)"
                rm_name = rm_match.group(2)
                linked_acl_names.extend(self.route_maps.get(rm_name, []))
                # Ищем имя пула в строке правила
                for p_name in self.pools:
                    if f"pool {p_name}".lower() in raw.lower():
                        used_pool_name = p_name
                        break
            elif list_match := list_pat.match(raw):
                nat_type = "Dynamic NAT/PAT (List/Overload)"
                acl_ref = list_match.group(2)
                linked_acl_names.append(acl_ref)
                for p_name in self.pools:
                    if f"pool {p_name}".lower() in raw.lower():
                        used_pool_name = p_name
                        break
            else:
                continue

            all_acl_lines = []
            for acl_name in linked_acl_names:
                if acl_name in self.access_lists:
                    all_acl_lines.extend(self.access_lists[acl_name])

            rules.append({
                "nat_type": nat_type,
                "real_interface": real_iface,
                "mapped_interface": mapped_iface,
                "raw_line": raw,
                "acl_lines": all_acl_lines,
                "used_pool": used_pool_name
            })

        return rules

    def rule_matches_query(self, rule, query: str) -> bool:
        if not query or query.lower() == "any":
            return True

        q = query.strip().lower()
        raw_line = rule["raw_line"].lower()

        # 1. Текстовое вхождение
        if q in raw_line:
            return True

        # 2. Интеллектуальная проверка IP / подсетей прямо в строке NAT (для Static NAT и др.)
        if self._line_contains_matching_ip(query, rule["raw_line"]):
            return True

        # 3. Проверка по связанному пулу (если правило использует пул и запрашиваемый IP/подсеть в него входит)
        if rule.get("used_pool") and rule["used_pool"] in self.pools:
            start_ip, end_ip = self.pools[rule["used_pool"]]
            if self._query_overlaps_ip_range(query, start_ip, end_ip):
                return True

        # 4. Проверка по содержимому связанных ACL
        acl_lines = rule.get("acl_lines", [])
        for acl_line in acl_lines:
            if q in acl_line.lower():
                return True
            if self._ip_matches_acl_line(query, acl_line):
                return True

        return False

    def _line_contains_matching_ip(self, query_str: str, line_str: str) -> bool:
        """Проверяет, пересекается ли запрашиваемая сеть/IP с любым IP-адресом, найденным в строке NAT"""
        try:
            query_net = ipaddress.ip_network(query_str, strict=False)
        except ValueError:
            return False

        words = line_str.split()
        for word in words:
            try:
                ip_obj = ipaddress.ip_address(word)
                ip_net = ipaddress.ip_network(str(ip_obj), strict=False)
                if query_net.overlaps(ip_net):
                    return True
            except ValueError:
                continue
        return False

    def _query_overlaps_ip_range(self, query_str: str, start_ip, end_ip) -> bool:
        """Проверяет, попадает ли диапазон пула под запрашиваемую сеть/IP"""
        try:
            query_net = ipaddress.ip_network(query_str, strict=False)
            curr = int(start_ip)
            end_val = int(end_ip)
            while curr <= end_val:
                ip_obj = ipaddress.ip_address(curr)
                ip_net = ipaddress.ip_network(str(ip_obj), strict=False)
                if query_net.overlaps(ip_net):
                    return True
                curr += 1
        except Exception:
            pass
        return False

    def _ip_matches_acl_line(self, query_ip_str: str, acl_line: str) -> bool:
        try:
            query_net = ipaddress.ip_network(query_ip_str, strict=False)
        except ValueError:
            return False

        words = acl_line.split()
        for i, word in enumerate(words):
            if word == "host" and i + 1 < len(words):
                try:
                    host_ip = ipaddress.ip_address(words[i + 1])
                    if query_net.overlaps(ipaddress.ip_network(str(host_ip))):
                        return True
                except ValueError:
                    continue
            else:
                try:
                    ip_obj = ipaddress.ip_address(word)
                    net_obj = None
                    if i + 1 < len(words):
                        next_word = words[i + 1]
                        if "." in next_word and not next_word.startswith("eq") and not next_word.startswith("range"):
                            try:
                                wildcard_bytes = [255 - int(b) for b in next_word.split('.')]
                                cidr_mask = sum(bin(b).count('1') for b in wildcard_bytes)
                                net_obj = ipaddress.ip_network(f"{word}/{cidr_mask}", strict=False)
                            except Exception:
                                pass

                    if not net_obj:
                        net_obj = ipaddress.ip_network(str(ip_obj), strict=False)

                    if query_net.overlaps(net_obj):
                        return True
                except ValueError:
                    continue
        return False


class CiscoFXOS_NAT_Parser:
    def __init__(self, config_text: str):
        self.config_text = config_text
        self.lines = config_text.splitlines()
        self.all_objects = self._parse_all_object_networks()
        self.object_groups = self._parse_object_groups()

    def _parse_all_object_networks(self):
        """Сбор одиночных объектов сети (как в ASA) для поддержки интеллектуального поиска"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object network"):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[2]
                    obj_items = []
                    j = i + 1
                    while j < len(self.lines) and self.lines[j].startswith(" "):
                        sub_line = self.lines[j].strip()
                        sub_parts = sub_line.split()
                        if sub_parts:
                            sub_cmd = sub_parts[0]
                            if sub_cmd == "host" and len(sub_parts) >= 2:
                                try:
                                    net = ipaddress.ip_network(f"{sub_parts[1]}/32", strict=False)
                                    obj_items.append(net)
                                except ValueError:
                                    pass
                            elif sub_cmd == "subnet" and len(sub_parts) >= 3:
                                try:
                                    net = ipaddress.IPv4Network((sub_parts[1], sub_parts[2]), strict=False)
                                    obj_items.append(net)
                                except ValueError:
                                    pass
                        j += 1
                    if obj_items:
                        objects[name] = obj_items
                    i = j - 1
            i += 1
        return objects

    def _parse_object_groups(self):
        """Сбор групп объектов сети (object-group network)"""
        ogroups = {}
        curr_og = None
        og_pat = re.compile(r'^\s*object-group\s+network\s+([^\s]+)', re.IGNORECASE)
        net_obj_pat = re.compile(r'^\s*network-object\s+(?:host\s+)?([^\s]+)(?:\s+([^\s]+))?', re.IGNORECASE)

        for line in self.lines:
            raw = line.strip()
            if og_m := og_pat.match(raw):
                curr_og = og_m.group(1)
                ogroups[curr_og] = []
                continue

            if curr_og:
                if net_m := net_obj_pat.match(raw):
                    ip_or_net = net_m.group(1)
                    mask = net_m.group(2)
                    try:
                        if mask:
                            net_str = f"{ip_or_net}/{mask}"
                            ogroups[curr_og].append(ipaddress.ip_network(net_str, strict=False))
                        else:
                            ip_obj = ipaddress.ip_address(ip_or_net)
                            ogroups[curr_og].append(ipaddress.ip_network(str(ip_obj), strict=False))
                    except ValueError:
                        pass
        return ogroups

    def _determine_detailed_type(self, line_str):
        """Строгое разделение на Standard NAT и Twice NAT с унифицированным форматом"""
        line_lower = line_str.lower()

        has_source = "source" in line_lower
        has_destination = "destination" in line_lower
        has_after_auto = "after-auto" in line_lower

        # Полноценный Twice NAT только если задействованы оба направления (source + destination)
        is_twice = has_source and has_destination

        if not is_twice:
            # Это Standard NAT (односторонний)
            base_type = "Standard NAT"
            if "source static" in line_lower:
                base_type = "Standard NAT (Static Source)"
            elif "source dynamic" in line_lower:
                base_type = "Standard NAT (Dynamic Source)"
            elif "dynamic" in line_lower:
                base_type = "Standard NAT (Dynamic Interface)"

            # Добавляем пометку after-auto, если она есть, но тип оставляем Standard
            if has_after_auto:
                base_type += " (After-Auto)"
            return base_type
        else:
            # Это настоящий Twice NAT (с destination)
            src_type = "Static Source" if "source static" in line_lower else (
                "Dynamic Source" if "source dynamic" in line_lower else None)
            dst_type = "Static Destination" if "destination static" in line_lower else (
                "Dynamic Destination" if "destination dynamic" in line_lower else None)

            sub_parts = [p for p in [src_type, dst_type] if p]
            base_type = f"Twice NAT ({' + '.join(sub_parts)})" if sub_parts else "Twice NAT"

            if has_after_auto:
                base_type += " (After-Auto)"
            return base_type
    def parse_all_nat_rules(self):
        rules = []
        nat_pat = re.compile(r'^\s*nat\s*\(([^,]+),\s*([^\)]+)\)\s*(.*)', re.IGNORECASE)

        for idx, line in enumerate(self.lines):
            raw = line.strip()
            if not raw or raw.startswith('!'):
                continue

            match = nat_pat.match(raw)
            if not match:
                continue

            real_iface = match.group(1).strip()
            mapped_iface = match.group(2).strip()

            # Собираем все упомянутые объекты/группы для поиска
            referenced_entities = []
            words = raw.split()
            for word in words:
                clean_w = word.strip('()[],;')
                if clean_w in self.all_objects or clean_w in self.object_groups:
                    referenced_entities.append(clean_w)

            rules.append({
                "line_number": idx + 1,
                "nat_type": self._determine_detailed_type(raw),
                "real_interface": real_iface,
                "mapped_interface": mapped_iface,
                "raw_line": raw,
                "referenced_entities": referenced_entities,
                "details": raw
            })

        return rules

    def rule_matches_query(self, rule, query_str):
        """Интеллектуальный поиск: текст, IP-адреса, подсети (с учетом объектов и групп объектов)"""
        if not query_str:
            return True

        query_lower = query_str.lower().strip()
        raw = rule.get("raw_line", "").lower()
        real_iface = rule.get("real_interface", "").lower()
        mapped_iface = rule.get("mapped_interface", "").lower()

        # 1. Поиск по IP / подсетям
        try:
            target_net = ipaddress.ip_network(query_lower, strict=False)

            # Проверяем связанные объекты сети
            for entity in rule.get("referenced_entities", []):
                if entity in self.all_objects:
                    for net in self.all_objects[entity]:
                        if target_net.overlaps(net) or target_net.subnet_of(net):
                            return True
                if entity in self.object_groups:
                    for net in self.object_groups[entity]:
                        if target_net.overlaps(net) or target_net.subnet_of(net):
                            return True

            # Проверяем IP в самой строке NAT
            for word in raw.split():
                clean_word = word.strip("()=,;")
                if clean_word in self.all_objects:
                    for net in self.all_objects[clean_word]:
                        if target_net.overlaps(net) or target_net.subnet_of(net):
                            return True
                try:
                    word_ip = ipaddress.ip_network(clean_word, strict=False)
                    if target_net.overlaps(word_ip):
                        return True
                except ValueError:
                    pass

            return False
        except ValueError:
            pass

        # 2. Обычный текстовый поиск
        if (query_lower == real_iface) or (query_lower == mapped_iface) or (query_lower in raw):
            return True

        return False


class Fortigate_NAT_Parser:
    def __init__(self, config_text: str):
        self.config_text = config_text
        self.lines = config_text.splitlines()
        self.services = self._parse_firewall_services()

    def _parse_firewall_services(self):
        """Парсит как кастомные сервисы, так и группы сервисов Fortinet"""
        services = {}
        service_groups = {}
        i = 0
        n = len(self.lines)

        while i < n:
            raw = self.lines[i].strip()

            # 1. Парсим кастомные сервисы
            if raw.startswith("config firewall service custom"):
                i += 1
                while i < n:
                    line = self.lines[i].strip()
                    if line.startswith("end"):
                        break
                    if line.startswith("edit"):
                        svc_name = line.split(maxsplit=1)[1].strip('"\'').lower()
                        svc_ports = {"tcp": [], "udp": []}

                        j = i + 1
                        while j < n:
                            sub_line = self.lines[j].strip()
                            if sub_line == "next" or sub_line.startswith("edit") or sub_line.startswith("end"):
                                break

                            # ИСПРАВЛЕНИЕ: берем порты начиная с индекса 2 (пропуская 'set' и 'tcp-portrange')
                            if "tcp-portrange" in sub_line.lower():
                                parts = sub_line.split()
                                if len(parts) > 2:
                                    svc_ports["tcp"].extend(parts[2:])

                            if "udp-portrange" in sub_line.lower():
                                parts = sub_line.split()
                                if len(parts) > 2:
                                    svc_ports["udp"].extend(parts[2:])

                            j += 1
                        services[svc_name] = svc_ports
                        i = j - 1
                    i += 1

            # 2. Парсим группы сервисов (service group)
            elif raw.startswith("config firewall service group"):
                i += 1
                while i < n:
                    line = self.lines[i].strip()
                    if line.startswith("end"):
                        break
                    if line.startswith("edit"):
                        group_name = line.split(maxsplit=1)[1].strip('"\'').lower()
                        members = []

                        j = i + 1
                        while j < n:
                            sub_line = self.lines[j].strip()
                            if sub_line == "next" or sub_line.startswith("edit") or sub_line.startswith("end"):
                                break
                            if "set member" in sub_line.lower():
                                members = [m.strip('"\'').lower() for m in sub_line.split()[2:]]
                            j += 1
                        service_groups[group_name] = members
                        i = j - 1
                    i += 1
            i += 1

        self.service_groups = service_groups
        return services
    def _get_service_ports(self, svc_name: str, visited=None):
        """Рекурсивно получает порты для сервиса или группы сервисов"""
        if visited is None:
            visited = set()
        svc_lower = svc_name.lower()
        if svc_lower in visited:
            return {"tcp": [], "udp": []}
        visited.add(svc_lower)

        combined = {"tcp": [], "udp": []}

        # Если это прямой кастомный сервис
        if svc_lower in self.services:
            for proto in ["tcp", "udp"]:
                combined[proto].extend(self.services[svc_lower][proto])

        # Если это группа сервисов, обходим ее участников рекурсивно
        elif svc_lower in self.service_groups:
            for member in self.service_groups[svc_lower]:
                sub_ports = self._get_service_ports(member, visited)
                combined["tcp"].extend(sub_ports["tcp"])
                combined["udp"].extend(sub_ports["udp"])

        return combined

    def parse_all_nat_rules(self):
        rules = []
        i = 0
        n = len(self.lines)

        while i < n:
            raw_line = self.lines[i].strip()

            if raw_line.startswith("config firewall vip") or \
                    raw_line.startswith("config firewall central-snat-map"):

                section_type_base = raw_line.split()[-1]
                i += 1

                while i < n:
                    line = self.lines[i].strip()
                    if line.startswith("end"):
                        break

                    if line.startswith("edit"):
                        block_lines = [line]
                        is_disabled = False

                        j = i + 1
                        while j < n:
                            sub_line = self.lines[j].strip()
                            if sub_line == "next" or sub_line.startswith("edit") or sub_line.startswith("end"):
                                break

                            if sub_line.startswith("set status disable"):
                                is_disabled = True

                            if "set uuid" in sub_line.lower():
                                j += 1
                                continue

                            block_lines.append(sub_line)
                            j += 1

                        if not is_disabled and len(block_lines) > 1:
                            block_text = "\n".join(block_lines)

                            if section_type_base == "vip":
                                if "portforward enable" in block_text.lower():
                                    nat_type = "Fortinet VIP (Port Forwarding / DNAT)"
                                else:
                                    nat_type = "Fortinet VIP (Static DNAT)"
                                real_iface = "outside"
                                mapped_iface = "inside"
                            elif section_type_base == "central-snat-map":
                                nat_type = "Fortinet Central SNAT"
                                real_iface = "inside"
                                mapped_iface = "outside"
                            else:
                                nat_type = "Fortinet NAT Rule"
                                real_iface = "inside"
                                mapped_iface = "outside"

                            rules.append({
                                "line_number": i + 1,
                                "nat_type": nat_type,
                                "real_interface": real_iface,
                                "mapped_interface": mapped_iface,
                                "raw_line": block_text,
                                "details": block_text
                            })

                        i = j - 1
                    i += 1
            i += 1

        return rules

    def rule_matches_query(self, rule, query_str: str) -> bool:
        """Интеллектуальный поиск: игнорируем комментарии, проверяем только реальные параметры"""
        if not query_str or query_str.lower() == "any":
            return True

        query_lower = query_str.lower().strip()
        raw_lines = rule.get("raw_line", "").splitlines()

        # Исключаем строки с комментариями из анализа для поиска по портам и IP
        clean_lines = [line for line in raw_lines if not line.strip().startswith("set comment")]
        clean_block_text = "\n".join(clean_lines).lower()

        # 1. Проверяем запрос по порту (tcp/..., udp/... или точный порт)
        is_port_query = False
        target_proto = None
        target_port = None

        if "/" in query_lower and not any(c in query_lower for c in ". "):
            parts = query_lower.split("/")
            if len(parts) == 2 and parts[0] in ["tcp", "udp"] and parts[1].isdigit():
                target_proto = parts[0]
                target_port = int(parts[1])
                is_port_query = True
        elif query_lower.isdigit():
            target_port = int(query_lower)
            is_port_query = True

        if is_port_query:
            words = clean_block_text.replace('"', ' ').replace("'", ' ').split()
            match_found = False

            # Проверяем сервисы и группы сервисов (без учета комментариев!)
            for word in words:
                if word in self.services or word in self.service_groups:
                    svc_data = self._get_service_ports(word)
                    for proto, ranges in svc_data.items():
                        if target_proto and proto != target_proto:
                            continue
                        for r in ranges:
                            if self._port_in_range(target_port, r):
                                match_found = True
                                break
                    if match_found:
                        break

            # Проверяем явные поля портов в правиле (extport / mappedport)
            if not match_found:
                port_keywords = ["extport", "mappedport", "portforward"]
                for i, word in enumerate(words):
                    if any(kw in words[max(0, i - 2):i + 1] for kw in port_keywords):
                        if word.isdigit() and int(word) == target_port:
                            match_found = True
                            break

            return match_found

        # 2. Проверка по IP / подсетям (тоже по очищенному тексту без комментариев)
        try:
            target_net = ipaddress.ip_network(query_lower, strict=False)
            words = clean_block_text.replace('"', ' ').replace("'", ' ').split()
            for word in words:
                try:
                    word_net = ipaddress.ip_network(word, strict=False)
                    if target_net.overlaps(word_net):
                        return True
                except ValueError:
                    continue
            return False
        except ValueError:
            pass

        # 3. Общий текстовый поиск (для имен объектов, интерфейсов и т.д.)
        if query_lower in clean_block_text:
            return True

        return False
    def _port_in_range(self, port: int, range_str: str) -> bool:
        """Проверяет, входит ли порт в диапазон или список (поддерживает '53', '80-90', '7003')"""
        try:
            if "-" in range_str:
                p_start, p_end = map(int, range_str.split("-"))
                return p_start <= port <= p_end
            else:
                return int(range_str) == port
        except ValueError:
            return False



class Juniper_NAT_Parser:
    def __init__(self, config_text: str):
        self.config_text = config_text
        self.lines = config_text.splitlines()
        self.pools = self._parse_juniper_pools()

    def _parse_juniper_pools(self):
        """Парсит пулы Juniper (source/destination pools) для использования в поиске, но не выводит их как правила"""
        pools = {}
        curr_pool = None
        i = 0
        n = len(self.lines)

        while i < n:
            line = self.lines[i].strip()
            # Ищем объявления pool имя_пула {
            if line.startswith("pool ") and line.endswith("{"):
                curr_pool = line.split()[1]
                pools[curr_pool] = []
                i += 1
                brace_count = 1
                while i < n and brace_count > 0:
                    sub_line = self.lines[i].strip()
                    if "{" in sub_line:
                        brace_count += sub_line.count("{")
                    if "}" in sub_line:
                        brace_count -= sub_line.count("}")
                        if brace_count <= 0:
                            break

                    # Ищем IP-адреса внутри адресов пула
                    parts = sub_line.replace(";", "").split()
                    for p in parts:
                        try:
                            net = ipaddress.ip_network(p, strict=False)
                            pools[curr_pool].append(net)
                        except ValueError:
                            pass
                    i += 1
            i += 1
        return pools

    def parse_all_nat_rules(self):
        """Парсит rule-set и отдельные правила NAT в Juniper"""
        rules = []
        i = 0
        n = len(self.lines)

        current_rule_set = None
        rule_set_from = "inside"
        rule_set_to = "outside"

        while i < n:
            line = self.lines[i].strip()

            # Отслеживаем rule-set
            if line.startswith("rule-set ") and line.endswith("{"):
                current_rule_set = line.split()[1]
                rule_set_from = "inside"
                rule_set_to = "outside"
                i += 1
                brace_count = 1

                # Парсим содержимое rule-set
                while i < n and brace_count > 0:
                    sub_line = self.lines[i].strip()

                    if sub_line.startswith("from "):
                        rule_set_from = sub_line.replace("from", "").replace(";", "").strip()
                    elif sub_line.startswith("to "):
                        rule_set_to = sub_line.replace("to", "").replace(";", "").strip()

                    if "{" in sub_line:
                        brace_count += sub_line.count("{")
                    if "}" in sub_line:
                        brace_count -= sub_line.count("}")
                        if brace_count <= 0:
                            break

                    # Находим отдельное правилонутри rule-set: rule имя_правила {
                    if sub_line.startswith("rule ") and sub_line.endswith("{"):
                        rule_name = sub_line.split()[1]
                        rule_block_lines = [sub_line]

                        r_idx = i + 1
                        r_brace = 1
                        while r_idx < n and r_brace > 0:
                            r_line = self.lines[r_idx].strip()
                            if "{" in r_line:
                                r_brace += r_line.count("{")
                            if "}" in r_line:
                                r_brace -= r_line.count("}")
                                if r_brace <= 0:
                                    rule_block_lines.append(r_line)
                                    break
                            rule_block_lines.append(r_line)
                            r_idx += 1

                        block_text = "\n".join(rule_block_lines)
                        block_lower = block_text.lower()

                        # Определяем тип NAT и направление
                        if "destination-nat" in block_lower:
                            nat_type = "Juniper Destination NAT"
                            real_interface = "outside"
                            mapped_interface = "inside"
                        elif "source-nat" in block_lower:
                            nat_type = "Juniper Source NAT"
                            real_interface = "inside"
                            mapped_interface = "outside"
                        elif "static-nat" in block_lower:
                            nat_type = "Juniper Static NAT"
                            real_interface = "outside"
                            mapped_interface = "inside"
                        else:
                            nat_type = "Juniper NAT Rule"
                            real_interface = rule_set_from
                            mapped_interface = rule_set_to

                        rules.append({
                            "line_number": i + 1,
                            "nat_type": nat_type,
                            "real_interface": real_interface,
                            "mapped_interface": mapped_interface,
                            "raw_line": block_text,
                            "details": block_text
                        })

                        i = r_idx
                    i += 1
            i += 1

        return rules

    def rule_matches_query(self, rule, query_str: str) -> bool:
        """Интеллектуальный поиск для Juniper (текст, подсети/IP с учетом пулов, порты)"""
        if not query_str or query_str.lower() == "any":
            return True

        query_lower = query_str.lower().strip()
        block_text = rule.get("raw_line", "").lower()

        # 1. Поиск по портам (например, tcp/3389 или просто 3389)
        is_port_query = False
        target_proto = None
        target_port = None

        if "/" in query_lower and not any(c in query_lower for c in ". "):
            parts = query_lower.split("/")
            if len(parts) == 2 and parts[0] in ["tcp", "udp"] and parts[1].isdigit():
                target_proto = parts[0]
                target_port = int(parts[1])
                is_port_query = True
        elif query_lower.isdigit():
            target_port = int(query_lower)
            is_port_query = True

        if is_port_query:
            # Проверяем протокол, если задан
            if target_proto and target_proto not in block_text:
                return False

            # Ищем числовой порт в блоке правила (например, в destination-port)
            words = block_text.replace('[', ' ').replace(']', ' ').replace(';', ' ').split()
            for i, word in enumerate(words):
                if word.isdigit() and int(word) == target_port:
                    return True
            return False

        # 2. Поиск по IP / подсетям (включая проверку через упомянутые пулы)
        try:
            target_net = ipaddress.ip_network(query_lower, strict=False)

            # Проверяем пулы, если они упомянуты в тексте правила
            for pool_name, nets in self.pools.items():
                if pool_name.lower() in block_text:
                    for net in nets:
                        if target_net.overlaps(net):
                            return True

            # Проверяем адреса прямо в тексте правила (включая списки в квадратных скобках)
            words = block_text.replace('[', ' ').replace(']', ' ').replace(';', ' ').split()
            for word in words:
                try:
                    word_net = ipaddress.ip_network(word, strict=False)
                    if target_net.overlaps(word_net):
                        return True
                except ValueError:
                    pass
            return False
        except ValueError:
            pass

        # 3. Общий текстовый поиск (имена правил, пулов, интерфейсы)
        if query_lower in block_text:
            return True

        return False



class Huawei_NAT_Parser:
    def __init__(self, config_text: str):
        self.config_text = config_text
        self.lines = config_text.splitlines()

    def parse_all_nat_rules(self):
        rules = []
        i = 0
        n = len(self.lines)

        while i < n:
            raw_line = self.lines[i].strip()

            # Пропускаем пустые строки, комментарии и заведомо нерелевантный системный мусор
            if not raw_line or raw_line.startswith('#') or \
                    raw_line.startswith("ip route-static") or \
                    raw_line.startswith("proxy-policy") or \
                    raw_line.startswith("pcp-policy") or \
                    raw_line.startswith("firewall zone") or \
                    raw_line == "aaa" or \
                    raw_line.startswith("ikev") or raw_line.startswith("ipsec"):
                i += 1
                continue

            # 1. Каждая команда "nat server" — это самостоятельное правило DNAT
            if raw_line.startswith("nat server"):
                rules.append({
                    "line_number": i + 1,
                    "nat_type": "Huawei NAT Server (DNAT)",
                    "real_interface": "outside",
                    "mapped_interface": "inside",
                    "raw_line": raw_line,
                    "details": raw_line
                })
                i += 1
                continue

            # 2. Обработка правил политик NAT (rule name ...)
            if raw_line.startswith("rule name"):
                rule_lines = [raw_line]
                is_disabled = False
                has_nat_action = False

                src_zone = "inside"
                dst_zone = "outside"

                j = i + 1
                while j < n:
                    sub_line = self.lines[j].strip()

                    # Если встретили границу следующего правила, пустую строку или блок — останавливаемся
                    if sub_line.startswith("rule name") or sub_line.startswith("#") or \
                            sub_line.startswith("nat server") or sub_line.startswith("interface") or \
                            sub_line.startswith("ip route-static"):
                        break

                    if sub_line == "disable":
                        is_disabled = True

                    if sub_line.startswith("source-zone"):
                        parts = sub_line.split()
                        if len(parts) > 1:
                            src_zone = parts[1]

                    if sub_line.startswith("destination-zone"):
                        parts = sub_line.split()
                        if len(parts) > 1:
                            dst_zone = parts[1]

                    if "action nat" in sub_line:
                        has_nat_action = True

                    rule_lines.append(sub_line)
                    j += 1

                block_text = "\n".join(rule_lines)

                # Учитываем только активные правила, у которых есть реальный NAT (action nat ...)
                if not is_disabled and has_nat_action:
                    if "easy-ip" in block_text:
                        nat_type = "Huawei NAT (Easy IP / SNAT)"
                    elif "address-group" in block_text:
                        nat_type = "Huawei NAT (Address Group / SNAT)"
                    else:
                        nat_type = "Huawei NAT Policy"

                    rules.append({
                        "line_number": i + 1,
                        "nat_type": nat_type,
                        "real_interface": src_zone,
                        "mapped_interface": dst_zone,
                        "raw_line": block_text,
                        "details": block_text
                    })

                i = j - 1
            i += 1

        return rules

    def rule_matches_query(self, rule, query_str: str) -> bool:
        """Интеллектуальный поиск для Huawei (текст, IP с масками, порты)"""
        if not query_str or query_str.lower() == "any":
            return True

        query_lower = query_str.lower().strip()
        block_text = rule.get("raw_line", "").lower()

        # 1. Текстовый поиск (если не порт и не IP)
        if "/" not in query_lower and not query_lower.isdigit():
            if query_lower in block_text:
                return True

        # 2. Поиск по порту
        is_port_query = False
        target_port = None
        if "/" in query_lower and not any(c in query_lower for c in ". "):
            parts = query_lower.split("/")
            if len(parts) == 2 and parts[1].isdigit():
                target_port = int(parts[1])
                is_port_query = True
        elif query_lower.isdigit():
            target_port = int(query_lower)
            is_port_query = True

        if is_port_query:
            words = block_text.replace(";", "").split()
            for w in words:
                if w.isdigit() and int(w) == target_port:
                    return True
            return False

        # 3. Поиск по IP / подсетям (с учетом масок Huawei вида ip mask)
        try:
            target_net = ipaddress.ip_network(query_lower, strict=False)
            tokens = block_text.replace("mask", "").split()
            i = 0
            while i < len(tokens):
                token = tokens[i]
                try:
                    net = ipaddress.ip_network(token, strict=False)
                    if target_net.overlaps(net):
                        return True
                except ValueError:
                    if i + 1 < len(tokens):
                        try:
                            masked_str = f"{token}/{tokens[i + 1]}"
                            net = ipaddress.ip_network(masked_str, strict=False)
                            if target_net.overlaps(net):
                                return True
                        except ValueError:
                            pass
                i += 1
            return False
        except ValueError:
            pass

        return False



class Eltex_NAT_Parser:
    def __init__(self, config_text: str):
        self.config_text = config_text
        self.lines = config_text.splitlines()
        self.net_objects, self.net_groups = self._parse_eltex_objects()
        self.pools = self._parse_eltex_pools()

    def _parse_eltex_objects(self):
        """Парсит многострочные сетевые объекты и группы объектов Eltex ESR"""
        objects = {}
        groups = {}
        i = 0
        n = len(self.lines)

        while i < n:
            line = self.lines[i].strip()
            if line.startswith("object-group network"):
                parts = line.split()
                if len(parts) >= 3:
                    obj_name = parts[2].lower()  # Приводим к lower для точного поиска
                elif len(parts) == 2:
                    obj_name = parts[1].lower()
                else:
                    i += 1
                    continue

                nets = []
                tokens = line.replace(";", "").split()
                for idx, t in enumerate(tokens):
                    if t in ["ip", "prefix"] and idx + 1 < len(tokens):
                        try:
                            net = ipaddress.ip_network(tokens[idx + 1], strict=False)
                            nets.append(net)
                        except ValueError:
                            pass

                # Читаем тело объекта до 'exit' или следующего блока
                j = i + 1
                while j < n:
                    sub_line = self.lines[j].strip()
                    if sub_line == "exit" or sub_line.startswith("object-group") or sub_line.startswith("nat source"):
                        break

                    sub_tokens = sub_line.replace(";", "").split()
                    for idx, t in enumerate(sub_tokens):
                        if t in ["ip", "prefix"] and idx + 1 < len(sub_tokens):
                            try:
                                net = ipaddress.ip_network(sub_tokens[idx + 1], strict=False)
                                nets.append(net)
                            except ValueError:
                                pass
                    j += 1

                if nets:
                    objects[obj_name] = nets
                    groups[obj_name] = nets
                i = j
            i += 1
        return objects, groups

    def _parse_eltex_pools(self):
        """Парсит пулы nat source"""
        pools = {}
        curr_pool = None
        in_nat_source = False

        for line in self.lines:
            line_str = line.strip()
            if line_str.startswith("nat source"):
                in_nat_source = True
                continue
            if in_nat_source and line_str == "exit" and not curr_pool:
                break

            if in_nat_source:
                if line_str.startswith("pool ") and "{" in line_str:
                    curr_pool = line_str.split()[1].lower()
                    pools[curr_pool] = []
                elif curr_pool:
                    if line_str == "}":
                        curr_pool = None
                    else:
                        parts = line_str.replace(";", "").split()
                        for p in parts:
                            try:
                                net = ipaddress.ip_network(p, strict=False)
                                pools[curr_pool].append(net)
                            except ValueError:
                                pass
        return pools

    def parse_all_nat_rules(self):
        """Надежный парсер правил nat source в Eltex ESR"""
        rules = []
        i = 0
        n = len(self.lines)
        in_nat_source = False

        while i < n:
            line = self.lines[i].strip()

            if line.startswith("nat source"):
                in_nat_source = True
                i += 1
                continue

            if in_nat_source and line.startswith("rule "):
                rule_lines = [line]
                is_enabled = False

                j = i + 1
                while j < n:
                    sub_line = self.lines[j].strip()
                    if sub_line == "enable":
                        is_enabled = True
                    rule_lines.append(sub_line)
                    if sub_line == "exit":
                        break
                    j += 1

                block_text = "\n".join(rule_lines)
                block_lower = block_text.lower()

                # Учитываем только включенные правила без disable
                if is_enabled and "disable" not in block_lower:
                    if "netmap" in block_lower:
                        nat_type = "Eltex Source NAT (Netmap)"
                    elif "off" in block_lower:
                        nat_type = "Eltex Source NAT (Bypass / Off)"
                    elif "interface" in block_lower:
                        nat_type = "Eltex Source NAT (Interface / Overload)"
                    else:
                        nat_type = "Eltex Source NAT Rule"

                    rules.append({
                        "line_number": i + 1,
                        "nat_type": nat_type,
                        "real_interface": "inside",
                        "mapped_interface": "outside",
                        "raw_line": block_text,
                        "details": block_text
                    })

                i = j
            i += 1

        return rules

    def rule_matches_query(self, rule, query_str: str) -> bool:
        """Интеллектуальный поиск для Eltex ESR с распаковкой объектов и подсетей"""
        if not query_str or query_str.lower() == "any":
            return True

        query_lower = query_str.lower().strip()
        block_text = rule.get("raw_line", "").lower()

        # 1. Поиск по порту
        if "/" not in query_lower and query_lower.isdigit():
            target_port = int(query_lower)
            words = block_text.replace(";", "").split()
            for w in words:
                if w.isdigit() and int(w) == target_port:
                    return True

        # 2. Поиск по IP / подсетям с распаковкой объектов, групп и пулов
        try:
            target_net = ipaddress.ip_network(query_lower, strict=False)
            words = block_text.replace(";", "").split()

            for word in words:
                if word in self.net_groups:
                    for net in self.net_groups[word]:
                        if target_net.overlaps(net):
                            return True
                if word in self.net_objects:
                    for net in self.net_objects[word]:
                        if target_net.overlaps(net):
                            return True
                if word in self.pools:
                    for net in self.pools[word]:
                        if target_net.overlaps(net):
                            return True

            for word in words:
                try:
                    net = ipaddress.ip_network(word, strict=False)
                    if target_net.overlaps(net):
                        return True
                except ValueError:
                    pass
            return False
        except ValueError:
            pass

        # 3. Общий текстовый поиск
        if query_lower in block_text:
            return True

        return False


# =====
# классы детализации.

from unpack_nat_parser import CiscoASA_NAT_Parser
from unpack_group_parser import CiscoFirepowerParserSVC


class Detail_FXOS_Parser:
    def __init__(self, config_text: str):
        self.config_text = config_text
        self.nat_parser = CiscoASA_NAT_Parser(config_text)
        # Подключаем специализированный парсер объектов и групп FXOS/Firepower
        self.group_parser = CiscoFirepowerParserSVC(config_text)

    def get_details(self, line_num: int):
        all_rules = []
        try:
            if hasattr(self.nat_parser, "parse_all_nat_rules"):
                all_rules = self.nat_parser.parse_all_nat_rules()
        except Exception:
            pass

        # Ищем целевое правило по номеру строки
        target_rule = None
        for r in all_rules:
            if r.get("line_number") == line_num or r.get("line") == line_num or r.get("index") == line_num:
                target_rule = r
                break

        if not target_rule and all_rules:
            idx = line_num - 1
            if 0 <= idx < len(all_rules):
                target_rule = all_rules[idx]
            else:
                target_rule = all_rules[0]

        raw_line = ""
        if target_rule:
            raw_line = target_rule.get("raw_line") or target_rule.get("details") or ""

        if not raw_line and self.config_text:
            lines = self.config_text.splitlines()
            if 0 <= line_num - 1 < len(lines):
                raw_line = lines[line_num - 1].strip()

        real_interface, mapped_interface = "", ""
        intf_match = re.search(r'nat\s*\(([^,]+),\s*([^)]+)\)', raw_line)
        if intf_match:
            real_interface = intf_match.group(1).strip()
            mapped_interface = intf_match.group(2).strip()

        src_orig, src_trans, dst_orig, dst_trans = "", "", "", ""
        try:
            if target_rule:
                src_orig = target_rule.get("src_orig", "")
                src_trans = target_rule.get("src_trans", "")
                dst_orig = target_rule.get("dst_orig", "")
                dst_trans = target_rule.get("dst_trans", "")

            # Учитываем after-auto / manual и ключевые слова Twice NAT
            if not src_orig:
                src_match = re.search(r'source\s+(?:static|dynamic|after-auto)\s+(\S+)(?:\s+(\S+))?', raw_line)
                if src_match:
                    src_orig = src_match.group(1) or ""
                    src_trans = src_match.group(2) or ""

            if not dst_orig:
                dst_match = re.search(r'destination\s+(?:static|dynamic)\s+(\S+)\s+(\S+)', raw_line)
                if dst_match:
                    dst_orig = dst_match.group(1) or ""
                    dst_trans = dst_match.group(2) or ""
        except Exception:
            pass

        # Функция рекурсивной распаковки объектов и групп через CiscoFirepowerParserSVC
        def resolve_obj(obj_name, is_translated_side=False):
            obj_str = str(obj_name).strip()

            # Если это ключевое слово any или явно указан прочерк — выводим как есть
            if obj_str.lower() in ["any", "—", "-"]:
                return [obj_str]

            if obj_str.lower() == "interface" or not obj_str:
                if is_translated_side and mapped_interface:
                    return [f"dynamic interface ({mapped_interface})"]
                return [obj_str if obj_str else "—"]

            if not self.group_parser or not hasattr(self.group_parser, "get_object_group"):
                return [obj_str]

            # Получаем элементы объекта или object-group через встроенный метод парсера
            unpacked = self.group_parser.get_object_group(obj_str)
            if not unpacked:
                return [obj_str]

            res = []
            for item in unpacked:
                if isinstance(item, dict):
                    # Обработка вложенных ссылок на объекты внутри групп
                    if item.get("type") == "object_ref":
                        sub_name = item.get("name")
                        sub_unpacked = self.group_parser.get_object_group(sub_name)
                        for sub_item in sub_unpacked:
                            if isinstance(sub_item, dict):
                                net_val = sub_item.get("network") or sub_item.get("text") or sub_item.get("ip")
                                res.append(str(net_val) if net_val else str(sub_item))
                            else:
                                res.append(str(sub_item))
                    else:
                        net_val = item.get("network") or item.get("text") or item.get("ip")
                        res.append(str(net_val) if net_val else str(item))
                else:
                    res.append(str(item))
            return res if res else [obj_str]

        def format_block(unpacked_list):
            if not unpacked_list:
                return "—"
            clean_lines = [str(x).strip() for x in unpacked_list if str(x).strip()]
            return "\n".join(clean_lines) if clean_lines else "—"

        return {
            "forms": {
                "pre_snat": format_block(resolve_obj(src_orig, is_translated_side=False)),
                "post_snat": format_block(resolve_obj(src_trans, is_translated_side=True)),
                "pre_dnat": format_block(resolve_obj(dst_trans, is_translated_side=False)),
                "post_dnat": format_block(resolve_obj(dst_orig, is_translated_side=False))
            }
        }


import re
from unpack_nat_parser import CiscoASA_NAT_Parser
from unpack_group_parser import CiscoASAParserSVC  # Импортируем ваш сервисный класс для ASA


class Detail_ASA_Parser:
    def __init__(self, config_text: str):
        self.config_text = config_text
        self.nat_parser = CiscoASA_NAT_Parser(config_text)
        # Подключаем специализированный парсер объектов/групп для ASA
        self.group_parser = CiscoASAParserSVC(config_text)

    def get_details(self, line_num: int):
        all_rules = []
        try:
            if hasattr(self.nat_parser, "parse_all_nat_rules"):
                all_rules = self.nat_parser.parse_all_nat_rules()
        except Exception:
            pass

        # Ищем целевое правило по номеру строки
        target_rule = None
        for r in all_rules:
            if r.get("line_number") == line_num or r.get("line") == line_num or r.get("index") == line_num:
                target_rule = r
                break

        if not target_rule and all_rules:
            idx = line_num - 1
            if 0 <= idx < len(all_rules):
                target_rule = all_rules[idx]
            else:
                target_rule = all_rules[0]

        raw_line = ""
        if target_rule:
            raw_line = target_rule.get("raw_line") or target_rule.get("details") or ""

        if not raw_line and self.config_text:
            lines = self.config_text.splitlines()
            if 0 <= line_num - 1 < len(lines):
                raw_line = lines[line_num - 1].strip()

        real_interface, mapped_interface = "", ""
        intf_match = re.search(r'nat\s*\(([^,]+),\s*([^)]+)\)', raw_line)
        if intf_match:
            real_interface = intf_match.group(1).strip()
            mapped_interface = intf_match.group(2).strip()

        src_orig, src_trans, dst_orig, dst_trans = "", "", "", ""

        try:
            # 1. Классический Twice NAT (содержит source или destination)
            if target_rule and ("source" in raw_line.lower() or "destination" in raw_line.lower()):
                src_orig = target_rule.get("src_orig", "")
                src_trans = target_rule.get("src_trans", "")
                dst_orig = target_rule.get("dst_orig", "")
                dst_trans = target_rule.get("dst_trans", "")

                if not src_orig:
                    src_match = re.search(r'source\s+(?:static|dynamic|after-auto)\s+(\S+)(?:\s+(\S+))?', raw_line)
                    if src_match:
                        src_orig = src_match.group(1) or ""
                        src_trans = src_match.group(2) or ""

                if not dst_orig:
                    dst_match = re.search(r'destination\s+(?:static|dynamic)\s+(\S+)\s+(\S+)', raw_line)
                    if dst_match:
                        dst_orig = dst_match.group(1) or ""
                        dst_trans = dst_match.group(2) or ""

            # 2. Короткий Object NAT / PAT (внутри object network)
                    # 2. Короткий Object NAT / PAT (внутри object network)
            else:
                        obj_name = ""
                        if target_rule:
                            obj_name = target_rule.get("object_name", "") or target_rule.get("name", "")

                        if not obj_name and self.config_text:
                            lines = self.config_text.splitlines()
                            for i in range(max(0, line_num - 1), -1, -1):
                                line_str = lines[i].strip()
                                if line_str.startswith("object network"):
                                    parts_obj = line_str.split()
                                    if len(parts_obj) >= 3:
                                        obj_name = parts_obj[2]
                                        break
                                if line_str.startswith("nat (") or line_str.startswith("access-list"):
                                    break

                        # Original Source — это имя объекта (например, подсеть 10.144.251.0/24),
                        # которое функция resolve_obj красиво распакует через group_parser
                        src_orig = obj_name if obj_name else (
                            f"interface ({real_interface})" if real_interface else "interface")

                        # Translated Source — то, что идет после слова static или dynamic
                        parts = raw_line.split()
                        try:
                            if "static" in raw_line.lower():
                                static_idx = parts.index("static")
                                if static_idx + 1 < len(parts):
                                    trans_ip = parts[static_idx + 1]
                                    if "service" in raw_line.lower():
                                        s_idx = parts.index("service")
                                        if s_idx + 3 < len(parts):
                                            proto = parts[s_idx + 1]
                                            port_trans = parts[s_idx + 3]
                                            src_trans = f"{trans_ip}:{port_trans} ({proto})"
                                        else:
                                            src_trans = trans_ip
                                    else:
                                        src_trans = trans_ip
                            elif "dynamic" in raw_line.lower():
                                dyn_idx = parts.index("dynamic")
                                if dyn_idx + 1 < len(parts):
                                    src_trans = parts[dyn_idx + 1]  # Здесь подтянется 83.239.46.162
                        except Exception:
                            pass
        except Exception:
            pass

        # Функция рекурсивной распаковки объектов и групп через CiscoASAParserSVC
            # Функция рекурсивной распаковки объектов и групп через CiscoASAParserSVC
        def resolve_obj(obj_name, is_translated_side=False):
                obj_str = str(obj_name).strip()

                if obj_str.lower() in ["any", "—", "-"]:
                    return [obj_str]

                if obj_str.lower() == "interface" or not obj_str:
                    if is_translated_side and mapped_interface:
                        return [f"dynamic interface ({mapped_interface})"]
                    return [obj_str if obj_str else "—"]

                if not self.group_parser or not hasattr(self.group_parser, "get_object_group"):
                    return [obj_str]

                unpacked = self.group_parser.get_object_group(obj_str)
                if not unpacked:
                    return [obj_str]

                res = []
                for item in unpacked:
                    if isinstance(item, dict):
                        # Безусловно игнорируем любые элементы, содержащие строки nat (...)
                        text_val = str(item.get("text", "")).strip()
                        if text_val.startswith("nat ("):
                            continue

                        if item.get("type") == "object_ref":
                            sub_name = item.get("name")
                            sub_unpacked = self.group_parser.get_object_group(sub_name)
                            for sub_item in sub_unpacked:
                                if isinstance(sub_item, dict):
                                    sub_text = str(sub_item.get("text", "")).strip()
                                    if sub_text.startswith("nat ("):
                                        continue
                                    net_val = sub_item.get("network") or sub_item.get("text") or sub_item.get("ip")
                                    res.append(str(net_val) if net_val else str(sub_item))
                                else:
                                    res.append(str(sub_item))
                        else:
                            net_val = item.get("network") or item.get("text") or item.get("ip")
                            res.append(str(net_val) if net_val else str(item))
                    else:
                        item_str = str(item).strip()
                        if not item_str.startswith("nat ("):
                            res.append(item_str)
                return res if res else [obj_str]
        def format_block(unpacked_list):
            if not unpacked_list:
                return "—"
            clean_lines = [str(x).strip() for x in unpacked_list if str(x).strip()]
            return "\n".join(clean_lines) if clean_lines else "—"

        return {
            "forms": {
                "pre_snat": format_block(resolve_obj(src_orig, is_translated_side=False)),
                "post_snat": format_block(resolve_obj(src_trans, is_translated_side=True)),
                "pre_dnat": format_block(resolve_obj(dst_trans, is_translated_side=False)),
                "post_dnat": format_block(resolve_obj(dst_orig, is_translated_side=False))
            }
        }