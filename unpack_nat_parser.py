import ipaddress


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
                        print(f"[PARSER OBJECTS] Объект '{name}' содержит сети: {[str(n) for n in obj_items]}")
                    i = j - 1
            i += 1
        return objects

    def parse_all_nat_rules(self):
        rules = []
        for idx, line in enumerate(self.lines):
            line_str = line.strip()

            # 1. Обрабатываем глобальные Twice NAT (которые содержат source или destination)
            if line_str.startswith("nat ("):
                if "source" in line_str or "destination" in line_str:
                    rule_info = self._parse_twice_nat_line(line_str, idx + 1)
                    if rule_info:
                        rules.append(rule_info)
                # Внимание: «голые» строки nat (...) вне блоков объектов мы теперь намеренно игнорируем,
                # так как они дублируют правила из object network и не содержат информации об исходном IP/объекте.

            # 2. Обрабатываем Object NAT строго внутри блоков object network
            elif line_str.startswith("object network"):
                parts = line_str.split()
                obj_name = parts[2] if len(parts) >= 3 else "unknown"

                j = idx + 1
                while j < len(self.lines) and self.lines[j].startswith(" "):
                    sub_line = self.lines[j].strip()
                    if sub_line.startswith("nat ("):
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
        if is_object_block or ("source" not in line_lower and "destination" not in line_lower):
            if "static" in line_lower:
                return "Object NAT (Static)"
            elif "dynamic" in line_lower:
                return "Object NAT (Dynamic)"
            return "Object NAT"
        else:
            src_type = "Static Source" if "source static" in line_lower else (
                "Dynamic Source" if "source dynamic" in line_lower else None)
            dst_type = "Static Destination" if "destination static" in line_lower else (
                "Dynamic Destination" if "destination dynamic" in line_lower else None)

            sub_parts = [p for p in [src_type, dst_type] if p]
            return f"Twice NAT ({' + '.join(sub_parts)})" if sub_parts else "Twice NAT"

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