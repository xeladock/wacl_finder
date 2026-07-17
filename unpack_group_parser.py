from abc import ABC, abstractmethod
import ipaddress


class BaseParser(ABC):
    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        self.object_ranges = self.parse_object_ranges()
    @abstractmethod
    def get_object_group(self, group_name):
        pass

class CiscoASAParser:

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        # словарь всех object network для подсветки object_ref
        self.object_networks = self.parse_all_object_networks()

    def parse_all_object_networks(self):
        """Парсим все object network в конфиге"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object network"):
                name = line.split()[2]
                # если следующая строка range
                if i + 1 < len(self.lines):
                    next_line = self.lines[i + 1].strip()
                    if next_line.startswith("range"):
                        parts = next_line.split()
                        start = ipaddress.ip_address(parts[1])
                        end = ipaddress.ip_address(parts[2])
                        objects[name] = {"type": "range", "start": start, "end": end, "text": next_line}
                        i += 1
                    else:
                        # object network без range → просто хранить строку
                        objects[name] = {"type": "object", "text": line}
                else:
                    objects[name] = {"type": "object", "text": line}
            i += 1
        return objects

    def get_object_group(self, group_name):
        """Возвращает список объектов указанной группы"""
        group_start = None
        objects = []

        for i, line in enumerate(self.lines):
            if line.strip() == f"object-group network {group_name}":
                group_start = i
                break

        # Если группа не найдена, проверяем object network
        if group_start is None:
            if group_name in self.object_networks:
                obj = self.object_networks[group_name]
                objects.append({
                    "text": obj["text"] if obj["type"] != "range" else obj["text"],
                    "type": obj["type"],
                    "network": obj.get("network"),
                    "start": obj.get("start"),
                    "end": obj.get("end")
                })
            return objects

        for line in self.lines[group_start + 1:]:
            if not line.startswith(" "):
                break
            line = line.strip()
            parts = line.split()

            if line.startswith("network-object"):
                # host
                if parts[1] == "host":
                    ip = parts[2]
                    objects.append({
                        "text": line,
                        "type": "host",
                        "network": ipaddress.ip_network(ip + "/32")
                    })
                # network с маской
                elif len(parts) == 3 and self._is_ip(parts[1]):
                    ip = parts[1]
                    mask = parts[2]
                    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    objects.append({
                        "text": line,
                        "type": "network",
                        "network": net
                    })
                # network без host
                elif len(parts) == 2 and self._is_ip(parts[1]):
                    ip = parts[1]
                    objects.append({
                        "text": line,
                        "type": "host",
                        "network": ipaddress.ip_network(ip + "/32")
                    })
                # network-object object obj_name
                elif len(parts) == 3 and parts[1] == "object":
                    objects.append({
                        "text": line,
                        "type": "object_ref",
                        "name": parts[2]
                    })

        return objects

    def check_ip(self, objects, ip):
        """
        Подсвечивает объекты:
          - host/network: если IP/сеть пересекается
          - object_ref: если IP/сеть входит в объект в self.object_networks
        Если ip пусто → выводим все объекты без BOLD
        """
        if not ip:
            return [(obj["text"], False) for obj in objects]

        # IP или сеть
        try:
            target = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            try:
                target = ipaddress.ip_network(ip + "/32")
            except ValueError:
                return [(obj["text"], False) for obj in objects]

        result = []

        for obj in objects:
            match = False

            # host/network
            if obj["type"] in ["host", "network"]:
                if target.overlaps(obj["network"]):
                    match = True

            # object_ref
            elif obj["type"] == "object_ref":
                name = obj["name"]
                if name in self.object_networks:
                    ref = self.object_networks[name]
                    # range
                    if ref["type"] == "range":
                        if ref["start"] <= target.network_address <= ref["end"] or \
                                ref["start"] <= target.broadcast_address <= ref["end"]:
                            match = True
                    # обычный object network (без range) → не подсвечивать
                    # можно оставить match = False
            # object network сам по себе (если группа = object network)
            elif obj["type"] == "range":
                if obj["start"] <= target.network_address <= obj["end"] or \
                        obj["start"] <= target.broadcast_address <= obj["end"]:
                    match = True

            result.append((obj["text"], match))

        return result
    def _is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

class CiscoIOSXEParser:

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        # словарь всех object network (для поддержки object_ref и прямого вызова object network)
        self.object_networks = self.parse_all_object_networks()

    def parse_all_object_networks(self):
        """Парсим все object network в конфиге Cisco IOS XE"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object network"):
                name = line.split(maxsplit=2)[-1]

                # ищем определение (host / range / subnet), пропускаем description
                for k in range(1, 6):
                    if i + k >= len(self.lines):
                        break
                    next_line = self.lines[i + k].strip()
                    if not next_line or next_line.startswith("description"):
                        continue

                    parts = next_line.split()

                    if next_line.startswith("host ") and len(parts) >= 2:
                        ip = parts[1]
                        objects[name] = {
                            "type": "host",
                            "network": ipaddress.ip_network(ip + "/32"),
                            "text": next_line
                        }
                        i += k
                        break

                    elif next_line.startswith("range ") and len(parts) >= 3:
                        start = ipaddress.ip_address(parts[1])
                        end = ipaddress.ip_address(parts[2])
                        objects[name] = {
                            "type": "range",
                            "start": start,
                            "end": end,
                            "text": next_line
                        }
                        i += k
                        break

                    elif next_line.startswith("subnet ") and len(parts) >= 3:
                        ip, mask = parts[1], parts[2]
                        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                        objects[name] = {
                            "type": "network",
                            "network": net,
                            "text": next_line
                        }
                        i += k
                        break

                else:
                    # если ничего не нашли
                    objects[name] = {"type": "object", "text": line}
            i += 1
        return objects

    def get_object_group(self, group_name):
        """Основной метод: парсит object-group network"""
        group_start = None
        objects = []

        # Ищем начало object-group
        for i, line in enumerate(self.lines):
            stripped = line.strip()
            if stripped == f"object-group network {group_name}":
                group_start = i
                break

        # Если не нашли object-group — возможно это просто object network
        if group_start is None:
            if group_name in self.object_networks:
                obj = self.object_networks[group_name]
                d = {"text": obj.get("text", ""), "type": obj["type"]}
                if "network" in obj:
                    d["network"] = obj["network"]
                if "start" in obj and "end" in obj:
                    d["start"] = obj["start"]
                    d["end"] = obj["end"]
                objects.append(d)
            return objects

        # Парсим содержимое object-group (строки с отступом)
        for line in self.lines[group_start + 1:]:
            if not line.startswith(" "):        # конец группы
                break

            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("description"):
                continue

            parts = line_stripped.split()

            # 1. host
            if line_stripped.startswith("host ") and len(parts) >= 2:
                ip = parts[1]
                objects.append({
                    "text": line_stripped,
                    "type": "host",
                    "network": ipaddress.ip_network(ip + "/32")
                })

            # 2. range
            elif line_stripped.startswith("range ") and len(parts) >= 3:
                try:
                    start = ipaddress.ip_address(parts[1])
                    end = ipaddress.ip_address(parts[2])
                    objects.append({
                        "text": line_stripped,
                        "type": "range",
                        "start": start,
                        "end": end
                    })
                except ValueError:
                    pass

            # 3. subnet (явно)
            elif line_stripped.startswith("subnet ") and len(parts) >= 3:
                try:
                    net = ipaddress.ip_network(f"{parts[1]}/{parts[2]}", strict=False)
                    objects.append({
                        "text": line_stripped,
                        "type": "network",
                        "network": net
                    })
                except ValueError:
                    pass

            # 4. сеть без слова "subnet" — самый частый случай в IOS XE
            elif len(parts) == 2 and not line_stripped.startswith(("host", "range", "group-object")):
                try:
                    net = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
                    objects.append({
                        "text": line_stripped,
                        "type": "network",
                        "network": net
                    })
                except ValueError:
                    pass

            # 5. group-object (ссылка на другой объект)
            elif len(parts) >= 2 and parts[0] == "group-object":
                objects.append({
                    "text": line_stripped,
                    "type": "object_ref",
                    "name": parts[1]
                })

        return objects


    def check_ip(self, objects, ip):
        """Подсветка совпадений — полностью аналогично CiscoASAParser"""
        if not ip:
            return [(obj["text"], False) for obj in objects]

        try:
            target = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            try:
                target = ipaddress.ip_network(ip + "/32")
            except ValueError:
                return [(obj["text"], False) for obj in objects]

        result = []

        for obj in objects:
            match = False

            if obj["type"] in ["host", "network"]:
                if target.overlaps(obj["network"]):
                    match = True

            elif obj["type"] == "range":
                if (obj["start"] <= target.network_address <= obj["end"] or
                        obj["start"] <= target.broadcast_address <= obj["end"]):
                    match = True

            elif obj["type"] == "object_ref":
                name = obj.get("name")
                if name in self.object_networks:
                    ref = self.object_networks[name]
                    if ref["type"] == "range":
                        if (ref["start"] <= target.network_address <= ref["end"] or
                                ref["start"] <= target.broadcast_address <= ref["end"]):
                            match = True
                    elif ref["type"] in ["host", "network"]:
                        if target.overlaps(ref["network"]):
                            match = True   # добавил поддержку для object_ref на host/network

            result.append((obj["text"], match))

        return result

class CiscoFirepowerParser:

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        # Все object network + object-group network для поддержки вложенности и object_ref
        self.all_objects = self.parse_all_objects()

    def parse_all_objects(self):
        """Парсим ВСЕ object network и object-group network"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            # object network (одиночный)
            if line.startswith("object network "):
                name = line.split(maxsplit=2)[2]
                # ищем содержимое
                for k in range(1, 6):
                    if i + k >= len(self.lines):
                        break
                    nxt = self.lines[i + k].strip()
                    if not nxt or nxt.startswith("description"):
                        continue
                    parts = nxt.split()

                    if nxt.startswith("host ") and len(parts) >= 2:
                        ip = parts[1]
                        objects[name] = {
                            "type": "host",
                            "network": ipaddress.ip_network(ip + "/32"),
                            "text": nxt
                        }
                        i += k
                        break
                    elif nxt.startswith("range ") and len(parts) >= 3:
                        start = ipaddress.ip_address(parts[1])
                        end = ipaddress.ip_address(parts[2])
                        objects[name] = {
                            "type": "range",
                            "start": start,
                            "end": end,
                            "text": nxt
                        }
                        i += k
                        break
                    elif (nxt.startswith("subnet ") or len(parts) == 2) and len(parts) >= 2:
                        try:
                            if nxt.startswith("subnet "):
                                ip, mask = parts[1], parts[2]
                            else:
                                ip, mask = parts[0], parts[1]
                            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                            objects[name] = {
                                "type": "network",
                                "network": net,
                                "text": nxt
                            }
                            i += k
                            break
                        except ValueError:
                            pass
                else:
                    objects[name] = {"type": "object", "text": line}
                i += 1
                continue

            # object-group network
            if line.startswith("object-group network "):
                name = line.split(maxsplit=2)[2]
                group_lines = []
                i += 1
                while i < len(self.lines) and self.lines[i].startswith(" "):
                    group_lines.append(self.lines[i].strip())
                    i += 1
                objects[name] = {
                    "type": "group",
                    "members": group_lines,
                    "text": line
                }
                continue  # i уже увеличен

            i += 1
        return objects

    def _resolve_object(self, name, visited=None):
        """Рекурсивно собирает все конечные объекты из группы (для полного раскрытия)"""
        if visited is None:
            visited = set()
        if name in visited:
            return []  # защита от циклов
        visited.add(name)

        if name not in self.all_objects:
            return []

        obj = self.all_objects[name]
        result = []

        if obj["type"] != "group":
            # это одиночный object network
            d = {"text": obj.get("text", name), "type": obj["type"]}
            if "network" in obj:
                d["network"] = obj["network"]
            if "start" in obj and "end" in obj:
                d["start"] = obj["start"]
                d["end"] = obj["end"]
            result.append(d)
            return result

        # это group — разбираем членов
        for member in obj.get("members", []):
            parts = member.split()
            if not parts:
                continue

            if member.startswith("network-object host "):
                ip = parts[2]
                result.append({
                    "text": member,
                    "type": "host",
                    "network": ipaddress.ip_network(ip + "/32")
                })

            elif member.startswith("network-object object "):
                ref_name = parts[2]
                result.extend(self._resolve_object(ref_name, visited.copy()))

            elif member.startswith("network-object "):
                # network-object IP MASK  или  network-object IP/prefix
                try:
                    if len(parts) == 3 and not parts[1].startswith("host"):
                        net = ipaddress.ip_network(f"{parts[1]}/{parts[2]}", strict=False)
                        result.append({
                            "text": member,
                            "type": "network",
                            "network": net
                        })
                    elif "/" in parts[1]:
                        net = ipaddress.ip_network(parts[1], strict=False)
                        result.append({
                            "text": member,
                            "type": "network",
                            "network": net
                        })
                except ValueError:
                    pass

            elif member.startswith("group-object "):
                ref_name = parts[1]
                result.extend(self._resolve_object(ref_name, visited.copy()))

        return result

    def get_object_group(self, group_name):
        """Возвращает список объектов (с раскрытием вложенных групп)"""
        if group_name in self.all_objects and self.all_objects[group_name]["type"] != "group":
            # если указали object network напрямую
            obj = self.all_objects[group_name]
            d = {"text": obj.get("text", ""), "type": obj["type"]}
            if "network" in obj:
                d["network"] = obj["network"]
            if "start" in obj and "end" in obj:
                d["start"] = obj["start"]
                d["end"] = obj["end"]
            return [d]

        # иначе — object-group
        resolved = self._resolve_object(group_name)
        return resolved

    def check_ip(self, objects, ip):
        """Подсветка совпадений (аналогично ASA)"""
        if not ip:
            return [(obj.get("text", ""), False) for obj in objects]

        try:
            target = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            try:
                target = ipaddress.ip_network(ip + "/32")
            except ValueError:
                return [(obj.get("text", ""), False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            obj_type = obj.get("type")

            if obj_type in ["host", "network"]:
                if target.overlaps(obj["network"]):
                    match = True

            elif obj_type == "range":
                if (obj["start"] <= target.network_address <= obj["end"] or
                        obj["start"] <= target.broadcast_address <= obj["end"]):
                    match = True

            result.append((obj.get("text", ""), match))

        return result
class CiscoFirepowerParser2:

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        # Все object network и object-group network
        self.all_objects = self.parse_all_objects()

    def parse_all_objects(self):
        """Парсим ВСЕ object network и object-group network"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            # object network (одиночный)
            if line.startswith("object network "):
                name = line.split(maxsplit=2)[2]
                # ищем содержимое
                for k in range(1, 6):
                    if i + k >= len(self.lines):
                        break
                    nxt = self.lines[i + k].strip()
                    if not nxt or nxt.startswith("description"):
                        continue
                    parts = nxt.split()

                    if nxt.startswith("host ") and len(parts) >= 2:
                        ip = parts[1]
                        objects[name] = {
                            "type": "host",
                            "network": ipaddress.ip_network(ip + "/32"),
                            "text": nxt
                        }
                        i += k
                        break
                    elif nxt.startswith("range ") and len(parts) >= 3:
                        start = ipaddress.ip_address(parts[1])
                        end = ipaddress.ip_address(parts[2])
                        objects[name] = {
                            "type": "range",
                            "start": start,
                            "end": end,
                            "text": nxt
                        }
                        i += k
                        break
                    elif nxt.startswith("subnet ") or (len(parts) == 2 and self._looks_like_network(parts[0])):
                        try:
                            if nxt.startswith("subnet "):
                                ip, mask = parts[1], parts[2]
                            else:
                                ip, mask = parts[0], parts[1]
                            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                            objects[name] = {
                                "type": "network",
                                "network": net,
                                "text": nxt
                            }
                            i += k
                            break
                        except ValueError:
                            pass
                else:
                    objects[name] = {"type": "object", "text": line}
                i += 1
                continue

            # object-group network
            if line.startswith("object-group network "):
                name = line.split(maxsplit=2)[2]
                group_lines = []
                i += 1
                while i < len(self.lines) and self.lines[i].startswith(" "):
                    group_lines.append(self.lines[i].strip())
                    i += 1
                objects[name] = {
                    "type": "group",
                    "members": group_lines,
                    "text": line
                }
                continue

            i += 1
        return objects

    def _looks_like_network(self, s: str) -> bool:
        """Проверяем, похожа ли строка на IP-адрес сети"""
        return s.count('.') == 3 and not s.startswith("host")

    def get_object_group(self, group_name):
        """Теперь НЕ раскрываем вложенные object/group — показываем как есть"""
        group_start = None
        objects = []

        # Ищем object-group
        for i, line in enumerate(self.lines):
            if line.strip() == f"object-group network {group_name}":
                group_start = i
                break

        # Если это object network (не group)
        if group_start is None:
            if group_name in self.all_objects:
                obj = self.all_objects[group_name]
                d = {
                    "text": obj.get("text", group_name),
                    "type": obj["type"]
                }
                if "network" in obj:
                    d["network"] = obj["network"]
                if "start" in obj and "end" in obj:
                    d["start"] = obj["start"]
                    d["end"] = obj["end"]
                objects.append(d)
            return objects

        # Парсим содержимое object-group (без рекурсивного раскрытия)
        for line in self.lines[group_start + 1:]:
            if not line.startswith(" "):
                break
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("description"):
                continue

            if line_stripped.startswith("network-object host "):
                ip = line_stripped.split()[2]
                objects.append({
                    "text": line_stripped,
                    "type": "host",
                    "network": ipaddress.ip_network(ip + "/32")
                })

            elif line_stripped.startswith("network-object object "):
                ref_name = line_stripped.split()[2]
                objects.append({
                    "text": f"object {ref_name}",
                    "type": "object_ref",
                    "name": ref_name
                })

            elif line_stripped.startswith("network-object "):
                # network-object IP MASK или network-object IP/prefix
                parts = line_stripped.split()
                try:
                    if len(parts) == 3 and not parts[1].startswith("host"):
                        net = ipaddress.ip_network(f"{parts[1]}/{parts[2]}", strict=False)
                        objects.append({
                            "text": line_stripped,
                            "type": "network",
                            "network": net
                        })
                    elif "/" in parts[1]:
                        net = ipaddress.ip_network(parts[1], strict=False)
                        objects.append({
                            "text": line_stripped,
                            "type": "network",
                            "network": net
                        })
                except ValueError:
                    pass

            elif line_stripped.startswith("group-object "):
                ref_name = line_stripped.split()[1]
                objects.append({
                    "text": f"object {ref_name}",   # или "group-object {ref_name}"
                    "type": "object_ref",
                    "name": ref_name
                })

        return objects

    def check_ip(self, objects, ip):
        """Подсветка только для реальных IP, object_ref не подсвечиваем"""
        if not ip:
            return [(obj.get("text", ""), False) for obj in objects]

        try:
            target = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            try:
                target = ipaddress.ip_network(ip + "/32")
            except ValueError:
                return [(obj.get("text", ""), False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            obj_type = obj.get("type")

            if obj_type in ["host", "network"]:
                if target.overlaps(obj.get("network")):
                    match = True
            elif obj_type == "range":
                if (obj["start"] <= target.network_address <= obj["end"] or
                        obj["start"] <= target.broadcast_address <= obj["end"]):
                    match = True
            # object_ref не подсвечиваем — это просто ссылка

            result.append((obj.get("text", ""), match))

        return result
class CiscoFirepowerParser3:

        def __init__(self, config_text):
            self.config = config_text
            self.lines = config_text.splitlines()
            # Все object network и object-group network для проверки вложенных ссылок
            self.all_objects = self.parse_all_objects()

        def parse_all_objects(self):
            """Парсим ВСЕ object network и object-group network"""
            objects = {}
            i = 0
            while i < len(self.lines):
                line = self.lines[i].strip()

                # object network (одиночный)
                if line.startswith("object network "):
                    name = line.split(maxsplit=2)[2]
                    for k in range(1, 6):
                        if i + k >= len(self.lines):
                            break
                        nxt = self.lines[i + k].strip()
                        if not nxt or nxt.startswith("description"):
                            continue
                        parts = nxt.split()

                        if nxt.startswith("host ") and len(parts) >= 2:
                            ip = parts[1]
                            objects[name] = {
                                "type": "host",
                                "network": ipaddress.ip_network(ip + "/32"),
                                "text": nxt
                            }
                            i += k
                            break
                        elif nxt.startswith("range ") and len(parts) >= 3:
                            start = ipaddress.ip_address(parts[1])
                            end = ipaddress.ip_address(parts[2])
                            objects[name] = {
                                "type": "range",
                                "start": start,
                                "end": end,
                                "text": nxt
                            }
                            i += k
                            break
                        elif nxt.startswith("subnet ") or (len(parts) == 2):
                            try:
                                if nxt.startswith("subnet "):
                                    ip, mask = parts[1], parts[2]
                                else:
                                    ip, mask = parts[0], parts[1]
                                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                                objects[name] = {
                                    "type": "network",
                                    "network": net,
                                    "text": nxt
                                }
                                i += k
                                break
                            except ValueError:
                                pass
                    else:
                        objects[name] = {"type": "object", "text": line}
                    i += 1
                    continue

                # object-group network
                if line.startswith("object-group network "):
                    name = line.split(maxsplit=2)[2]
                    group_lines = []
                    i += 1
                    while i < len(self.lines) and self.lines[i].startswith(" "):
                        group_lines.append(self.lines[i].strip())
                        i += 1
                    objects[name] = {
                        "type": "group",
                        "members": group_lines,
                        "text": line
                    }
                    continue

                i += 1
            return objects


        def get_object_group(self, group_name):
            """Показываем object_ref без раскрытия"""
            group_start = None
            objects = []

            for i, line in enumerate(self.lines):
                if line.strip() == f"object-group network {group_name}":
                    group_start = i
                    break

            # Если указали object network напрямую
            if group_start is None:
                if group_name in self.all_objects:
                    obj = self.all_objects[group_name]
                    d = {"text": obj.get("text", group_name), "type": obj["type"]}
                    if "network" in obj:
                        d["network"] = obj["network"]
                    if "start" in obj and "end" in obj:
                        d["start"] = obj["start"]
                        d["end"] = obj["end"]
                    objects.append(d)
                return objects

            # Парсим object-group (без рекурсии)
            for line in self.lines[group_start + 1:]:
                if not line.startswith(" "):
                    break
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith("description"):
                    continue

                if line_stripped.startswith("network-object host "):
                    ip = line_stripped.split()[2]
                    objects.append({
                        "text": line_stripped,
                        "type": "host",
                        "network": ipaddress.ip_network(ip + "/32")
                    })

                elif line_stripped.startswith("network-object object "):
                    ref_name = line_stripped.split()[2]
                    objects.append({
                        "text": f"object {ref_name}",
                        "type": "object_ref",
                        "name": ref_name
                    })

                elif line_stripped.startswith("network-object "):
                    parts = line_stripped.split()
                    try:
                        if len(parts) == 3 and not parts[1].startswith("host"):
                            net = ipaddress.ip_network(f"{parts[1]}/{parts[2]}", strict=False)
                            objects.append({
                                "text": line_stripped,
                                "type": "network",
                                "network": net
                            })
                        elif "/" in parts[1]:
                            net = ipaddress.ip_network(parts[1], strict=False)
                            objects.append({
                                "text": line_stripped,
                                "type": "network",
                                "network": net
                            })
                    except ValueError:
                        pass

                elif line_stripped.startswith("group-object "):
                    ref_name = line_stripped.split()[1]
                    objects.append({
                        "text": f"object {ref_name}",
                        "type": "object_ref",
                        "name": ref_name
                    })

            return objects

        def check_ip(self, objects, ip):
            """Подсветка с учётом вложенных object_ref"""
            if not ip:
                return [(obj.get("text", ""), False) for obj in objects]

            try:
                target = ipaddress.ip_network(ip, strict=False)
            except ValueError:
                try:
                    target = ipaddress.ip_network(ip + "/32")
                except ValueError:
                    return [(obj.get("text", ""), False) for obj in objects]

            result = []

            for obj in objects:
                match = False
                obj_type = obj.get("type")

                # Прямые адреса / сети / диапазоны
                if obj_type in ["host", "network"]:
                    if target.overlaps(obj.get("network")):
                        match = True

                elif obj_type == "range":
                    if (obj["start"] <= target.network_address <= obj["end"] or
                            obj["start"] <= target.broadcast_address <= obj["end"]):
                        match = True

                # ВЛОЖЕННЫЕ object_ref — проверяем, есть ли IP внутри них
                elif obj_type == "object_ref":
                    name = obj.get("name")
                    if name in self.all_objects:
                        ref = self.all_objects[name]
                        ref_type = ref.get("type")

                        if ref_type in ["host", "network"]:
                            if target.overlaps(ref.get("network")):
                                match = True
                        elif ref_type == "range":
                            if (ref["start"] <= target.network_address <= ref["end"] or
                                    ref["start"] <= target.broadcast_address <= ref["end"]):
                                match = True

                result.append((obj.get("text", ""), match))

            return result
class CiscoNexusParser:

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        # Для поддержки object-ref (если будут вложенные группы)
        self.all_objects = self.parse_all_objects()

    def parse_all_objects(self):
        """Парсим все object-group ip address и object network (если встретятся)"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            # object-group ip address NAME
            if line.startswith("object-group ip address "):
                name = line.split(maxsplit=3)[3]
                members = []
                i += 1
                while i < len(self.lines) and self.lines[i].strip().startswith(("10", "20", "30", "40", "50", "60", "70", "80", "90", "100")):
                    members.append(self.lines[i].strip())
                    i += 1
                objects[name] = {
                    "type": "group",
                    "members": members,
                    "text": line
                }
                continue

            # object network (на всякий случай, как в Firepower)
            if line.startswith("object network "):
                # аналогично Firepower — можно расширить позже
                pass

            i += 1
        return objects

    def get_object_group(self, group_name):
        """Парсит object-group ip address"""
        group_start = None
        objects = []

        # Ищем начало группы
        for i, line in enumerate(self.lines):
            if line.strip() == f"object-group ip address {group_name}":
                group_start = i
                break

        # Если не нашли — возможно это object network (редко)
        if group_start is None:
            if group_name in self.all_objects:
                obj = self.all_objects[group_name]
                if obj["type"] == "group":
                    return self._parse_members(obj["members"])
            return objects

        # Собираем все строки-члены группы
        members = []
        for line in self.lines[group_start + 1:]:
            stripped = line.strip()
            if not stripped or not stripped[0].isdigit():  # конец группы (sequence number должен быть)
                break
            members.append(stripped)

        return self._parse_members(members)

    def _parse_members(self, members):
        """Разбирает строки вида:
           10 host 10.1.1.1
           20 10.2.3.4/24
           30 10.5.6.7 255.255.255.0
        """
        objects = []

        for line in members:
            parts = line.split()

            # пропускаем sequence number
            if not parts or not parts[0][0].isdigit():
                continue

            seq_parts = parts[1:] if parts[0][0].isdigit() else parts

            if not seq_parts:
                continue

            # 1. host IP
            if seq_parts[0] == "host" and len(seq_parts) >= 2:
                ip = seq_parts[1]
                try:
                    net = ipaddress.ip_network(ip + "/32")
                    objects.append({
                        "text": line,
                        "type": "host",
                        "network": net
                    })
                except ValueError:
                    pass

            # 2. IP/PREFIX (самый частый в ваших примерах)
            elif len(seq_parts) == 1 and "/" in seq_parts[0]:
                try:
                    net = ipaddress.ip_network(seq_parts[0], strict=False)
                    objects.append({
                        "text": line,
                        "type": "network",
                        "network": net
                    })
                except ValueError:
                    pass

            # 3. IP MASK (subnet mask или wildcard)
            elif len(seq_parts) == 2:
                try:
                    # пробуем как сеть с маской
                    net = ipaddress.ip_network(f"{seq_parts[0]}/{seq_parts[1]}", strict=False)
                    objects.append({
                        "text": line,
                        "type": "network",
                        "network": net
                    })
                except ValueError:
                    # если не получилось — пробуем как wildcard mask (реже)
                    try:
                        # простой вариант: считаем хостом
                        net = ipaddress.ip_network(seq_parts[0] + "/32")
                        objects.append({
                            "text": line,
                            "type": "host",
                            "network": net
                        })
                    except ValueError:
                        pass

        return objects

    def check_ip(self, objects, ip):
        """Подсветка совпадений — полностью совместимо с остальными парсерами"""
        if not ip:
            return [(obj.get("text", ""), False) for obj in objects]

        try:
            target = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            try:
                target = ipaddress.ip_network(ip + "/32")
            except ValueError:
                return [(obj.get("text", ""), False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            if obj.get("type") in ["host", "network"]:
                if target.overlaps(obj["network"]):
                    match = True
            result.append((obj.get("text", ""), match))

        return result
class FortigateParser:

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        # Словарь всех address/address-group для поддержки ссылок
        self.all_objects = self.parse_all_objects()

    def parse_all_objects(self):
        """Парсим все address и addrgrp (edit блоки)"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            if line.startswith('edit "'):
                # Извлекаем имя объекта
                name = line.split('"')[1]
                members = []
                subnet = None
                start_ip = None
                end_ip = None
                obj_type = "group"

                i += 1
                while i < len(self.lines):
                    curr = self.lines[i].strip()
                    if curr.startswith('next') or curr.startswith('end'):
                        break

                    if curr.startswith('set member '):
                        # извлекаем все объекты в member
                        # убираем 'set member ' и кавычки
                        member_str = curr[11:].strip()
                        # Разбиваем по кавычкам
                        import re
                        member_list = re.findall(r'"([^"]+)"', member_str)
                        members.extend(member_list)

                    elif curr.startswith('set subnet '):
                        parts = curr.split()
                        if len(parts) >= 4:
                            ip = parts[2]
                            mask = parts[3]
                            try:
                                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                                subnet = net
                                obj_type = "network"
                            except ValueError:
                                pass

                    elif curr.startswith('set type iprange'):
                        obj_type = "range"

                    elif curr.startswith('set start-ip '):
                        start_ip = curr.split()[2]

                    elif curr.startswith('set end-ip '):
                        end_ip = curr.split()[2]

                    i += 1

                # Сохраняем объект
                if obj_type == "range" and start_ip and end_ip:
                    objects[name] = {
                        "type": "range",
                        "start": ipaddress.ip_address(start_ip),
                        "end": ipaddress.ip_address(end_ip),
                        "text": f"iprange {start_ip} - {end_ip}"
                    }
                elif subnet:
                    objects[name] = {
                        "type": "network",
                        "network": subnet,
                        "text": f"subnet {subnet.network_address} {subnet.netmask}"
                    }
                else:
                    # group или неизвестный объект
                    objects[name] = {
                        "type": "group",
                        "members": members,
                        "text": name
                    }

            i += 1
        return objects

    def get_object_group(self, group_name):
        """Возвращает членов группы БЕЗ авто-раскрытия вложенных объектов"""
        objects = []

        if group_name in self.all_objects:
            obj = self.all_objects[group_name]

            if obj["type"] != "group":
                # Это одиночный address (subnet или range)
                d = {
                    "text": obj.get("text", group_name),
                    "type": obj["type"]
                }
                if "network" in obj:
                    d["network"] = obj["network"]
                if "start" in obj and "end" in obj:
                    d["start"] = obj["start"]
                    d["end"] = obj["end"]
                objects.append(d)
                return objects

            # Это group — показываем members как ссылки
            for member in obj.get("members", []):
                objects.append({
                    "text": f'member "{member}"',
                    "type": "object_ref",
                    "name": member
                })

            return objects

        # Если объект не найден
        return []

    def check_ip(self, objects, ip):
        """Подсветка с учётом вложенных object_ref"""
        if not ip:
            return [(obj.get("text", ""), False) for obj in objects]

        try:
            target = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            try:
                target = ipaddress.ip_network(ip + "/32")
            except ValueError:
                return [(obj.get("text", ""), False) for obj in objects]

        result = []

        for obj in objects:
            match = False
            obj_type = obj.get("type")

            # Прямые адреса
            if obj_type in ["host", "network"]:
                if target.overlaps(obj.get("network")):
                    match = True

            elif obj_type == "range":
                if (obj["start"] <= target.network_address <= obj["end"] or
                        obj["start"] <= target.broadcast_address <= obj["end"]):
                    match = True

            # Вложенные ссылки (member "XXX")
            elif obj_type == "object_ref":
                name = obj.get("name")
                if name in self.all_objects:
                    ref = self.all_objects[name]
                    if ref["type"] in ["network", "host"]:
                        if target.overlaps(ref.get("network")):
                            match = True
                    elif ref["type"] == "range":
                        if (ref["start"] <= target.network_address <= ref["end"] or
                                ref["start"] <= target.broadcast_address <= ref["end"]):
                            match = True

            result.append((obj.get("text", ""), match))

        return result

class CiscoPIXParser:

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        # Для поддержки object network (если будут)
        self.object_networks = self.parse_all_object_networks()

    def parse_all_object_networks(self):
        """Парсим object network (аналогично ASA)"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object network"):
                name = line.split(maxsplit=2)[2]
                # ищем следующую строку с описанием
                if i + 1 < len(self.lines):
                    next_line = self.lines[i + 1].strip()
                    if next_line.startswith("range"):
                        parts = next_line.split()
                        start = ipaddress.ip_address(parts[1])
                        end = ipaddress.ip_address(parts[2])
                        objects[name] = {"type": "range", "start": start, "end": end, "text": next_line}
                        i += 1
                    elif next_line.startswith("host"):
                        ip = next_line.split()[1]
                        objects[name] = {
                            "type": "host",
                            "network": ipaddress.ip_network(ip + "/32"),
                            "text": next_line
                        }
                        i += 1
                    else:
                        objects[name] = {"type": "object", "text": line}
                else:
                    objects[name] = {"type": "object", "text": line}
            i += 1
        return objects

    def get_object_group(self, group_name):
        """Парсит object-group network для Cisco PIX"""
        group_start = None
        objects = []

        # Ищем начало object-group
        for i, line in enumerate(self.lines):
            if line.strip() == f"object-group network {group_name}":
                group_start = i
                break

        # Если не нашли — проверяем, может это object network
        if group_start is None:
            if group_name in self.object_networks:
                obj = self.object_networks[group_name]
                d = {
                    "text": obj.get("text", ""),
                    "type": obj["type"]
                }
                if "network" in obj:
                    d["network"] = obj["network"]
                if "start" in obj and "end" in obj:
                    d["start"] = obj["start"]
                    d["end"] = obj["end"]
                objects.append(d)
            return objects

        # Парсим содержимое группы
        for line in self.lines[group_start + 1:]:
            if not line.startswith(" "):
                break
            line_stripped = line.strip()
            if not line_stripped:
                continue

            parts = line_stripped.split()

            # network-object IP MASK  (основной формат в PIX)
            if line_stripped.startswith("network-object") and len(parts) >= 3:
                ip = parts[1]
                mask = parts[2]
                try:
                    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    objects.append({
                        "text": line_stripped,
                        "type": "network",
                        "network": net
                    })
                except ValueError:
                    pass

            # network-object host IP
            elif line_stripped.startswith("network-object host") and len(parts) >= 3:
                ip = parts[2]
                objects.append({
                    "text": line_stripped,
                    "type": "host",
                    "network": ipaddress.ip_network(ip + "/32")
                })

            # network-object object NAME (вложенная ссылка — редко в старом PIX, но поддержим)
            elif len(parts) >= 3 and parts[1] == "object":
                objects.append({
                    "text": line_stripped,
                    "type": "object_ref",
                    "name": parts[2]
                })

        return objects

    def check_ip(self, objects, ip):
        """Подсветка — полностью как в ASA"""
        if not ip:
            return [(obj.get("text", ""), False) for obj in objects]

        try:
            target = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            try:
                target = ipaddress.ip_network(ip + "/32")
            except ValueError:
                return [(obj.get("text", ""), False) for obj in objects]

        result = []
        for obj in objects:
            match = False

            if obj.get("type") in ["host", "network"]:
                if target.overlaps(obj.get("network")):
                    match = True

            elif obj.get("type") == "range":
                if (obj["start"] <= target.network_address <= obj["end"] or
                        obj["start"] <= target.broadcast_address <= obj["end"]):
                    match = True

            # object_ref (если вдруг будет)
            elif obj.get("type") == "object_ref":
                name = obj.get("name")
                if name in self.object_networks:
                    ref = self.object_networks[name]
                    if ref["type"] == "range":
                        if (ref["start"] <= target.network_address <= ref["end"] or
                                ref["start"] <= target.broadcast_address <= ref["end"]):
                            match = True
                    elif ref.get("type") in ["host", "network"]:
                        if target.overlaps(ref.get("network")):
                            match = True

            result.append((obj.get("text", ""), match))

        return result
# class HuaweiVRPParser:
#
#     def __init__(self, config_text):
#         self.config = config_text
#         self.lines = config_text.splitlines()
#         # Все address-set (object и group) для поддержки вложенности
#         self.all_address_sets = self.parse_all_address_sets()
#
#     def parse_all_address_sets(self):
#         """Парсим все ip address-set type object и type group"""
#         address_sets = {}
#         i = 0
#         while i < len(self.lines):
#             line = self.lines[i].strip()
#
#             if line.startswith("ip address-set ") and " type " in line:
#                 # Пример: ip address-set netams type object
#                 parts = line.split()
#                 name = parts[2]
#                 addr_type = parts[4]   # object или group
#
#                 members = []
#                 i += 1
#                 while i < len(self.lines):
#                     curr_line = self.lines[i].strip()
#                     if curr_line == "#" or curr_line.startswith("ip address-set ") or not curr_line:
#                         break
#                     if curr_line.startswith("address "):
#                         members.append(curr_line)
#                     i += 1
#
#                 address_sets[name] = {
#                     "type": addr_type,
#                     "members": members,
#                     "text": line
#                 }
#                 continue
#
#             i += 1
#         return address_sets
#
#     def _parse_member(self, member_line: str):
#         """Разбирает одну строку address ..."""
#         parts = member_line.split()
#
#         # address <seq> IP mask <mask>
#         if len(parts) >= 5 and parts[1].isdigit() and parts[3] == "mask":
#             ip = parts[2]
#             mask = parts[4]
#             try:
#                 net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
#                 return {
#                     "text": member_line,
#                     "type": "network" if int(mask) < 32 else "host",
#                     "network": net
#                 }
#             except ValueError:
#                 pass
#
#         # address <seq> range START END
#         elif len(parts) >= 5 and parts[3] == "range":
#             try:
#                 start = ipaddress.ip_address(parts[4])
#                 end = ipaddress.ip_address(parts[5])
#                 return {
#                     "text": member_line,
#                     "type": "range",
#                     "start": start,
#                     "end": end
#                 }
#             except ValueError:
#                 pass
#
#         return None
#
#     def _resolve_address_set(self, name, visited=None):
#         """Рекурсивно раскрывает address-set (включая вложенные группы)"""
#         if visited is None:
#             visited = set()
#         if name in visited:
#             return []  # защита от циклов
#         visited.add(name)
#
#         if name not in self.all_address_sets:
#             return []
#
#         addr_set = self.all_address_sets[name]
#         result = []
#
#         for member in addr_set.get("members", []):
#             parsed = self._parse_member(member)
#             if parsed:
#                 result.append(parsed)
#             else:
#                 # Проверяем, не является ли это ссылкой на другой address-set
#                 # В Huawei group может содержать: address X address-set NAME
#                 if "address-set" in member:
#                     try:
#                         ref_name = member.split("address-set")[-1].strip().split()[0]
#                         result.extend(self._resolve_address_set(ref_name, visited.copy()))
#                     except:
#                         pass
#
#         return result
#
#     def get_object_group(self, group_name):
#         """Основной метод — возвращает раскрытые объекты"""
#         if group_name not in self.all_address_sets:
#             return []
#
#         addr_set = self.all_address_sets[group_name]
#
#         # Если это type object — просто парсим его членов
#         if addr_set["type"] == "object":
#             objects = []
#             for member in addr_set["members"]:
#                 parsed = self._parse_member(member)
#                 if parsed:
#                     objects.append(parsed)
#             return objects
#
#         # Если это type group — рекурсивно раскрываем
#         return self._resolve_address_set(group_name)
#
#     def check_ip(self, objects, ip):
#         """Подсветка совпадений (совместимо со всеми остальными парсерами)"""
#         if not ip:
#             return [(obj.get("text", ""), False) for obj in objects]
#
#         try:
#             target = ipaddress.ip_network(ip, strict=False)
#         except ValueError:
#             try:
#                 target = ipaddress.ip_network(ip + "/32")
#             except ValueError:
#                 return [(obj.get("text", ""), False) for obj in objects]
#
#         result = []
#         for obj in objects:
#             match = False
#             obj_type = obj.get("type")
#
#             if obj_type in ["host", "network"]:
#                 if target.overlaps(obj.get("network")):
#                     match = True
#
#             elif obj_type == "range":
#                 if (obj["start"] <= target.network_address <= obj["end"] or
#                         obj["start"] <= target.broadcast_address <= obj["end"]):
#                     match = True
#
#             result.append((obj.get("text", ""), match))
#
#         return result
class HuaweiVRPParser:

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        self.all_address_sets = self.parse_all_address_sets()

    def parse_all_address_sets(self):
        """Парсим все ip address-set type object/group"""
        address_sets = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            if line.startswith("ip address-set ") and " type " in line:
                parts = line.split()
                name = parts[2]
                addr_type = parts[4]  # object или group

                members = []
                i += 1
                while i < len(self.lines):
                    curr = self.lines[i].strip()
                    if curr == "#" or curr.startswith("ip address-set ") or not curr:
                        break
                    if curr.startswith("address "):
                        members.append(curr)
                    i += 1

                address_sets[name] = {
                    "type": addr_type,
                    "members": members,
                    "text": line
                }
                continue
            i += 1
        return address_sets

    def _clean_description(self, line: str) -> str:
        """Удаляем ' description ...' из строки"""
        if " description " in line:
            return line.split(" description ")[0].strip()
        return line.strip()

    def _parse_member(self, member_line: str):
        """Разбирает одну строку address"""
        clean_line = self._clean_description(member_line)
        parts = clean_line.split()

        # Формат 1: address <seq> range START END
        if len(parts) >= 4 and parts[1].isdigit() and parts[2] == "range":
            try:
                start = ipaddress.ip_address(parts[3])
                end = ipaddress.ip_address(parts[4])
                return {
                    "text": self._clean_description(member_line),
                    "type": "range",
                    "start": start,
                    "end": end
                }
            except ValueError:
                pass

        # Формат 2: address <seq> IP mask MASK
        if len(parts) >= 5 and parts[1].isdigit() and parts[3] == "mask":
            ip = parts[2]
            mask = parts[4]
            try:
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                obj_type = "network" if int(mask) < 32 else "host"
                return {
                    "text": self._clean_description(member_line),
                    "type": obj_type,
                    "network": net
                }
            except ValueError:
                pass

        return None

    def _resolve_address_set(self, name, visited=None):
        """Рекурсивно раскрывает вложенные группы"""
        if visited is None:
            visited = set()
        if name in visited:
            return []
        visited.add(name)

        if name not in self.all_address_sets:
            return []

        addr_set = self.all_address_sets[name]
        result = []

        for member in addr_set.get("members", []):
            parsed = self._parse_member(member)
            if parsed:
                result.append(parsed)
            elif "address-set" in member:
                # поддержка вложенных address-set
                try:
                    ref_name = member.split("address-set")[-1].strip().split()[0]
                    result.extend(self._resolve_address_set(ref_name, visited.copy()))
                except:
                    pass

        return result

    def get_object_group(self, group_name):
        """Главный метод"""
        if group_name not in self.all_address_sets:
            return []

        addr_set = self.all_address_sets[group_name]

        if addr_set["type"] == "object":
            objects = [self._parse_member(m) for m in addr_set.get("members", []) if self._parse_member(m)]
            return objects

        # type group
        return self._resolve_address_set(group_name)

    def check_ip(self, objects, ip):
        """Подсветка совпадений"""
        if not ip:
            return [(obj.get("text", ""), False) for obj in objects]

        try:
            target = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            try:
                target = ipaddress.ip_network(ip + "/32")
            except ValueError:
                return [(obj.get("text", ""), False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            if obj.get("type") in ["host", "network"] and "network" in obj:
                if target.overlaps(obj["network"]):
                    match = True
            elif obj.get("type") == "range" and "start" in obj and "end" in obj:
                if (obj["start"] <= target.network_address <= obj["end"] or
                        obj["start"] <= target.broadcast_address <= obj["end"]):
                    match = True

            result.append((obj.get("text", ""), match))

        return result