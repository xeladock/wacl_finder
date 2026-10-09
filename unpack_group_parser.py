from abc import ABC, abstractmethod
import ipaddress
import socket
import re
from collections import defaultdict


class BaseParser(ABC):
    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        self.object_ranges = self.parse_object_ranges()
    @abstractmethod
    def get_object_group(self, group_name):
        pass


class CiscoASAParserSVC:
    # Карта стандартных портов Cisco ASA
    WELL_KNOWN_PORTS = frozenset({
        "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53,
        "www": 80, "http": 80, "pop3": 110, "ntp": 123, "https": 443,
        "snmp": 161, "syslog": 514, "radius": 1812, "tacacs": 49,
        "bgp": 179, "ldaps": 636, "kerberos": 88, "rdp": 3389,
        "sip": 5060, "h323": 1720, "ftp": 21, "tftp": 69
    })

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        self.names = self.parse_all_names()  # Маппинг alias -> IP
        self.object_networks = self.parse_all_object_networks()
        self.object_services = self.parse_all_object_services()

    def parse_all_names(self):
        """Парсит строки 'name IP ALIAS [description]' в словарь"""
        names_map = {}
        for line in self.lines:
            line_str = line.strip()
            if line_str.startswith("name "):
                parts = line_str.split()
                if len(parts) >= 3:
                    ip_addr = parts[1]
                    alias_name = parts[2]
                    names_map[alias_name] = {
                        "ip": ip_addr,
                        "raw_line": line_str
                    }
        return names_map

    def _resolve_port(self, port_str):
        """Преобразует строку с именем сервиса (domain, ssh, 8080) или префиксом (udp/domain) в int"""
        if port_str is None:
            return None

        p_str = str(port_str).lower().strip()

        if "/" in p_str:
            p_str = p_str.split("/", 1)[1].strip()

        if p_str.isdigit():
            return int(p_str)

        if p_str in self.WELL_KNOWN_PORTS:
            return self.WELL_KNOWN_PORTS[p_str]

        try:
            return socket.getservbyname(p_str)
        except (OSError, TypeError):
            return None

    def parse_all_object_networks(self):
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object network"):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[2]
                    if i + 1 < len(self.lines):
                        next_line = self.lines[i + 1].strip()
                        if next_line.startswith("range"):
                            p = next_line.split()
                            start = ipaddress.ip_address(p[1])
                            end = ipaddress.ip_address(p[2])
                            objects[name] = {"type": "range", "start": start, "end": end, "text": next_line}
                            i += 1
                        elif next_line.startswith("host"):
                            p = next_line.split()
                            host_val = p[1]
                            resolved_ip = self.names[host_val]["ip"] if host_val in self.names else host_val
                            try:
                                objects[name] = {
                                    "type": "host",
                                    "network": ipaddress.ip_network(f"{resolved_ip}/32"),
                                    "text": next_line
                                }
                                i += 1
                            except ValueError:
                                objects[name] = {"type": "object", "text": line}
                        else:
                            objects[name] = {"type": "object", "text": line}
                    else:
                        objects[name] = {"type": "object", "text": line}
            i += 1
        return objects

    def parse_all_object_services(self):
        services = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object service"):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[2]
                    service_lines = []
                    j = i + 1
                    while j < len(self.lines) and self.lines[j].startswith(" "):
                        service_lines.append(self.lines[j].strip())
                        j += 1
                    services[name] = {"text": line, "lines": service_lines}
            i += 1
        return services

    def get_object_group(self, group_name):
        group_start = None
        group_type = None
        header_proto = "ip"

        for i, line in enumerate(self.lines):
            l = line.strip()
            if l == f"object-group network {group_name}":
                group_start = i
                group_type = "network"
                break
            elif l.startswith(f"object-group service {group_name}"):
                parts = l.split()
                if len(parts) >= 3 and parts[2] == group_name:
                    group_start = i
                    group_type = "service"
                    if len(parts) >= 4:
                        header_proto = parts[3].lower()
                    break

        if group_start is None:
            if group_name in self.object_networks:
                obj = self.object_networks[group_name]
                return [{
                    "text": obj["text"],
                    "type": obj["type"],
                    "start": obj.get("start"),
                    "end": obj.get("end")
                }]
            elif group_name in self.object_services:
                obj = self.object_services[group_name]
                return [{
                    "text": obj["text"],
                    "type": "service_object_single",
                    "lines": obj["lines"]
                }]
            # Раскрываем одиночный name-алиас (например: request -> KucherOS -> 10.0.18.32)
            elif group_name in self.names:
                ip_str = self.names[group_name]["ip"]
                net = ipaddress.ip_network(f"{ip_str}/32")
                return [{"text": ip_str, "type": "host", "network": net}]

            return []

        objects = []
        for line in self.lines[group_start + 1:]:
            if not line.startswith(" "):
                break
            line_str = line.strip()
            parts = line_str.split()

            if group_type == "network":
                if line_str.startswith("network-object"):
                    # 1. network-object host <IP|ALIAS>
                    if parts[1] == "host" and len(parts) >= 3:
                        host_or_alias = parts[2]
                        resolved_ip = self.names[host_or_alias]["ip"] if host_or_alias in self.names else host_or_alias
                        try:
                            objects.append({
                                "text": line_str,
                                "type": "host",
                                "network": ipaddress.ip_network(resolved_ip + "/32")
                            })
                        except ValueError:
                            pass

                    # 2. network-object <IP> <MASK> или network-object <ALIAS> <MASK>
                    elif len(parts) == 3 and parts[1] != "object":
                        ip_or_alias, mask = parts[1], parts[2]
                        resolved_ip = self.names[ip_or_alias]["ip"] if ip_or_alias in self.names else ip_or_alias
                        try:
                            net = ipaddress.ip_network(f"{resolved_ip}/{mask}", strict=False)
                            objects.append({
                                "text": line_str,
                                "type": "network",
                                "network": net
                            })
                        except ValueError:
                            pass

                    # 3. network-object <IP|ALIAS>
                    elif len(parts) == 2 and parts[1] != "host":
                        ip_or_alias = parts[1]
                        resolved_ip = self.names[ip_or_alias]["ip"] if ip_or_alias in self.names else ip_or_alias
                        try:
                            objects.append({
                                "text": line_str,
                                "type": "host",
                                "network": ipaddress.ip_network(resolved_ip + "/32")
                            })
                        except ValueError:
                            pass

                    # 4. network-object object <NAME>
                    elif len(parts) >= 3 and parts[1] == "object":
                        objects.append({
                            "text": line_str,
                            "type": "object_ref",
                            "name": parts[2]
                        })

            elif group_type == "service":
                if line_str.startswith("service-object"):
                    parsed_svc = self._parse_service_object(line_str)
                    parsed_svc["text"] = line_str
                    objects.append(parsed_svc)
                elif line_str.startswith("port-object"):
                    parsed_svc = self._parse_port_object(line_str, header_proto)
                    parsed_svc["text"] = line_str
                    objects.append(parsed_svc)
                elif line_str.startswith("group-object"):
                    objects.append({
                        "text": line_str,
                        "type": "service_group_ref",
                        "name": parts[1]
                    })

        return objects

    def _parse_service_object(self, line):
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "object":
            return {"type": "service_object_ref", "name": parts[2]}

        proto = parts[1].lower() if len(parts) > 1 else "ip"
        start_port, end_port = None, None

        if "eq" in parts:
            eq_idx = parts.index("eq")
            if eq_idx + 1 < len(parts):
                p = self._resolve_port(parts[eq_idx + 1])
                start_port, end_port = p, p
        elif "range" in parts:
            r_idx = parts.index("range")
            if r_idx + 2 < len(parts):
                start_port = self._resolve_port(parts[r_idx + 1])
                end_port = self._resolve_port(parts[r_idx + 2])

        return {
            "type": "service",
            "proto": proto,
            "start_port": start_port,
            "end_port": end_port
        }

    def _parse_port_object(self, line, default_proto="ip"):
        parts = line.split()
        start_port, end_port = None, None

        if "eq" in parts:
            eq_idx = parts.index("eq")
            if eq_idx + 1 < len(parts):
                p = self._resolve_port(parts[eq_idx + 1])
                start_port, end_port = p, p
        elif "range" in parts:
            r_idx = parts.index("range")
            if r_idx + 2 < len(parts):
                start_port = self._resolve_port(parts[r_idx + 1])
                end_port = self._resolve_port(parts[r_idx + 2])

        return {
            "type": "service",
            "proto": default_proto,
            "start_port": start_port,
            "end_port": end_port
        }

    def check_service(self, objects, target_port=None, target_proto=None, _parsed_targets=None):
        if not target_port and not _parsed_targets:
            return [(obj["text"], False) for obj in objects]

        if _parsed_targets is None:
            raw_items = [p.strip() for p in str(target_port).split(",") if p.strip()]
            parsed_targets = []

            clean_default_proto = str(target_proto).lower().strip() if target_proto else None
            if clean_default_proto in (None, "", "none"):
                clean_default_proto = None

            for idx, item in enumerate(raw_items):
                item_proto = None
                port_str = item

                if "/" in item:
                    parts = item.split("/", 1)
                    item_proto = parts[0].lower().strip()
                    port_str = parts[1].strip()
                elif idx == 0 and clean_default_proto:
                    item_proto = clean_default_proto

                if item_proto in (None, "", "none"):
                    item_proto = None
                else:
                    item_proto = item_proto.lower().strip()

                resolved_p = self._resolve_port(port_str)
                if resolved_p is not None:
                    parsed_targets.append((resolved_p, item_proto))
        else:
            parsed_targets = _parsed_targets

        if not parsed_targets:
            return [(obj["text"], False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            obj_type = obj.get("type")

            if obj_type == "service":
                start_p = obj.get("start_port")
                end_p = obj.get("end_port")
                text_line = obj.get("text", "").lower()
                obj_proto = str(obj.get("proto", "ip")).lower()

                if "service-object tcp" in text_line or "port-object tcp" in text_line:
                    obj_proto = "tcp"
                elif "service-object udp" in text_line or "port-object udp" in text_line:
                    obj_proto = "udp"

                if start_p is not None and end_p is not None:
                    for target_p, req_proto in parsed_targets:
                        if not (start_p <= target_p <= end_p):
                            continue

                        proto_match = True
                        if req_proto in ("tcp", "udp"):
                            if obj_proto in ("tcp", "udp") and obj_proto != req_proto:
                                proto_match = False

                        if proto_match:
                            match = True
                            break

            elif obj_type == "service_group_ref":
                ref_name = obj.get("name")
                if ref_name:
                    sub_objects = self.get_object_group(ref_name)
                    sub_matches = self.check_service(
                        sub_objects,
                        _parsed_targets=parsed_targets
                    )
                    if any(m[1] for m in sub_matches):
                        match = True

            result.append((obj["text"], match))

        return result

    def check_ip(self, objects, ip_query):
        if not ip_query:
            return [(obj["text"], False) for obj in objects]

        raw_targets = [item.strip() for item in str(ip_query).split(",") if item.strip()]
        targets = []
        for raw in raw_targets:
            try:
                targets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue

        if not targets:
            return [(obj["text"], False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            for target in targets:
                if obj["type"] in ["host", "network"]:
                    if "network" in obj and target.overlaps(obj["network"]):
                        match = True
                        break
                elif obj["type"] == "object_ref":
                    name = obj.get("name")
                    if name in self.object_networks:
                        ref = self.object_networks[name]
                        if ref["type"] == "range":
                            if (ref["start"] <= target.network_address <= ref["end"] or
                                    ref["start"] <= target.broadcast_address <= ref["end"]):
                                match = True
                                break
                        elif ref["type"] in ["host", "network"]:
                            if "network" in ref and target.overlaps(ref["network"]):
                                match = True
                                break
                elif obj["type"] == "range":
                    if (obj["start"] <= target.network_address <= obj["end"] or
                            obj["start"] <= target.broadcast_address <= obj["end"]):
                        match = True
                        break

            result.append((obj["text"], match))
        return result

    def _is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

class CiscoIOSXEParserSVC:
    # Карта стандартных портов (включая специфичные для IOS XE / Cisco)
    WELL_KNOWN_PORTS = frozenset({
        "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53,
        "www": 80, "http": 80, "pop3": 110, "ntp": 123, "https": 443,
        "snmp": 161, "syslog": 514, "radius": 1812, "tacacs": 49,
        "bgp": 179, "ldaps": 636, "kerberos": 88, "rdp": 3389,
        "sip": 5060, "h323": 1720, "ftp": 21, "tftp": 69, "msrpc": 135
    })

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        self.object_networks = self.parse_all_object_networks()
        self.object_services = self.parse_all_object_services()

    def _resolve_port(self, port_str):
        """Преобразует имя сервиса (www, domain, ntp) или числовой порт в int"""
        if port_str is None:
            return None

        p_str = str(port_str).lower().strip()

        # Если передали "udp/domain" или "tcp/80", отсекаем протокол
        if "/" in p_str:
            p_str = p_str.split("/", 1)[1].strip()

        if p_str.isdigit():
            return int(p_str)

        if p_str in self.WELL_KNOWN_PORTS:
            return self.WELL_KNOWN_PORTS[p_str]

        try:
            return socket.getservbyname(p_str)
        except (OSError, TypeError):
            return None

    def parse_all_object_networks(self):
        """Парсим все object network в конфиге Cisco IOS XE"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object network"):
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    name = parts[2]

                    for k in range(1, 6):
                        if i + k >= len(self.lines):
                            break
                        next_line = self.lines[i + k].strip()
                        if not next_line or next_line.startswith("description"):
                            continue

                        p_next = next_line.split()

                        if next_line.startswith("host ") and len(p_next) >= 2:
                            ip = p_next[1]
                            objects[name] = {
                                "type": "host",
                                "network": ipaddress.ip_network(ip + "/32"),
                                "text": next_line
                            }
                            i += k
                            break

                        elif next_line.startswith("range ") and len(p_next) >= 3:
                            start = ipaddress.ip_address(p_next[1])
                            end = ipaddress.ip_address(p_next[2])
                            objects[name] = {
                                "type": "range",
                                "start": start,
                                "end": end,
                                "text": next_line
                            }
                            i += k
                            break

                        elif next_line.startswith("subnet ") and len(p_next) >= 3:
                            ip, mask = p_next[1], p_next[2]
                            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                            objects[name] = {
                                "type": "network",
                                "network": net,
                                "text": next_line
                            }
                            i += k
                            break
                    else:
                        objects[name] = {"type": "object", "text": line}
            i += 1
        return objects

    def parse_all_object_services(self):
        """Парсим все одиночные object service в конфиге Cisco IOS XE"""
        services = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object service"):
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    name = parts[2]
                    service_lines = []
                    j = i + 1
                    while j < len(self.lines) and self.lines[j].startswith(" "):
                        s_line = self.lines[j].strip()
                        if s_line and not s_line.startswith("description"):
                            service_lines.append(s_line)
                        j += 1
                    services[name] = {"text": line, "lines": service_lines}
            i += 1
        return services

    def _parse_ios_xe_service_line(self, line):
        """
        Парсит строки сервисов формата Cisco IOS XE:
          - tcp eq www
          - tcp range 1640 1691
          - udp eq ntp
          - tcp-udp eq 8080
          - ip / icmp
        """
        parts = line.split()
        if not parts:
            return {"type": "unknown"}

        proto = parts[0].lower()
        start_port, end_port = None, None

        if "eq" in parts:
            idx = parts.index("eq")
            if idx + 1 < len(parts):
                p = self._resolve_port(parts[idx + 1])
                start_port, end_port = p, p
        elif "range" in parts:
            idx = parts.index("range")
            if idx + 2 < len(parts):
                start_port = self._resolve_port(parts[idx + 1])
                end_port = self._resolve_port(parts[idx + 2])
        elif "gt" in parts:
            idx = parts.index("gt")
            if idx + 1 < len(parts):
                p = self._resolve_port(parts[idx + 1])
                if p is not None:
                    start_port, end_port = p + 1, 65535
        elif "lt" in parts:
            idx = parts.index("lt")
            if idx + 1 < len(parts):
                p = self._resolve_port(parts[idx + 1])
                if p is not None:
                    start_port, end_port = 1, p - 1
        elif proto in ("ip", "ip-hop-by-hop", "icmp"):
            # Протоколы без портов охватывают весь диапазон
            start_port, end_port = 1, 65535

        return {
            "type": "service",
            "proto": proto,
            "start_port": start_port,
            "end_port": end_port
        }

    def get_object_group(self, group_name):
        """Возвращает список объектов указанной группы (network или service)"""
        group_start = None
        group_type = None

        for i, line in enumerate(self.lines):
            l = line.strip()
            if l == f"object-group network {group_name}":
                group_start = i
                group_type = "network"
                break
            elif l.startswith(f"object-group service {group_name}"):
                group_start = i
                group_type = "service"
                break

        if group_start is None:
            if group_name in self.object_networks:
                obj = self.object_networks[group_name]
                d = {"text": obj.get("text", ""), "type": obj["type"]}
                if "network" in obj:
                    d["network"] = obj["network"]
                if "start" in obj and "end" in obj:
                    d["start"] = obj["start"]
                    d["end"] = obj["end"]
                return [d]
            elif group_name in self.object_services:
                obj = self.object_services[group_name]
                return [{
                    "text": obj["text"],
                    "type": "service_object_single",
                    "lines": obj["lines"]
                }]
            return []

        objects = []
        for line in self.lines[group_start + 1:]:
            if not line.startswith(" "):
                break

            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("description"):
                continue

            parts = line_stripped.split()

            if group_type == "network":
                if line_stripped.startswith("host ") and len(parts) >= 2:
                    objects.append({
                        "text": line_stripped,
                        "type": "host",
                        "network": ipaddress.ip_network(parts[1] + "/32")
                    })
                elif line_stripped.startswith("range ") and len(parts) >= 3:
                    try:
                        objects.append({
                            "text": line_stripped,
                            "type": "range",
                            "start": ipaddress.ip_address(parts[1]),
                            "end": ipaddress.ip_address(parts[2])
                        })
                    except ValueError:
                        pass
                elif line_stripped.startswith("subnet ") and len(parts) >= 3:
                    try:
                        objects.append({
                            "text": line_stripped,
                            "type": "network",
                            "network": ipaddress.ip_network(f"{parts[1]}/{parts[2]}", strict=False)
                        })
                    except ValueError:
                        pass
                elif len(parts) == 2 and not line_stripped.startswith(("host", "range", "group-object")):
                    try:
                        objects.append({
                            "text": line_stripped,
                            "type": "network",
                            "network": ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
                        })
                    except ValueError:
                        pass
                elif len(parts) >= 2 and parts[0] == "group-object":
                    objects.append({
                        "text": line_stripped,
                        "type": "object_ref",
                        "name": parts[1]
                    })

            elif group_type == "service":
                if parts[0] == "group-object" and len(parts) >= 2:
                    objects.append({
                        "text": line_stripped,
                        "type": "service_group_ref",
                        "name": parts[1]
                    })
                elif parts[0] == "service-object" and len(parts) >= 2:
                    # Резервная обработка формата service-object (если встречается)
                    parsed_svc = self._parse_ios_xe_service_line(" ".join(parts[1:]))
                    parsed_svc["text"] = line_stripped
                    objects.append(parsed_svc)
                else:
                    # Стандартные строки IOS XE: "tcp eq www", "udp eq ntp"
                    parsed_svc = self._parse_ios_xe_service_line(line_stripped)
                    parsed_svc["text"] = line_stripped
                    objects.append(parsed_svc)

        return objects

    def check_service(self, objects, target_port=None, target_proto=None, _parsed_targets=None):
        """
        Проверка сервисов IOS XE с изолированной фильтрацией по TCP/UDP для каждого порта.
        """
        if not target_port and not _parsed_targets:
            return [(obj["text"], False) for obj in objects]

        # 1. Формируем распарсенный список целей с привязкой протокола (только на верхнем вызове)
        if _parsed_targets is None:
            raw_items = [p.strip() for p in str(target_port).split(",") if p.strip()]
            parsed_targets = []

            # Нормализуем протокол по умолчанию
            clean_default_proto = str(target_proto).lower().strip() if target_proto else None
            if clean_default_proto in (None, "", "none"):
                clean_default_proto = None

            for idx, item in enumerate(raw_items):
                item_proto = None
                port_str = item

                # Если префикс "udp/8088" явно указан в элементе
                if "/" in item:
                    parts = item.split("/", 1)
                    item_proto = parts[0].lower().strip()
                    port_str = parts[1].strip()
                # Если слэша нет, но это первый элемент (idx == 0) и внешняя функция передала target_proto
                elif idx == 0 and clean_default_proto:
                    item_proto = clean_default_proto

                if item_proto in (None, "", "none"):
                    item_proto = None
                else:
                    item_proto = item_proto.lower().strip()

                resolved_p = self._resolve_port(port_str)
                if resolved_p is not None:
                    parsed_targets.append((resolved_p, item_proto))
        else:
            parsed_targets = _parsed_targets

        if not parsed_targets:
            return [(obj["text"], False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            obj_type = obj.get("type")

            if obj_type == "service":
                start_p = obj.get("start_port")
                end_p = obj.get("end_port")
                text_line = obj.get("text", "").lower()
                obj_proto = str(obj.get("proto", "ip")).lower()

                # Уточняем протокол из текста строки IOS XE ("tcp eq 22", "udp eq 8088")
                parts = text_line.split()
                if parts and parts[0] in ("tcp", "udp"):
                    obj_proto = parts[0]

                if start_p is not None and end_p is not None:
                    for target_p, req_proto in parsed_targets:
                        # 1. Проверка диапазона портов
                        if not (start_p <= target_p <= end_p):
                            continue

                        # 2. Проверка протокола
                        proto_match = True
                        if req_proto in ("tcp", "udp"):
                            if obj_proto in ("tcp", "udp") and obj_proto != req_proto:
                                proto_match = False
                            elif obj_proto not in ("tcp", "udp", "ip", "tcp-udp", "any"):
                                proto_match = False

                        if proto_match:
                            match = True
                            break

            elif obj_type == "service_group_ref":
                ref_name = obj.get("name")
                if ref_name:
                    sub_objects = self.get_object_group(ref_name)
                    # Передаем уже сформированные parsed_targets в рекурсию
                    sub_matches = self.check_service(
                        sub_objects,
                        _parsed_targets=parsed_targets
                    )
                    if any(m[1] for m in sub_matches):
                        match = True

            result.append((obj["text"], match))

        return result
    def check_ip(self, objects, ip_query):
        """
        Подсветка IP / Сетей с поддержкой множественного поиска через запятую.
        Пример: "10.160.11.21, 10.160.11.18"
        """
        if not ip_query:
            return [(obj["text"], False) for obj in objects]

        # Разбиваем запрос по запятым
        raw_targets = [item.strip() for item in str(ip_query).split(",") if item.strip()]

        targets = []
        for raw in raw_targets:
            try:
                targets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                try:
                    targets.append(ipaddress.ip_network(raw + "/32"))
                except ValueError:
                    continue

        if not targets:
            return [(obj["text"], False) for obj in objects]

        result = []
        for obj in objects:
            match = False

            # Проверяем совпадение хотя бы с одной из запрашиваемых целей
            for target in targets:
                if obj.get("type") in ["host", "network"]:
                    if "network" in obj and target.overlaps(obj["network"]):
                        match = True
                        break

                elif obj.get("type") == "range":
                    if "start" in obj and "end" in obj:
                        if (obj["start"] <= target.network_address <= obj["end"] or
                                obj["start"] <= target.broadcast_address <= obj["end"]):
                            match = True
                            break

                elif obj.get("type") == "object_ref":
                    name = obj.get("name")
                    if name in self.object_networks:
                        ref = self.object_networks[name]
                        if ref["type"] == "range":
                            if (ref["start"] <= target.network_address <= ref["end"] or
                                    ref["start"] <= target.broadcast_address <= ref["end"]):
                                match = True
                                break
                        elif ref["type"] in ["host", "network"]:
                            if "network" in ref and target.overlaps(ref["network"]):
                                match = True
                                break

            result.append((obj["text"], match))

        return result

class CiscoFirepowerParserSVC:
    # Карта стандартных портов
    WELL_KNOWN_PORTS = frozenset({
        "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53,
        "www": 80, "http": 80, "pop3": 110, "ntp": 123, "https": 443,
        "snmp": 161, "syslog": 514, "radius": 1812, "tacacs": 49,
        "bgp": 179, "ldaps": 636, "kerberos": 88, "rdp": 3389,
        "sip": 5060, "h323": 1720, "ftp": 21, "tftp": 69,
        "netbios-ns": 137, "netbios-dgm": 138, "netbios-ssn": 139,
        "microsoft-ds": 445
    })

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        self.all_objects = self.parse_all_objects()
        self.object_services = self.parse_all_object_services()

    def _resolve_port(self, port_str):
        """Преобразует имя сервиса или числовой порт в int"""
        if port_str is None:
            return None

        p_str = str(port_str).lower().strip()

        if "/" in p_str:
            p_str = p_str.split("/", 1)[1].strip()

        if p_str.isdigit():
            return int(p_str)

        if p_str in self.WELL_KNOWN_PORTS:
            return self.WELL_KNOWN_PORTS[p_str]

        try:
            return socket.getservbyname(p_str)
        except (OSError, TypeError):
            return None

    def parse_all_objects(self):
        """Парсим ВСЕ object network и object-group network"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            if line.startswith("object network "):
                parts_line = line.split(maxsplit=2)
                if len(parts_line) >= 3:
                    name = parts_line[2]
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

            if line.startswith("object-group network "):
                parts_group = line.split(maxsplit=2)
                if len(parts_group) >= 3:
                    name = parts_group[2]
                    group_lines = []
                    i += 1
                    while i < len(self.lines) and self.lines[i].startswith(" "):
                        s_line = self.lines[i].strip()
                        if s_line and not s_line.startswith("description"):
                            group_lines.append(s_line)
                        i += 1
                    objects[name] = {
                        "type": "group",
                        "members": group_lines,
                        "text": line
                    }
                    continue

            i += 1
        return objects

    def parse_all_object_services(self):
        """Парсим все одиночные object service"""
        services = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object service"):
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    name = parts[2]
                    service_lines = []
                    j = i + 1
                    while j < len(self.lines) and self.lines[j].startswith(" "):
                        s_line = self.lines[j].strip()
                        if s_line and not s_line.startswith("description"):
                            service_lines.append(s_line)
                        j += 1
                    services[name] = {"text": line, "lines": service_lines}
            i += 1
        return services

    def _parse_service_object(self, line):
        """Парсинг service-object в FXOS/Firepower"""
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "object":
            return {"type": "service_object_ref", "name": parts[2]}

        proto = parts[1].lower() if len(parts) > 1 else "ip"
        start_port, end_port = None, None

        if "eq" in parts:
            eq_idx = parts.index("eq")
            if eq_idx + 1 < len(parts):
                p = self._resolve_port(parts[eq_idx + 1])
                start_port, end_port = p, p
        elif "range" in parts:
            r_idx = parts.index("range")
            if r_idx + 2 < len(parts):
                start_port = self._resolve_port(parts[r_idx + 1])
                end_port = self._resolve_port(parts[r_idx + 2])

        return {
            "type": "service",
            "proto": proto,
            "start_port": start_port,
            "end_port": end_port
        }

    def _parse_port_object(self, line, default_proto="ip"):
        """Парсинг port-object в FXOS/Firepower"""
        parts = line.split()
        start_port, end_port = None, None

        if "eq" in parts:
            eq_idx = parts.index("eq")
            if eq_idx + 1 < len(parts):
                p = self._resolve_port(parts[eq_idx + 1])
                start_port, end_port = p, p
        elif "range" in parts:
            r_idx = parts.index("range")
            if r_idx + 2 < len(parts):
                start_port = self._resolve_port(parts[r_idx + 1])
                end_port = self._resolve_port(parts[r_idx + 2])

        return {
            "type": "service",
            "proto": default_proto,
            "start_port": start_port,
            "end_port": end_port
        }

    def get_object_group(self, group_name):
        """Возвращает список элементов группы"""
        group_start = None
        group_type = None
        header_proto = "ip"

        for i, line in enumerate(self.lines):
            l = line.strip()
            if l == f"object-group network {group_name}":
                group_start = i
                group_type = "network"
                break
            elif l.startswith(f"object-group service {group_name}"):
                parts = l.split()
                if len(parts) >= 3 and parts[2] == group_name:
                    group_start = i
                    group_type = "service"
                    if len(parts) >= 4:
                        header_proto = parts[3].lower()
                    break

        if group_start is None:
            if group_name in self.all_objects:
                obj = self.all_objects[group_name]
                d = {"text": obj.get("text", group_name), "type": obj["type"]}
                if "network" in obj:
                    d["network"] = obj["network"]
                if "start" in obj and "end" in obj:
                    d["start"] = obj["start"]
                    d["end"] = obj["end"]
                return [d]
            elif group_name in self.object_services:
                obj = self.object_services[group_name]
                return [{
                    "text": obj["text"],
                    "type": "service_object_single",
                    "lines": obj["lines"]
                }]
            return []

        objects = []
        for line in self.lines[group_start + 1:]:
            if not line.startswith(" "):
                break
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("description"):
                continue

            parts = line_stripped.split()

            if group_type == "network":
                if line_stripped.startswith("network-object host "):
                    ip = parts[2]
                    objects.append({
                        "text": line_stripped,
                        "type": "host",
                        "network": ipaddress.ip_network(ip + "/32")
                    })
                elif line_stripped.startswith("network-object object "):
                    ref_name = parts[2]
                    objects.append({
                        "text": f"object {ref_name}",
                        "type": "object_ref",
                        "name": ref_name
                    })
                elif line_stripped.startswith("network-object "):
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
                    ref_name = parts[1]
                    objects.append({
                        "text": f"object {ref_name}",
                        "type": "object_ref",
                        "name": ref_name
                    })

            elif group_type == "service":
                if line_stripped.startswith("service-object"):
                    parsed_svc = self._parse_service_object(line_stripped)
                    parsed_svc["text"] = line_stripped
                    objects.append(parsed_svc)
                elif line_stripped.startswith("port-object"):
                    parsed_svc = self._parse_port_object(line_stripped, header_proto)
                    parsed_svc["text"] = line_stripped
                    objects.append(parsed_svc)
                elif line_stripped.startswith("group-object"):
                    objects.append({
                        "text": line_stripped,
                        "type": "service_group_ref",
                        "name": parts[1]
                    })

        return objects

    def check_service(self, objects, target_port=None, target_proto=None, _parsed_targets=None):
        """
        Проверка сервисов FXOS с изолированной фильтрацией по TCP/UDP для каждого порта.
        """
        if not target_port and not _parsed_targets:
            return [(obj.get("text", ""), False) for obj in objects]

        # 1. Парсинг целей и строгая изоляция протоколов (только на верхнем вызове)
        if _parsed_targets is None:
            raw_items = [p.strip() for p in str(target_port).split(",") if p.strip()]
            parsed_targets = []

            # Нормализация дефолтного протокола
            clean_default_proto = str(target_proto).lower().strip() if target_proto else None
            if clean_default_proto in (None, "", "none"):
                clean_default_proto = None

            for idx, item in enumerate(raw_items):
                item_proto = None
                port_str = item

                # Если префикс "udp/6969" явно указан в элементе
                if "/" in item:
                    parts = item.split("/", 1)
                    item_proto = parts[0].lower().strip()
                    port_str = parts[1].strip()
                # Если слэша нет, но это первый элемент (idx == 0) и внешняя функция передала target_proto
                elif idx == 0 and clean_default_proto:
                    item_proto = clean_default_proto

                if item_proto in (None, "", "none"):
                    item_proto = None
                else:
                    item_proto = item_proto.lower().strip()

                resolved_p = self._resolve_port(port_str)
                if resolved_p is not None:
                    parsed_targets.append((resolved_p, item_proto))
        else:
            parsed_targets = _parsed_targets

        if not parsed_targets:
            return [(obj.get("text", ""), False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            obj_type = obj.get("type")

            if obj_type == "service":
                start_p = obj.get("start_port")
                end_p = obj.get("end_port")
                text_line = obj.get("text", "").lower()
                obj_proto = str(obj.get("proto", "ip")).lower()

                # Уточняем протокол напрямую из текста строки FXOS ("service-object tcp ...")
                if "service-object tcp" in text_line or "port-object tcp" in text_line:
                    obj_proto = "tcp"
                elif "service-object udp" in text_line or "port-object udp" in text_line:
                    obj_proto = "udp"

                if start_p is not None and end_p is not None:
                    for target_p, req_proto in parsed_targets:
                        # 1. Совпадение порта
                        if not (start_p <= target_p <= end_p):
                            continue

                        # 2. Согласование протокола
                        proto_match = True
                        if req_proto in ("tcp", "udp"):
                            if obj_proto in ("tcp", "udp") and obj_proto != req_proto:
                                proto_match = False
                            elif obj_proto not in ("tcp", "udp", "ip", "tcp-udp", "any"):
                                proto_match = False

                        if proto_match:
                            match = True
                            break

            elif obj_type == "service_group_ref":
                ref_name = obj.get("name")
                if ref_name:
                    sub_objects = self.get_object_group(ref_name)
                    # Передаем уже сформированные и изолированные targets в рекурсивные вызовы
                    sub_matches = self.check_service(
                        sub_objects,
                        _parsed_targets=parsed_targets
                    )
                    if any(m[1] for m in sub_matches):
                        match = True

            result.append((obj.get("text", ""), match))

        return result
    def check_ip(self, objects, ip_query):
        """
        Подсветка IP с поддержкой поиска через запятую
        """
        if not ip_query:
            return [(obj.get("text", ""), False) for obj in objects]

        raw_targets = [item.strip() for item in str(ip_query).split(",") if item.strip()]

        targets = []
        for raw in raw_targets:
            try:
                targets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                try:
                    targets.append(ipaddress.ip_network(raw + "/32"))
                except ValueError:
                    continue

        if not targets:
            return [(obj.get("text", ""), False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            obj_type = obj.get("type")

            for target in targets:
                if obj_type in ["host", "network"]:
                    if "network" in obj and target.overlaps(obj["network"]):
                        match = True
                        break

                elif obj_type == "range":
                    if "start" in obj and "end" in obj:
                        if (obj["start"] <= target.network_address <= obj["end"] or
                                obj["start"] <= target.broadcast_address <= obj["end"]):
                            match = True
                            break

                elif obj_type == "object_ref":
                    name = obj.get("name")
                    if name in self.all_objects:
                        ref = self.all_objects[name]
                        ref_type = ref.get("type")

                        if ref_type in ["host", "network"]:
                            if "network" in ref and target.overlaps(ref["network"]):
                                match = True
                                break
                        elif ref_type == "range":
                            if "start" in ref and "end" in ref:
                                if (ref["start"] <= target.network_address <= ref["end"] or
                                        ref["start"] <= target.broadcast_address <= ref["end"]):
                                    match = True
                                    break

            result.append((obj.get("text", ""), match))

        return result

class FortigateParserSVC:

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        self.all_services = self.parse_all_services()
        self.all_objects = self.parse_all_objects()

    def _extract_port_num(self, val_str):
        """Гарантированно извлекает число (порт) из любых строк вида '2598', 'tcp-2598', 'tcp/2598'"""
        if not val_str:
            return None
        # Ищем последовательность цифр в строке
        match = re.search(r'\b(\d{1,5})\b', str(val_str))
        if match:
            p = int(match.group(1))
            if 1 <= p <= 65535:
                return p
        return None

    def parse_all_objects(self):
        """Парсим address и addrgrp"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            if line.startswith('edit "'):
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
                        member_str = curr[11:].strip()
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
                    objects[name] = {
                        "type": "group",
                        "members": members,
                        "text": name
                    }

            i += 1
        return objects

    def parse_all_services(self):
        """Парсим custom service и service group"""
        services = {}
        i = 0
        in_service_block = False

        while i < len(self.lines):
            line = self.lines[i].strip()

            if line.startswith("config firewall service custom") or line.startswith("config firewall service group"):
                in_service_block = True
                i += 1
                continue

            if in_service_block and line.startswith("end"):
                in_service_block = False

            if in_service_block and line.startswith('edit "'):
                name = line.split('"')[1]
                tcp_ranges = []
                udp_ranges = []
                members = []
                is_group = False
                is_ip_proto = False

                i += 1
                while i < len(self.lines):
                    curr = self.lines[i].strip()
                    if curr.startswith('next') or curr.startswith('end'):
                        break

                    if curr.startswith('set member '):
                        is_group = True
                        member_str = curr[11:].strip()
                        member_list = re.findall(r'"([^"]+)"', member_str)
                        members.extend(member_list)

                    elif curr.startswith('set protocol IP'):
                        is_ip_proto = True

                    elif curr.startswith('set tcp-portrange '):
                        val = curr[18:].strip().replace('"', '')
                        tcp_ranges.extend(self._parse_forti_portrange(val))

                    elif curr.startswith('set udp-portrange '):
                        val = curr[18:].strip().replace('"', '')
                        udp_ranges.extend(self._parse_forti_portrange(val))

                    i += 1

                if is_group:
                    services[name] = {
                        "type": "service_group",
                        "members": members,
                        "text": name
                    }
                else:
                    services[name] = {
                        "type": "service_custom",
                        "tcp_ranges": tcp_ranges,
                        "udp_ranges": udp_ranges,
                        "is_ip_proto": is_ip_proto,
                        "text": name
                    }

            i += 1
        return services

    def _parse_forti_portrange(self, val_str):
        ranges = []
        parts = val_str.split()
        for p in parts:
            if ":" in p:
                p = p.split(":")[0]

            if "-" in p:
                sub = p.split("-")
                start_p = self._extract_port_num(sub[0])
                end_p = self._extract_port_num(sub[1])
                if start_p is not None and end_p is not None:
                    ranges.append((start_p, end_p))
            else:
                p_int = self._extract_port_num(p)
                if p_int is not None:
                    ranges.append((p_int, p_int))
        return ranges

    def get_object_group(self, group_name):
        """Первоочередная проверка по сервисам, затем по сетевым объектам"""
        objects = []

        # Сначала проверяем сервисы
        if group_name in self.all_services:
            svc = self.all_services[group_name]
            if svc["type"] == "service_group":
                for member in svc.get("members", []):
                    objects.append({
                        "text": f'member "{member}"',
                        "type": "service_object_ref",
                        "name": member
                    })
            else:
                objects.append({
                    "text": f'edit "{group_name}"',
                    "type": "service_single",
                    "name": group_name
                })
            return objects

        # Затем проверяем сетевые адреса/группы
        if group_name in self.all_objects:
            obj = self.all_objects[group_name]
            if obj["type"] != "group":
                return [{
                    "text": obj.get("text", group_name),
                    "type": obj["type"],
                    "name": group_name
                }]

            for member in obj.get("members", []):
                objects.append({
                    "text": f'member "{member}"',
                    "type": "object_ref",
                    "name": member
                })
            return objects

        return [{
            "text": f'member "{group_name}"',
            "type": "service_object_ref",
            "name": group_name
        }]

    def check_service(self, objects, target_query=None, target_proto=None, _parsed_targets=None):
        if not target_query and not _parsed_targets:
            return [(obj.get("text", ""), False) for obj in objects]

        # 1. Формируем распарсенный список целей и изолируем протоколы (только на верхнем вызове)
        if _parsed_targets is None:
            raw_elements = [q.strip() for q in str(target_query).split(",") if q.strip()]

            exact_only_queries = []  # Только текстовый поиск 1:1
            port_search_queries = []  # Поиск по именам + портам

            for elem in raw_elements:
                if (elem.startswith('"') and elem.endswith('"')) or (elem.startswith("'") and elem.endswith("'")):
                    exact_only_queries.append(elem.strip('\'"').lower())
                else:
                    port_search_queries.append(elem.strip('\'"'))

            clean_default_proto = str(target_proto).lower().strip() if target_proto else None
            if clean_default_proto in (None, "", "none"):
                clean_default_proto = None

            parsed_targets = []
            for idx, q_item in enumerate(port_search_queries):
                item_proto = None
                port_str = q_item

                # 1. Если явно передан слэш ("udp/2598")
                if "/" in q_item:
                    parts = q_item.split("/", 1)
                    item_proto = parts[0].lower().strip()
                    port_str = parts[1].strip()
                # 2. Если слэша нет, то только первый элемент подхватывает внешнее значение target_proto
                elif idx == 0 and clean_default_proto:
                    item_proto = clean_default_proto

                if item_proto in (None, "", "none"):
                    item_proto = None
                else:
                    item_proto = item_proto.lower().strip()

                resolved_p = None
                if port_str.isdigit():
                    resolved_p = int(port_str)
                else:
                    if "/" in q_item:
                        resolved_p = self._extract_port_num(port_str)

                if resolved_p is not None and 1 <= resolved_p <= 65535:
                    parsed_targets.append((resolved_p, item_proto))
        else:
            parsed_targets = _parsed_targets
            exact_only_queries = []
            port_search_queries = []

        result = []

        for obj in objects:
            is_match = False
            text_raw = obj.get("text", "")

            # Извлекаем и нормализуем чистое имя объекта из конфига
            member_name = obj.get("name", "")
            if not member_name:
                member_name = re.sub(r'^(member|edit)\s+"?|"$', '', text_raw).strip()

            clean_member_name = member_name.strip(' "').lower()

            # --- ШАГ 1А: Строгая текстовая проверка для элементов В КАВЫЧКАХ ---
            for q_exact in exact_only_queries:
                if q_exact == clean_member_name:
                    is_match = True
                    break

            # --- ШАГ 1Б: Текстовая проверка для элементов БЕЗ кавычек ---
            if not is_match:
                for q_norm in port_search_queries:
                    if q_norm.lower() == clean_member_name:
                        is_match = True
                        break

            # --- ШАГ 2: Совпадение по портам (ТОЛЬКО для запросов без кавычек) ---
            if not is_match and parsed_targets and member_name in self.all_services:
                svc_info = self.all_services[member_name]

                if svc_info.get("is_ip_proto"):
                    is_match = True
                else:
                    tcp_ranges = svc_info.get("tcp_ranges", [])
                    udp_ranges = svc_info.get("udp_ranges", [])

                    for target_p, req_proto in parsed_targets:
                        # Фильтрация по TCP
                        if req_proto in (None, "tcp", "ip", "any"):
                            for start_p, end_p in tcp_ranges:
                                if start_p <= target_p <= end_p:
                                    is_match = True
                                    break

                        # Фильтрация по UDP
                        if not is_match and req_proto in (None, "udp", "ip", "any"):
                            for start_p, end_p in udp_ranges:
                                if start_p <= target_p <= end_p:
                                    is_match = True
                                    break

                        if is_match:
                            break

            # --- ШАГ 3: Рекурсивная проверка для групп сервисов FortiGate ---
            if not is_match and obj.get("type") == "service_object_ref":
                ref_name = obj.get("name")
                if ref_name and ref_name in self.all_services:
                    svc = self.all_services[ref_name]
                    if svc.get("type") == "service_group":
                        sub_objects = self.get_object_group(ref_name)
                        sub_matches = self.check_service(
                            sub_objects,
                            _parsed_targets=parsed_targets
                        )
                        if any(m[1] for m in sub_matches):
                            is_match = True

            result.append((text_raw, is_match))

        return result
    def check_ip(self, objects, ip_query):
        if not ip_query:
            return [(obj.get("text", ""), False) for obj in objects]

        raw_targets = [item.strip() for item in str(ip_query).split(",") if item.strip()]

        targets = []
        for raw in raw_targets:
            try:
                targets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                try:
                    targets.append(ipaddress.ip_network(raw + "/32"))
                except ValueError:
                    continue

        if not targets:
            return [(obj.get("text", ""), False) for obj in objects]

        result = []

        for obj in objects:
            match = False
            obj_type = obj.get("type")
            text_raw = obj.get("text", "")

            for target in targets:
                if obj_type in ["host", "network"]:
                    if "network" in obj and target.overlaps(obj["network"]):
                        match = True
                        break

                elif obj_type == "range":
                    if "start" in obj and "end" in obj:
                        if (obj["start"] <= target.network_address <= obj["end"] or
                                obj["start"] <= target.broadcast_address <= obj["end"]):
                            match = True
                            break

                elif obj_type == "object_ref":
                    name = obj.get("name")
                    if name in self.all_objects:
                        ref = self.all_objects[name]
                        ref_type = ref.get("type")

                        if ref_type in ["host", "network"]:
                            if "network" in ref and target.overlaps(ref["network"]):
                                match = True
                                break
                        elif ref_type == "range":
                            if "start" in ref and "end" in ref:
                                if (ref["start"] <= target.network_address <= ref["end"] or
                                        ref["start"] <= target.broadcast_address <= ref["end"]):
                                    match = True
                                    break

            result.append((text_raw, match))

        return result

class CiscoNexusParserSVC:

    # Встроенный справочник популярных сервисов Cisco IANA
    PORT_MAP = {
        'www': 80,
        'http': 80,
        'https': 443,
        'domain': 53,
        'dns': 53,
        'ssh': 22,
        'telnet': 23,
        'smtp': 25,
        'snmp': 161,
        'snmptrap': 162,
        'ntp': 123,
        'syslog': 514,
        'kerberos': 88,
        'ldap': 389,
        'ldaps': 636,
        'bgp': 179,
    }

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        # Парсим IP-объекты и сервисные группы
        self.all_objects = self.parse_all_objects()
        self.all_port_groups = self.parse_all_port_groups()

    def _resolve_port(self, val_str):
        """Преобразует строку в порт (число или имя из таблицы Cisco)."""
        val_clean = str(val_str).strip().lower()
        if val_clean.isdigit():
            p = int(val_clean)
            return p if 1 <= p <= 65535 else None
        return self.PORT_MAP.get(val_clean)

    def parse_all_objects(self):
        """Парсим все object-group ip address и object network"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            # object-group ip address NAME
            if line.startswith("object-group ip address "):
                name = line.split(maxsplit=3)[3]
                members = []
                i += 1
                while i < len(self.lines) and self.lines[
                    i
                ].strip().startswith(
                    (
                        "10",
                        "20",
                        "30",
                        "40",
                        "50",
                        "60",
                        "70",
                        "80",
                        "90",
                        "100",
                    )
                ):
                    members.append(self.lines[i].strip())
                    i += 1
                objects[name] = {
                    "type": "group",
                    "members": members,
                    "text": line,
                }
                continue

            i += 1
        return objects

    def parse_all_port_groups(self):
        """Парсим object-group ip port NAME и object-group port NAME"""
        groups = {}
        i = 0

        while i < len(self.lines):
            line = self.lines[i].strip()

            if line.startswith("object-group ip port ") or line.startswith(
                "object-group port "
            ):
                parts = line.split()
                group_name = parts[-1]

                members = []
                i += 1
                while i < len(self.lines):
                    curr = self.lines[i].strip()

                    # Конец блока группы
                    if (
                        not curr
                        or curr.startswith("object-group")
                        or curr.startswith("ip access-list")
                        or curr == "!"
                    ):
                        break

                    # Игнорируем комментарии
                    if curr.startswith("remark"):
                        i += 1
                        continue

                    members.append(curr)
                    i += 1

                groups[group_name] = {
                    "type": "service_group",
                    "members": members,
                    "text": group_name,
                }
                continue

            i += 1

        return groups

    def get_object_group(self, group_name):
        """Возвращает содержимое группы: сначала ищет по IP, затем по портам/сервисам."""
        # 1. Поиск по IP object-group
        group_start = None
        for i, line in enumerate(self.lines):
            if line.strip() == f"object-group ip address {group_name}":
                group_start = i
                break

        if group_start is not None:
            members = []
            for line in self.lines[group_start + 1 :]:
                stripped = line.strip()
                if not stripped or not stripped[0].isdigit():
                    break
                members.append(stripped)
            return self._parse_members(members)

        if group_name in self.all_objects:
            obj = self.all_objects[group_name]
            if obj["type"] == "group":
                return self._parse_members(obj["members"])

        # 2. Поиск по портовым группам (object-group ip port / object-group port)
        if group_name in self.all_port_groups:
            grp = self.all_port_groups[group_name]
            objects = []
            for member_text in grp.get("members", []):
                objects.append(
                    {
                        "text": member_text,
                        "type": "service_object_ref",
                        "name": member_text,
                    }
                )
            return objects

        return [
            {
                "text": f"object-group {group_name}",
                "type": "service_object_ref",
                "name": group_name,
            }
        ]

    def _parse_members(self, members):
        """Разбирает сетевые строки IP-групп"""
        objects = []

        for line in members:
            parts = line.split()

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
                    objects.append(
                        {"text": line, "type": "host", "network": net}
                    )
                except ValueError:
                    pass

            # 2. IP/PREFIX
            elif len(seq_parts) == 1 and "/" in seq_parts[0]:
                try:
                    net = ipaddress.ip_network(seq_parts[0], strict=False)
                    objects.append(
                        {"text": line, "type": "network", "network": net}
                    )
                except ValueError:
                    pass

            # 3. IP MASK
            elif len(seq_parts) == 2:
                try:
                    net = ipaddress.ip_network(
                        f"{seq_parts[0]}/{seq_parts[1]}", strict=False
                    )
                    objects.append(
                        {"text": line, "type": "network", "network": net}
                    )
                except ValueError:
                    try:
                        net = ipaddress.ip_network(seq_parts[0] + "/32")
                        objects.append(
                            {"text": line, "type": "host", "network": net}
                        )
                    except ValueError:
                        pass

        return objects

    def check_service(self, objects, target_query=None, target_proto=None, _parsed_targets=None):
        if not target_query and not _parsed_targets:
            return [(obj.get("text", ""), False) for obj in objects]

        # 1. Формируем распарсенный список целей и изолируем протоколы (только на верхнем вызове)
        if _parsed_targets is None:
            raw_elements = [
                q.strip() for q in str(target_query).split(",") if q.strip()
            ]

            exact_only_queries = []
            port_search_queries = []

            for elem in raw_elements:
                if (elem.startswith('"') and elem.endswith('"')) or (
                        elem.startswith("'") and elem.endswith("'")
                ):
                    exact_only_queries.append(elem.strip("'\"").lower())
                else:
                    port_search_queries.append(elem.strip("'\""))

            clean_default_proto = str(target_proto).lower().strip() if target_proto else None
            if clean_default_proto in (None, "", "none"):
                clean_default_proto = None

            parsed_targets = []
            for idx, q_item in enumerate(port_search_queries):
                item_proto = None
                port_str = q_item

                # Префикс "udp/80" в самом элементе
                if "/" in q_item:
                    parts = q_item.split("/", 1)
                    item_proto = parts[0].lower().strip()
                    port_str = parts[1].strip()
                # Только первый элемент подхватывает внешнее значение target_proto
                elif idx == 0 and clean_default_proto:
                    item_proto = clean_default_proto

                if item_proto in (None, "", "none"):
                    item_proto = None
                else:
                    item_proto = item_proto.lower().strip()

                resolved_p = None
                if port_str.isdigit():
                    resolved_p = int(port_str)
                else:
                    resolved_p = self._resolve_port(port_str)

                if resolved_p is not None and 1 <= resolved_p <= 65535:
                    parsed_targets.append((resolved_p, item_proto))
        else:
            parsed_targets = _parsed_targets
            exact_only_queries = []
            port_search_queries = []

        result = []

        for obj in objects:
            is_match = False
            text_raw = obj.get("text", "")

            # Чистим строку от sequence number в начале (например, "10 eq 80" -> "eq 80")
            parts = text_raw.strip().split()
            if parts and parts[0].isdigit():
                clean_text = " ".join(parts[1:]).lower()
            else:
                clean_text = text_raw.lower()

            # --- ШАГ 1А: Запрос В КАВЫЧКАХ (строгое текстовое совпадение) ---
            for q_exact in exact_only_queries:
                if q_exact == clean_text or q_exact in clean_text.split():
                    is_match = True
                    break

            # --- ШАГ 1Б: Запрос БЕЗ кавычек (текстовое совпадение) ---
            if not is_match:
                for q_norm in port_search_queries:
                    clean_q = q_norm.lower().strip()
                    if clean_q == clean_text or clean_q in clean_text.split():
                        is_match = True
                        break

            # --- ШАГ 2: Совпадение по диапазонам портов и протоколу ---
            if not is_match and parsed_targets:
                line_parts = clean_text.split()

                # Извлекаем протокол из текста записи Cisco NX-OS (например, "eq tcp 80" или "tcp eq 80")
                obj_proto = "ip"
                if "tcp" in line_parts:
                    obj_proto = "tcp"
                elif "udp" in line_parts:
                    obj_proto = "udp"

                line_ranges = []

                if "eq" in line_parts:
                    idx_eq = line_parts.index("eq")
                    for p_str in line_parts[idx_eq + 1:]:
                        p_num = self._resolve_port(p_str)
                        if p_num is not None:
                            line_ranges.append((p_num, p_num))

                elif "range" in line_parts:
                    idx_r = line_parts.index("range")
                    r_args = line_parts[idx_r + 1:]
                    if len(r_args) >= 2:
                        sp = self._resolve_port(r_args[0])
                        ep = self._resolve_port(r_args[1])
                        if sp and ep:
                            line_ranges.append((sp, ep))

                elif "gt" in line_parts:
                    idx_gt = line_parts.index("gt")
                    if len(line_parts) > idx_gt + 1:
                        gt_p = self._resolve_port(line_parts[idx_gt + 1])
                        if gt_p:
                            line_ranges.append((gt_p + 1, 65535))

                elif "lt" in line_parts:
                    idx_lt = line_parts.index("lt")
                    if len(line_parts) > idx_lt + 1:
                        lt_p = self._resolve_port(line_parts[idx_lt + 1])
                        if lt_p:
                            line_ranges.append((1, lt_p - 1))

                # Проверяем вхождение целевого порта и соответствие протокола
                for target_p, req_proto in parsed_targets:
                    # 1. Проверка порта
                    port_match = any(start_p <= target_p <= end_p for start_p, end_p in line_ranges)

                    # 2. Проверка протокола
                    proto_match = True
                    if req_proto in ("tcp", "udp"):
                        if obj_proto in ("tcp", "udp") and obj_proto != req_proto:
                            proto_match = False

                    if port_match and proto_match:
                        is_match = True
                        break

            # --- ШАГ 3: Рекурсивный проход для групп ---
            if not is_match and obj.get("type") == "service_group_ref":
                ref_name = obj.get("name")
                if ref_name:
                    sub_objects = self.get_object_group(ref_name)
                    sub_matches = self.check_service(
                        sub_objects,
                        _parsed_targets=parsed_targets
                    )
                    if any(m[1] for m in sub_matches):
                        is_match = True

            result.append((text_raw, is_match))

        return result
    def check_ip(self, objects, ip):
        """Подсветка совпадений по IP (поддерживает список через запятую)."""
        if not ip:
            return [(obj.get("text", ""), False) for obj in objects]

        # 1. Разбиваем входную строку по запятым и формируем список ip_network объектов
        raw_targets = [
            t.strip() for t in str(ip).split(",") if t.strip()
        ]
        parsed_targets = []

        for target_str in raw_targets:
            try:
                parsed_targets.append(
                    ipaddress.ip_network(target_str, strict=False)
                )
            except ValueError:
                try:
                    parsed_targets.append(
                        ipaddress.ip_network(target_str + "/32")
                    )
                except ValueError:
                    pass

        # Если ни один IP из запроса не удалось распознать
        if not parsed_targets:
            return [(obj.get("text", ""), False) for obj in objects]

        # 2. Проверяем совпадение каждого объекта группы с любым из искомых IP
        result = []
        for obj in objects:
            match = False
            if obj.get("type") in ["host", "network"]:
                obj_net = obj.get("network")
                if obj_net:
                    for target_net in parsed_targets:
                        if target_net.overlaps(obj_net):
                            match = True
                            break
            result.append((obj.get("text", ""), match))

        return result

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
        group_start = None
        group_type = None
        header_proto = "ip"

        for i, line in enumerate(self.lines):
            stripped = line.strip()
            if stripped.startswith("object-group network ") and stripped.split()[-1] == group_name:
                group_start = i
                group_type = "network"
                break
            elif stripped.startswith("object-group service ") and group_name in stripped.split():
                parts = stripped.split()
                if parts[2] == group_name:
                    group_start = i
                    group_type = "service"
                    if len(parts) >= 4:
                        header_proto = parts[3].lower()
                    break

        if group_start is None:
            if group_name in self.object_networks:
                obj = self.object_networks[group_name]
                return [{
                    "text": obj["text"],
                    "type": obj["type"],
                    "network": obj.get("network"),
                    "start": obj.get("start"),
                    "end": obj.get("end")
                }]
            elif group_name in self.object_services:
                return [{
                    "text": "\n".join(self.object_services[group_name]),
                    "type": "service_object",
                    "lines": self.object_services[group_name]
                }]
            return []

        objects = []
        for line in self.lines[group_start + 1:]:
            if not line.startswith(" "):
                break
            stripped = line.strip()
            parts = stripped.split()

            if group_type == "service":
                # 1. service-object tcp/udp destination eq/range ...
                if stripped.startswith("service-object"):
                    proto = parts[1].lower() if len(parts) > 1 else "ip"

                    # Динамически ищем позиции 'eq', 'range', 'gt', 'lt' в строке
                    p_start, p_end = None, None

                    if "eq" in parts:
                        eq_idx = parts.index("eq")
                        if eq_idx + 1 < len(parts):
                            p_start = p_end = self._resolve_port(parts[eq_idx + 1])
                    elif "range" in parts:
                        rng_idx = parts.index("range")
                        if rng_idx + 2 < len(parts):
                            p_start = self._resolve_port(parts[rng_idx + 1])
                            p_end = self._resolve_port(parts[rng_idx + 2])

                    objects.append({
                        "text": stripped,
                        "type": "service",
                        "proto": proto,
                        "start_port": p_start,
                        "end_port": p_end
                    })

                # 2. port-object eq/range ...
                elif stripped.startswith("port-object"):
                    p_start, p_end = None, None

                    if "eq" in parts:
                        eq_idx = parts.index("eq")
                        if eq_idx + 1 < len(parts):
                            p_start = p_end = self._resolve_port(parts[eq_idx + 1])
                    elif "range" in parts:
                        rng_idx = parts.index("range")
                        if rng_idx + 2 < len(parts):
                            p_start = self._resolve_port(parts[rng_idx + 1])
                            p_end = self._resolve_port(parts[rng_idx + 2])

                    objects.append({
                        "text": stripped,
                        "type": "service",
                        "proto": header_proto,
                        "start_port": p_start,
                        "end_port": p_end
                    })

                # 3. group-object <ref_group>
                elif stripped.startswith("group-object"):
                    ref_group = parts[1]
                    objects.append({
                        "text": stripped,
                        "type": "service_group_ref",
                        "name": ref_group
                    })

            elif group_type == "network":
                # ... стандартный разбор network-object ...
                pass

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


class HuaweiVRPParserSVC:

    # Встроенный справочник стандартных сервисов Huawei/IANA
    PORT_MAP = {
        'ftp': 21,
        'ssh': 22,
        'telnet': 23,
        'smtp': 25,
        'dns': 53,
        'domain': 53,
        'http': 80,
        'www': 80,
        'kerberos': 88,
        'pop3': 110,
        'ntp': 123,
        'snmp': 161,
        'snmptrap': 162,
        'bgp': 179,
        'ldap': 389,
        'https': 443,
        'syslog': 514,
        'ldaps': 636,
        'radius': 1812,
    }

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        self.all_address_sets = self.parse_all_address_sets()
        self.all_service_sets = self.parse_all_service_sets()

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
                    if (
                        curr == "#"
                        or curr.startswith("ip address-set ")
                        or not curr
                    ):
                        break
                    if curr.startswith("address "):
                        members.append(curr)
                    i += 1

                address_sets[name] = {
                    "type": addr_type,
                    "members": members,
                    "text": line,
                }
                continue
            i += 1
        return address_sets

    def parse_all_service_sets(self):
        """Парсим все ip service-set type object/group"""
        service_sets = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            if line.startswith("ip service-set ") and " type " in line:
                parts = line.split()
                name = parts[2]
                svc_type = parts[4]  # object или group

                members = []
                i += 1
                while i < len(self.lines):
                    curr = self.lines[i].strip()
                    if (
                        curr == "#"
                        or curr.startswith("ip service-set ")
                        or curr.startswith("ip address-set ")
                        or not curr
                    ):
                        break

                    # Пропускаем description самого сета
                    if curr.startswith("description "):
                        i += 1
                        continue

                    if curr.startswith("service "):
                        members.append(curr)
                    i += 1

                service_sets[name] = {
                    "type": svc_type,
                    "members": members,
                    "text": line,
                }
                continue
            i += 1
        return service_sets

    def _resolve_port(self, val_str):
        """Преобразует порт в число или запрашивает из справочника PORT_MAP."""
        val_clean = str(val_str).strip().lower()
        if val_clean.isdigit():
            p = int(val_clean)
            return p if 1 <= p <= 65535 else None
        return self.PORT_MAP.get(val_clean)

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
        if len(parts) >= 5 and parts[1].isdigit() and parts[2] == "range":
            try:
                start = ipaddress.ip_address(parts[3])
                end = ipaddress.ip_address(parts[4])
                return {
                    "text": self._clean_description(member_line),
                    "type": "range",
                    "start": start,
                    "end": end,
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
                    "network": net,
                }
            except ValueError:
                pass

        return None

    def _resolve_address_set(self, name, visited=None):
        """Рекурсивно раскрывает вложенные IP-группы"""
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
                try:
                    ref_name = (
                        member.split("address-set")[-1].strip().split()[0]
                    )
                    result.extend(
                        self._resolve_address_set(ref_name, visited.copy())
                    )
                except Exception:
                    pass

        return result

    def _resolve_service_set(self, name, visited=None):
        """Рекурсивно раскрывает вложенные сервисные группы (type group)"""
        if visited is None:
            visited = set()
        if name in visited:
            return []
        visited.add(name)

        if name not in self.all_service_sets:
            # Если это просто одиночный системный сервис (например, ssh, ftp)
            return [
                {
                    "text": f"service {name}",
                    "type": "service_object_ref",
                    "name": name,
                }
            ]

        svc_set = self.all_service_sets[name]
        result = []

        if svc_set["type"] == "object":
            for m in svc_set.get("members", []):
                result.append(
                    {"text": m, "type": "service_object_ref", "name": name}
                )
        else:
            # type group
            for member in svc_set.get("members", []):
                if "service-set" in member:
                    try:
                        ref_name = (
                            member.split("service-set")[-1].strip().split()[0]
                        )
                        result.extend(
                            self._resolve_service_set(ref_name, visited.copy())
                        )
                    except Exception:
                        pass
                else:
                    result.append(
                        {
                            "text": member,
                            "type": "service_object_ref",
                            "name": name,
                        }
                    )

        return result

    def get_object_group(self, group_name):
        """Возвращает содержимое группы (адресной или сервисной)"""
        # 1. Сначала ищем среди address-set
        if group_name in self.all_address_sets:
            addr_set = self.all_address_sets[group_name]
            if addr_set["type"] == "object":
                return [
                    self._parse_member(m)
                    for m in addr_set.get("members", [])
                    if self._parse_member(m)
                ]
            return self._resolve_address_set(group_name)

        # 2. Если не нашли, ищем среди service-set
        if group_name in self.all_service_sets:
            return self._resolve_service_set(group_name)

        return [
            {
                "text": f"service-set {group_name}",
                "type": "service_object_ref",
                "name": group_name,
            }
        ]

    def check_service(self, objects, target_query=None, target_proto=None, _parsed_targets=None):
        """Подсветка совпадений по сервисам и портам Huawei VRP"""
        if not target_query and not _parsed_targets:
            return [(obj.get("text", ""), False) for obj in objects]

        # 1. Формируем распарсенный список целей и изолируем протоколы (только на верхнем вызове)
        if _parsed_targets is None:
            raw_elements = [
                q.strip() for q in str(target_query).split(",") if q.strip()
            ]

            exact_only_queries = []
            port_search_queries = []

            for elem in raw_elements:
                if (elem.startswith('"') and elem.endswith('"')) or (
                        elem.startswith("'") and elem.endswith("'")
                ):
                    exact_only_queries.append(elem.strip("'\"").lower())
                else:
                    port_search_queries.append(elem.strip("'\""))

            clean_default_proto = str(target_proto).lower().strip() if target_proto else None
            if clean_default_proto in (None, "", "none"):
                clean_default_proto = None

            parsed_targets = []
            for idx, q_item in enumerate(port_search_queries):
                item_proto = None
                port_str = q_item

                if "/" in q_item:
                    parts = q_item.split("/", 1)
                    item_proto = parts[0].lower().strip()
                    port_str = parts[1].strip()
                elif idx == 0 and clean_default_proto:
                    item_proto = clean_default_proto

                if item_proto in (None, "", "none"):
                    item_proto = None
                else:
                    item_proto = item_proto.lower().strip()

                resolved_p = self._resolve_port(port_str)
                if resolved_p is not None:
                    parsed_targets.append((resolved_p, item_proto))
        else:
            parsed_targets = _parsed_targets
            exact_only_queries = []
            port_search_queries = []

        result = []

        for obj in objects:
            is_match = False
            text_raw = obj.get("text", "")
            clean_text = self._clean_description(text_raw).lower()

            # --- ШАГ 1А: Строгое совпадение В КАВЫЧКАХ ---
            for q_exact in exact_only_queries:
                if q_exact == clean_text or q_exact in clean_text.split():
                    is_match = True
                    break

            # --- ШАГ 1Б: Совпадение БЕЗ кавычек (только НЕЧИСЛОВЫЕ поисковые строки) ---
            if not is_match:
                for q_norm in port_search_queries:
                    clean_q = q_norm.lower().strip()
                    # Если запрос - чистое число, пропускаем ШАГ 1Б и отправляем на математическую проверку порта и протокола в ШАГ 2
                    if clean_q.isdigit():
                        continue
                    if clean_q == clean_text or clean_q in clean_text.split():
                        is_match = True
                        break

            # --- ШАГ 2: Сопоставление портов и протоколов ---
            if not is_match and parsed_targets:
                line_proto = None
                if "protocol " in clean_text:
                    try:
                        line_proto = clean_text.split("protocol ")[1].split()[0].lower()
                    except IndexError:
                        pass

                line_ranges = []

                # 2.1 Явное указание destination-port
                if "destination-port " in clean_text:
                    try:
                        dest_part = clean_text.split("destination-port ")[1].strip()
                        tokens = dest_part.split()

                        # Обработка вариантов формата "13723 to 13724" или нескольких портов
                        i = 0
                        while i < len(tokens):
                            if i + 2 < len(tokens) and tokens[i + 1] == "to":
                                sp = self._resolve_port(tokens[i])
                                ep = self._resolve_port(tokens[i + 2])
                                if sp and ep:
                                    line_ranges.append((sp, ep))
                                i += 3
                            else:
                                p_num = self._resolve_port(tokens[i])
                                if p_num is not None:
                                    line_ranges.append((p_num, p_num))
                                i += 1
                    except Exception:
                        pass

                # 2.2 Неявное имя сервиса в строке
                else:
                    for token in clean_text.split():
                        p_from_map = self.PORT_MAP.get(token)
                        if p_from_map is not None:
                            line_ranges.append((p_from_map, p_from_map))

                # Проверяем вхождение целевого порта в диапазоны и СТРОГОЕ совпадение протокола
                for target_p, req_proto in parsed_targets:
                    proto_match = True
                    if req_proto in ("tcp", "udp"):
                        if line_proto in ("tcp", "udp") and line_proto != req_proto:
                            proto_match = False

                    if not proto_match:
                        continue

                    for start_p, end_p in line_ranges:
                        if start_p <= target_p <= end_p:
                            is_match = True
                            break
                    if is_match:
                        break

            # --- ШАГ 3: Рекурсивный проход для групп Huawei ---
            if not is_match and obj.get("type") == "service_object_ref":
                ref_name = obj.get("name")
                if ref_name and ref_name in self.all_service_sets:
                    svc_set = self.all_service_sets[ref_name]
                    if svc_set.get("type") == "group":
                        sub_objects = self.get_object_group(ref_name)
                        sub_matches = self.check_service(
                            sub_objects,
                            _parsed_targets=parsed_targets
                        )
                        if any(m[1] for m in sub_matches):
                            is_match = True

            result.append((text_raw, is_match))

        return result
    def check_ip(self, objects, ip):
        """Подсветка совпадений по IP (с поддержкой списка через запятую)"""
        if not ip:
            return [(obj.get("text", ""), False) for obj in objects]

        raw_targets = [t.strip() for t in str(ip).split(",") if t.strip()]
        parsed_targets = []

        for target_str in raw_targets:
            try:
                parsed_targets.append(
                    ipaddress.ip_network(target_str, strict=False)
                )
            except ValueError:
                try:
                    parsed_targets.append(
                        ipaddress.ip_network(target_str + "/32")
                    )
                except ValueError:
                    pass

        if not parsed_targets:
            return [(obj.get("text", ""), False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            if obj.get("type") in ["host", "network"] and "network" in obj:
                for target_net in parsed_targets:
                    if target_net.overlaps(obj["network"]):
                        match = True
                        break
            elif obj.get("type") == "range" and "start" in obj and "end" in obj:
                for target_net in parsed_targets:
                    if (
                        obj["start"] <= target_net.network_address <= obj["end"]
                        or obj["start"]
                        <= target_net.broadcast_address
                        <= obj["end"]
                    ):
                        match = True
                        break

            result.append((obj.get("text", ""), match))

        return result

class CiscoPIXParserSVC:

    PORT_MAP = {
        'www': 80,
        'http': 80,
        'https': 443,
        'domain': 53,
        'dns': 53,
        'ssh': 22,
        'telnet': 23,
        'smtp': 25,
        'snmp': 161,
        'snmptrap': 162,
        'ntp': 123,
        'syslog': 514,
        'kerberos': 88,
        'ldap': 389,
        'ldaps': 636,
        'bgp': 179,
        'sip': 5060,
        'ftp': 21,
        'ftp-data': 20,
    }

    def __init__(self, config_text):
        self.config = config_text.replace("\r\n", "\n")
        self.lines = self.config.splitlines()
        self.names = self.parse_all_names()  # Маппинг alias -> info dict
        self.object_networks = self.parse_all_object_networks()
        self.all_service_groups = self.parse_all_service_groups()

    def parse_all_names(self):
        """Парсим директивы name IP ALIAS [description ...]"""
        names_map = {}
        for line in self.lines:
            line_str = line.strip()
            if line_str.startswith("name "):
                parts = line_str.split()
                if len(parts) >= 3:
                    ip_addr = parts[1]
                    alias_name = parts[2]
                    names_map[alias_name] = {
                        "ip": ip_addr,
                        "raw_line": line_str,
                    }
        return names_map

    def _resolve_port(self, val_str):
        val_clean = str(val_str).strip().lower()
        if val_clean.isdigit():
            p = int(val_clean)
            return p if 1 <= p <= 65535 else None
        return self.PORT_MAP.get(val_clean)

    def parse_all_object_networks(self):
        """Парсим object network"""
        objects = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            if line.startswith("object network"):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[2]
                    if i + 1 < len(self.lines):
                        next_line = self.lines[i + 1].strip()
                        if next_line.startswith("range"):
                            p = next_line.split()
                            start = ipaddress.ip_address(p[1])
                            end = ipaddress.ip_address(p[2])
                            objects[name] = {
                                "type": "range",
                                "start": start,
                                "end": end,
                                "text": next_line,
                            }
                            i += 1
                        elif next_line.startswith("host"):
                            ip_val = next_line.split()[1]
                            resolved_ip = (
                                self.names[ip_val]["ip"]
                                if ip_val in self.names
                                else ip_val
                            )
                            try:
                                objects[name] = {
                                    "type": "host",
                                    "network": ipaddress.ip_network(
                                        resolved_ip + "/32"
                                    ),
                                    "text": next_line,
                                }
                            except ValueError:
                                objects[name] = {
                                    "type": "object",
                                    "text": next_line,
                                }
                            i += 1
                        else:
                            objects[name] = {"type": "object", "text": line}
                    else:
                        objects[name] = {"type": "object", "text": line}
            i += 1
        return objects

    def parse_all_service_groups(self):
        """Парсит все object-group service NAME [tcp|udp|ip]"""
        groups = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            if line.startswith("object-group service "):
                parts = line.split()
                group_name = parts[2]
                header_proto = parts[3].lower() if len(parts) >= 4 else None

                members = []
                i += 1
                while i < len(self.lines):
                    curr = self.lines[i].strip()
                    if (
                        not curr
                        or not self.lines[i].startswith(" ")
                        or curr.startswith("object-group")
                    ):
                        break

                    if curr.startswith("description "):
                        i += 1
                        continue

                    members.append(curr)
                    i += 1

                groups[group_name] = {
                    "header_proto": header_proto,
                    "members": members,
                    "text": line,
                }
                continue

            i += 1
        return groups

    def get_object_group(self, group_name):
        """Возвращает содержимое группы, объекта или alias name.

        Если имя не найдено — возвращает None.
        """
        # 1. Поиск среди object-group network
        group_start = None
        for i, line in enumerate(self.lines):
            if line.strip() == f"object-group network {group_name}":
                group_start = i
                break

        if group_start is not None:
            objects = []
            for line in self.lines[group_start + 1 :]:
                if not line.startswith(" "):
                    break
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                parts = line_stripped.split()

                # network-object IP MASK или network-object ALIAS MASK
                if (
                    line_stripped.startswith("network-object")
                    and len(parts) >= 3
                    and parts[1] != "host"
                    and parts[1] != "object"
                ):
                    ip_or_alias = parts[1]
                    mask = parts[2]
                    resolved_ip = (
                        self.names[ip_or_alias]["ip"]
                        if ip_or_alias in self.names
                        else ip_or_alias
                    )
                    try:
                        net = ipaddress.ip_network(
                            f"{resolved_ip}/{mask}", strict=False
                        )
                        objects.append({
                            "text": line_stripped,
                            "type": "network",
                            "network": net,
                        })
                    except ValueError:
                        pass

                # network-object host IP или network-object host ALIAS
                elif (
                    line_stripped.startswith("network-object host")
                    and len(parts) >= 3
                ):
                    host_or_alias = parts[2]
                    resolved_ip = (
                        self.names[host_or_alias]["ip"]
                        if host_or_alias in self.names
                        else host_or_alias
                    )
                    try:
                        objects.append({
                            "text": line_stripped,
                            "type": "host",
                            "network": ipaddress.ip_network(
                                resolved_ip + "/32"
                            ),
                        })
                    except ValueError:
                        pass

                # network-object object NAME
                elif len(parts) >= 3 and parts[1] == "object":
                    objects.append({
                        "text": line_stripped,
                        "type": "object_ref",
                        "name": parts[2],
                    })

            return objects

        # 2. Поиск по одиночной object network
        if group_name in self.object_networks:
            obj = self.object_networks[group_name]
            d = {"text": obj.get("text", ""), "type": obj["type"]}
            if "network" in obj:
                d["network"] = obj["network"]
            if "start" in obj and "end" in obj:
                d["start"] = obj["start"]
                d["end"] = obj["end"]
            return [d]

        # 3. Поиск по object-group service
        if group_name in self.all_service_groups:
            grp = self.all_service_groups[group_name]
            objects = []
            for member_text in grp.get("members", []):
                objects.append({
                    "text": member_text,
                    "type": "service_object_ref",
                    "name": member_text,
                    "header_proto": grp.get("header_proto"),
                })
            return objects

        # 4. Поиск по имени из name (alias -> IP)
        if group_name in self.names:
            ip_str = self.names[group_name]["ip"]
            net = ipaddress.ip_network(f"{ip_str}/32")
            return [{"text": ip_str, "type": "host", "network": net}]

        # Не найдено ничего
        return None

    def check_service(self, objects, target_query=None, target_proto=None, _parsed_targets=None):
        if not objects and not _parsed_targets:
            return []
        if not target_query and not _parsed_targets:
            return [(obj.get("text", ""), False) for obj in (objects or [])]

        # 1. Формируем распарсенный список целей и изолируем протоколы (только на верхнем вызове)
        if _parsed_targets is None:
            raw_elements = [
                q.strip() for q in str(target_query).split(",") if q.strip()
            ]

            exact_only_queries = []
            port_search_queries = []

            for elem in raw_elements:
                if (elem.startswith('"') and elem.endswith('"')) or (
                        elem.startswith("'") and elem.endswith("'")
                ):
                    exact_only_queries.append(elem.strip("'\"").lower())
                else:
                    port_search_queries.append(elem.strip("'\""))

            clean_default_proto = str(target_proto).lower().strip() if target_proto else None
            if clean_default_proto in (None, "", "none"):
                clean_default_proto = None

            parsed_targets = []
            for idx, q_item in enumerate(port_search_queries):
                item_proto = None
                port_str = q_item

                # Префикс "udp/8080" явно указан в самом элементе
                if "/" in q_item:
                    parts = q_item.split("/", 1)
                    item_proto = parts[0].lower().strip()
                    port_str = parts[1].strip()
                # Только первый элемент (idx == 0) подхватывает внешнее значение target_proto
                elif idx == 0 and clean_default_proto:
                    item_proto = clean_default_proto

                if item_proto in (None, "", "none"):
                    item_proto = None
                else:
                    item_proto = item_proto.lower().strip()

                resolved_p = self._resolve_port(port_str)
                if resolved_p is not None:
                    parsed_targets.append((resolved_p, item_proto))
        else:
            parsed_targets = _parsed_targets
            exact_only_queries = []
            port_search_queries = []

        result = []

        for obj in objects:
            is_match = False
            text_raw = obj.get("text", "")
            clean_text = text_raw.lower().strip()
            header_proto = obj.get("header_proto")

            # --- ШАГ 1А: Запрос В КАВЫЧКАХ ---
            for q_exact in exact_only_queries:
                if q_exact == clean_text or q_exact in clean_text.split():
                    is_match = True
                    break

            # --- ШАГ 1Б: Запрос БЕЗ кавычек (по тексту) ---
            if not is_match:
                for q_norm in port_search_queries:
                    clean_q = q_norm.lower().strip()
                    if clean_q == clean_text or clean_q in clean_text.split():
                        is_match = True
                        break

            # --- ШАГ 2: Сопоставление портов и протоколов ---
            if not is_match and parsed_targets:
                line_proto = header_proto
                tokens = clean_text.split()

                if tokens and tokens[0] == "service-object" and len(tokens) >= 2:
                    line_proto = tokens[1]
                elif tokens and tokens[0] == "port-object" and len(tokens) >= 2:
                    if header_proto:
                        line_proto = header_proto

                line_ranges = []

                if "eq" in tokens:
                    idx = tokens.index("eq")
                    for tok in tokens[idx + 1:]:
                        p_num = self._resolve_port(tok)
                        if p_num is not None:
                            line_ranges.append((p_num, p_num))
                        else:
                            break

                elif "range" in tokens:
                    idx = tokens.index("range")
                    if len(tokens) >= idx + 3:
                        sp = self._resolve_port(tokens[idx + 1])
                        ep = self._resolve_port(tokens[idx + 2])
                        if sp and ep:
                            line_ranges.append((sp, ep))

                elif "gt" in tokens:
                    idx = tokens.index("gt")
                    if len(tokens) >= idx + 2:
                        gt_p = self._resolve_port(tokens[idx + 1])
                        if gt_p:
                            line_ranges.append((gt_p + 1, 65535))

                elif "lt" in tokens:
                    idx = tokens.index("lt")
                    if len(tokens) >= idx + 2:
                        lt_p = self._resolve_port(tokens[idx + 1])
                        if lt_p:
                            line_ranges.append((1, lt_p - 1))

                else:
                    for tok in tokens:
                        p_from_map = self.PORT_MAP.get(tok)
                        if p_from_map is not None:
                            line_ranges.append((p_from_map, p_from_map))

                # Проверяем совпадение порта и протокола
                for target_p, req_proto in parsed_targets:
                    proto_match = True
                    if req_proto in ("tcp", "udp"):
                        if line_proto in ("tcp", "udp") and line_proto != req_proto:
                            proto_match = False

                    if not proto_match:
                        continue

                    for start_p, end_p in line_ranges:
                        if start_p <= target_p <= end_p:
                            is_match = True
                            break
                    if is_match:
                        break

            # --- ШАГ 3: Рекурсивный проход по группам ---
            if not is_match and obj.get("type") == "service_group_ref":
                ref_name = obj.get("name")
                if ref_name:
                    sub_objects = self.get_object_group(ref_name)
                    if sub_objects:
                        sub_matches = self.check_service(
                            sub_objects,
                            _parsed_targets=parsed_targets
                        )
                        if any(m[1] for m in sub_matches):
                            is_match = True

            result.append((text_raw, is_match))

        return result
    def check_ip(self, objects, ip):
        if not objects or not ip:
            return [(obj.get("text", ""), False) for obj in (objects or [])]

        raw_targets = [t.strip() for t in str(ip).split(",") if t.strip()]
        parsed_targets = []

        for target_str in raw_targets:
            try:
                parsed_targets.append(
                    ipaddress.ip_network(target_str, strict=False)
                )
            except ValueError:
                try:
                    parsed_targets.append(
                        ipaddress.ip_network(target_str + "/32")
                    )
                except ValueError:
                    pass

        if not parsed_targets:
            return [(obj.get("text", ""), False) for obj in objects]

        result = []
        for obj in objects:
            match = False

            if obj.get("type") in ["host", "network"]:
                for target_net in parsed_targets:
                    if target_net.overlaps(obj.get("network")):
                        match = True
                        break

            elif obj.get("type") == "range":
                for target_net in parsed_targets:
                    if (
                        obj["start"] <= target_net.network_address <= obj["end"]
                        or obj["start"]
                        <= target_net.broadcast_address
                        <= obj["end"]
                    ):
                        match = True
                        break

            elif obj.get("type") == "object_ref":
                name = obj.get("name")
                if name in self.object_networks:
                    ref = self.object_networks[name]
                    for target_net in parsed_targets:
                        if ref["type"] == "range":
                            if (
                                ref["start"]
                                <= target_net.network_address
                                <= ref["end"]
                                or ref["start"]
                                <= target_net.broadcast_address
                                <= ref["end"]
                            ):
                                match = True
                                break
                        elif ref.get("type") in ["host", "network"]:
                            if target_net.overlaps(ref.get("network")):
                                match = True
                                break

            result.append((obj.get("text", ""), match))

        return result

class EltexObjectGroupParserSVC:
    def __init__(self, config_text: str):
        self.config_lines = config_text.splitlines()
        self.network_groups = defaultdict(list)
        self.service_groups = defaultdict(list)
        self._parse()

    def _parse(self):
        current_group_type = None  # 'network' или 'service'
        current_group_name = None

        for line in self.config_lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("!"):
                continue

            # Определяем начало группы network
            if line_str.startswith("object-group network "):
                current_group_type = "network"
                current_group_name = line_str.split()[2]
                continue

            # Определяем начало группы service
            elif line_str.startswith("object-group service "):
                current_group_type = "service"
                current_group_name = line_str.split()[2]
                continue

            # Выход из секции группы
            elif line_str == "exit":
                current_group_type = None
                current_group_name = None
                continue

            # Разбор строк внутри группы network
            if current_group_type == "network" and current_group_name:
                parts = line_str.split()
                if len(parts) >= 3 and parts[0] == "ip" and parts[1] == "prefix":
                    raw_net = parts[2]
                    try:
                        net = ipaddress.ip_network(raw_net, strict=False)
                        self.network_groups[current_group_name].append({
                            "text": line_str,  # Сохраняем "ip prefix 10.36.169.0/24"
                            "type": "network" if net.prefixlen != 32 else "host",
                            "network": net
                        })
                    except ValueError:
                        continue

            # Разбор строк внутри группы service
            elif current_group_type == "service" and current_group_name:
                parts = line_str.split()
                if len(parts) >= 2 and parts[0] == "port-range":
                    raw_port = parts[1]
                    if "-" in raw_port:
                        start_str, end_str = raw_port.split("-", 1)
                        if start_str.isdigit() and end_str.isdigit():
                            self.service_groups[current_group_name].append({
                                "text": line_str,  # Сохраняем "port-range 50001-50005"
                                "type": "port_range",
                                "start": int(start_str),
                                "end": int(end_str)
                            })
                    else:
                        if raw_port.isdigit():
                            port = int(raw_port)
                            self.service_groups[current_group_name].append({
                                "text": line_str,  # Сохраняем "port-range 80"
                                "type": "port",
                                "start": port,
                                "end": port
                            })

    def get_object_group(self, group_name: str):
        if group_name in self.network_groups:
            return self.network_groups[group_name]

        if group_name in self.service_groups:
            return self.service_groups[group_name]

        return None

    def check_service(self, objects, target_query=None, target_proto=None, _parsed_targets=None):
        if not objects and not _parsed_targets:
            return []
        if not target_query and not _parsed_targets:
            return [(obj.get("text", ""), False) for obj in (objects or [])]

        if _parsed_targets is None:
            raw_elements = [
                q.strip() for q in str(target_query).split(",") if q.strip()
            ]

            exact_only_queries = []
            port_search_queries = []

            for elem in raw_elements:
                if (elem.startswith('"') and elem.endswith('"')) or (
                    elem.startswith("'") and elem.endswith("'")
                ):
                    exact_only_queries.append(elem.strip("'\"").lower())
                else:
                    port_search_queries.append(elem.strip("'\""))

            clean_default_proto = str(target_proto).lower().strip() if target_proto else None
            if clean_default_proto in (None, "", "none"):
                clean_default_proto = None

            parsed_targets = []
            for idx, q_item in enumerate(port_search_queries):
                item_proto = None
                port_str = q_item

                if "/" in q_item:
                    parts = q_item.split("/", 1)
                    item_proto = parts[0].lower().strip()
                    port_str = parts[1].strip()
                elif idx == 0 and clean_default_proto:
                    item_proto = clean_default_proto

                if item_proto in (None, "", "none"):
                    item_proto = None
                else:
                    item_proto = item_proto.lower().strip()

                resolved_p = None
                if port_str.isdigit():
                    resolved_p = int(port_str)

                if resolved_p is not None and 1 <= resolved_p <= 65535:
                    parsed_targets.append((resolved_p, item_proto))
        else:
            parsed_targets = _parsed_targets
            exact_only_queries = []
            port_search_queries = []

        result = []

        for obj in objects:
            is_match = False
            text_raw = str(obj.get("text", "")).strip()
            clean_text = text_raw.lower()

            # 1А. Запрос в кавычках (точный поиск)
            for q_exact in exact_only_queries:
                if q_exact == clean_text or q_exact in clean_text.split():
                    is_match = True
                    break

            # 1Б. Запрос без кавычек (попадание подстроки/токена)
            if not is_match:
                for q_norm in port_search_queries:
                    clean_q = q_norm.lower().strip()
                    if clean_q == clean_text or clean_q in clean_text.split():
                        is_match = True
                        break

            # 2. Проверка числовых диапазонов портов
            if not is_match and parsed_targets:
                start_p = obj.get("start")
                end_p = obj.get("end")

                if start_p is not None and end_p is not None:
                    for target_p, req_proto in parsed_targets:
                        if start_p <= target_p <= end_p:
                            is_match = True
                            break

            result.append((text_raw, is_match))

        return result

    def check_ip(self, objects, target_ip):
        if not objects or not target_ip:
            return [(obj.get("text", ""), False) for obj in (objects or [])]

        raw_targets = [t.strip() for t in str(target_ip).split(",") if t.strip()]
        parsed_targets = []

        for t_str in raw_targets:
            try:
                parsed_targets.append(ipaddress.ip_network(t_str, strict=False))
            except ValueError:
                try:
                    parsed_targets.append(ipaddress.ip_network(t_str + "/32"))
                except ValueError:
                    pass

        if not parsed_targets:
            return [(obj.get("text", ""), False) for obj in objects]

        result = []
        for obj in objects:
            match = False
            obj_net = obj.get("network")
            if obj_net:
                for target_net in parsed_targets:
                    if target_net.overlaps(obj_net):
                        match = True
                        break
            result.append((obj.get("text", ""), match))

        return result