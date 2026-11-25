import re


def parse_device_config(config_text: str):
    """Парсит конфиг устройства и возвращает словарь всех сетевых групп и объектов."""
    object_groups = {}
    current_group = None

    for line in config_text.splitlines():
        line = line.strip()

        # Парсим object-group network
        match_group = re.match(r"^object-group network\s+(\S+)", line)
        if match_group:
            current_group = match_group.group(1)
            object_groups[current_group] = []
            continue

        if current_group and line.startswith("network-object"):
            # Извлекаем IP или имя подсети/другой группы из строки network-object
            parts = line.split()
            if len(parts) >= 2:
                obj_val = parts[1]  # Это может быть IP или имя другой группы
                object_groups[current_group].append(obj_val)
        elif line.startswith("!"):
            current_group = None

    return object_groups


def expand_object_name(obj_name: str, object_groups: dict, visited=None) -> list:
    """Рекурсивно разворачивает имя объекта или группы в список конкретных IP/подсетей."""
    if visited is None:
        visited = set()

    if obj_name in visited:
        return []
    visited.add(obj_name)

    results = []
    if obj_name in object_groups:
        for item in object_groups[obj_name]:
            # Проверяем, является ли элемент вложенной группой или конкретным IP
            if item in object_groups:
                results.extend(expand_object_name(item, object_groups, visited))
            else:
                results.append(item)
    else:
        # Если это не группа, а конкретный IP (или ключевое слово вроде 'interface')
        results.append(obj_name)

    return results