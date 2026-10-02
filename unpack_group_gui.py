import ipaddress
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import re
from pygments.lexer import default

from unpack_group_core import get_object_group

# Создаем роутер с префиксом, чтобы не путать с другими путями
router = APIRouter(prefix="/api/og", tags=["OG Viewer"])

# Описываем входящие данные
class OGSearchRequest(BaseModel):
    device: str
    group: str
    ip: str = ""


def validate_ip_or_network2(value: str) -> bool:
    if not value or value.lower() == "any":
        return True
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


import re
import ipaddress


# def validate_search_query(value: str) -> bool:
#     """Проверяет корректность поискового запроса (IP, порты, proto/port, proto/service_name)"""
#     if not value or value.lower() == "any":
#         return True
#
#     items = [item.strip() for item in value.split(",") if item.strip()]
#     if not items:
#         return True
#
#     for item in items:
#         item_valid = False
#
#         # 1. Проверка IP / Network / CIDR
#         try:
#             ipaddress.ip_network(item, strict=False)
#             item_valid = True
#         except ValueError:
#             pass
#
#         # 2. Проверка proto/port или proto/service_name (udp/53, tcp/domain, udp/domain)
#         if not item_valid and "/" in item:
#             parts = item.split("/", 1)
#             proto = parts[0].lower().strip()
#             val = parts[1].lower().strip()
#
#             if proto in ("tcp", "udp", "ip"):
#                 # Валидно, если после слэша идут цифры ИЛИ имя сервиса (буквы/дефисы)
#                 if val.isdigit() or re.match(r"^[a-z0-9\-_]+$", val):
#                     item_valid = True
#
#         # 3. Числовой порт (1-65535)
#         if not item_valid and item.isdigit() and 1 <= int(item) <= 65535:
#             item_valid = True
#
#         # 4. Имя сервиса без слэша (ssh, domain, https и т.д.)
#         if not item_valid and re.match(r"^[a-z0-9\-_]+$", item.lower()):
#             item_valid = True
#
#         if not item_valid:
#             return False
#
#     return True
def validate_search_query(value: str) -> bool:
    """Универсальная валидация: пропускает любые поисковые запросы."""
    if not value or value.lower() == "any":
        return True
    return True

@router.post("/search")
async def search_og(data: OGSearchRequest):
    device = data.device.strip()
    device = device.split(':')[0].strip()
    group = data.group.strip()
    query = data.ip.strip()
    print("query is", query)
    # print("dgp:",device, group, ip)
    if not device:
        raise HTTPException(status_code=400, detail="Введите название устройства.")
    if not group:
        raise HTTPException(status_code=400, detail="Введите название Object-group.")
    if not validate_search_query(query):
        raise HTTPException(status_code=400, detail="Некорректный формат IP-адреса, сети или порта/сервиса.")

    try:
        # Вызываем парсер для устройства
        parser, objects, err = get_object_group(device, group)

        if err:
            raise HTTPException(status_code=400, detail=str(err))
        if not objects:
            raise HTTPException(status_code=400, detail="Object-group не найден.")

        # Если поисковый запрос пустой / any
        if not query or query.lower() == "any":
            results = [{"text": obj["text"], "bold": False} for obj in objects]
            return {"results": results}

        # Определяем, является ли группа сервисной
        is_service_group = any(
            obj.get("type") in (
            "service", "service_group_ref", "service_object", "service_object_ref", "service_single")
            for obj in objects
        )

        # Выполняем поиск в зависимости от типа группы
        if is_service_group:
            # Если передано например 'tcp/80', разбираем протокол и порт
            target_proto = None
            target_port = query

            if "/" in query and not query.startswith("1"):  # защита от случайных /24
                parts = query.split("/")
                if len(parts) == 2 and parts[0].lower() in ("tcp", "udp", "ip"):
                    target_proto = parts[0].lower()
                    target_port = parts[1]

            # Вызываем метод поиска по сервисам
            if hasattr(parser, 'check_service'):
                try:
                    check_results = parser.check_service(objects, target_port, target_proto)
                    print("cr",check_results)
                except TypeError as e:
                    # Резервный вызов, если парсер принимает только позиционные аргументы (objects, target_port, target_proto)
                    check_results = parser.check_service(objects, target_port, target_proto)
                    print(e)
            else:
                check_results = [(obj["text"], False) for obj in objects]
                print("else 1")
        else:
            print("else 2")
            # Стандартный поиск по IP-адресам/сетям
            check_results = parser.check_ip(objects, query)

        # Формируем ответ
        print("check_results is", check_results )
        results = []
        cnt = 0
        for text, match in check_results:
            if match:
                cnt += 1
                results.append({"text": text + "  ✔", "bold": True})
            else:
                results.append({"text": text, "bold": False})

        if not cnt:
            return {"results": [{"text": "Совпадений не найдено.", "empty": True}]}
        else:
            results.insert(0, {"text": f"Найдено совпадений: {cnt}\n", "italic": True})

        return {"results": results}

    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=f"⚠️ Внутренняя ошибка сервера: {str(e)}")