import ipaddress
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from pygments.lexer import default

from unpack_group_core import get_object_group

# Создаем роутер с префиксом, чтобы не путать с другими путями
router = APIRouter(prefix="/api/og", tags=["OG Viewer"])

print("it's group_enter")

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


@router.post("/search")
async def search_og(data: OGSearchRequest):
    device = data.device.strip()
    group = data.group.strip()
    ip = data.ip.strip()
    print("dgp:",device, group, ip)
    if not device:
        raise HTTPException(status_code=400, detail="Введите название устройства.")
    if not group:
        raise HTTPException(status_code=400, detail="Введите название Object-group.")
    if not validate_ip_or_network2(ip):
        raise HTTPException(status_code=400, detail="Некорректный формат ip-адреса или сети.")

    try:
        # Вызываем ваш оригинальный парсер
        parser, objects, err = get_object_group(device, group)

        if err:
            raise HTTPException(status_code=400, detail=str(err))
        if not objects:
            raise HTTPException(status_code=400, detail="Object-group не найден.")

        # Если IP не передан
        if not ip:
            results = [{"text": obj["text"], "bold": False} for obj in objects]
            return {"results": results}

        # Если IP передан
        check_results = parser.check_ip(objects, ip)

        results = []
        cnt=0
        for text, match in check_results:
            if match:
                cnt+=1
                results.append({"text": text, "bold": True})
            else:
                results.append({"text": text, "bold": False})

        if not cnt:
            return {"results": [{"text": "Совпадений не найдено.", "bold": True}]}

        else:
            results.insert(0,{"text": f"Найдено совпадений:{cnt}\n", "italic": True})

        return {"results": results}

    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        print(e)
        raise HTTPException(status_code=500, detail=f"Внутренняя ошибка сервера: {str(e)}")