# unpack_nat_gui.py
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from path import DATA_DIR
from unpack_nat_core import get_object_group
from fastapi.responses import FileResponse
# from unpack_nat_core import detect_vendor as dv
BASE_DIR = DATA_DIR + "/config_files_clear"
from unpack_nat_parser import CiscoASA_NAT_Parser

class NatSearchRequest(BaseModel):
    device: str
    group: str = ""  # Это поле "NAT / IP / Port" из вашей формы
    # ip: str = ""


router = APIRouter(prefix="/api/nat", tags=["NAT Viewer"])


@router.post("/search")
async def search_nat_rules(req: NatSearchRequest):
    device = req.device.strip().split(':')[0].strip()
    if not device:
        raise HTTPException(status_code=400, detail="Не указано имя устройства")

    # Получаем путь, парсер и возможную ошибку за один вызов
    file_path, parser_class, err = get_object_group(device)
    if err:
        raise HTTPException(status_code=400, detail=err)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            config_text = f.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка чтения конфига: {str(e)}")

    try:
        parser = parser_class(config_text)
        all_rules = parser.parse_all_nat_rules()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка парсинга NAT: {str(e)}")

    query = req.group.strip()
    if not query:
        matched_rules = all_rules
    else:
        matched_rules = [r for r in all_rules if parser.rule_matches_query(r, query)]

    return {
        "device": req.device,
        "total_found": len(matched_rules),
        "rules": matched_rules
    }

page_router = APIRouter(tags=["Pages"])
@router.get("/nat_viewer_exp.html")
async def get_nat_exp_page():
    # Определяем абсолютный путь к папке со скриптом и поднимаемся к static
    base_path = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_path, "static", "html", "nat_viewer_exp.html") # или "static", "html", "nat_viewer_exp.html"
    return FileResponse(file_path)


from exp_nat_parser import parse_device_config, expand_object_name

# Если у вас уже есть router в этом файле (например, для отдачи nat_viewer_exp.html),
# используйте его. Если не

from unpack_group_core import find_device_config, vm
import os


@router.get("/detail")
async def get_nat_rule_detail(device: str, line: int):
    # 1. Находим путь к файлу устройства
    file_path = find_device_config(device)
    if not file_path:
        raise HTTPException(status_status=404, detail=f"Конфиг устройства {device} не найден")

    # 2. Определяем вендора
    vendor = os.path.basename(os.path.dirname(file_path))

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            config_text = f.read()
    except Exception as e:
        raise HTTPException(status_status=500, detail=f"Ошибка чтения конфига: {str(e)}")

    parser_class = vm.get(vendor)
    if not parser_class:
        raise HTTPException(status_status=400, detail=f"Вендор {vendor} не поддерживается")

    parser = parser_class(config_text)

    # 3. Находим нужную строку правила по номеру `line`
    lines = config_text.splitlines()
    target_line_text = ""
    if 0 <= line - 1 < len(lines):
        target_line_text = lines[line - 1].strip()

    # 4. Распаковываем тестовую группу (позже заменим на динамическую из строки)
    raw_objects = parser.get_object_group("Net_Monitoring_SHPD") or []

    lines_output = []
    for item in raw_objects:
        if isinstance(item, dict):
            net_val = item.get("network") or item.get("text") or item.get("ip")
            if net_val:
                lines_output.append(str(net_val))
            else:
                lines_output.append(str(item))
        else:
        # Использование точного формата и структуры данных
            lines_output.append(str(item))

    if not lines_output:
        lines_output = ["Объект не найден"]

    unpacked_text = "\n".join(lines_output)

    # 5. Возвращаем строгий JSON-объект, который ждет фронтенд
    return {
        "forms": {
            "pre_snat": f"Строка #{line}: {target_line_text}\n\nРаспаковка:\n{unpacked_text}",
            "post_snat": "interface",
            "pre_dnat": "Пример назначения (pre)",
            "post_dnat": "Пример назначения (post)"
        }
    }