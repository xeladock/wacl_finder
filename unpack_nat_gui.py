# unpack_nat_gui.py
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from path import DATA_DIR
from unpack_nat_core import get_object_group
from fastapi.responses import FileResponse
# from unpack_nat_core import detect_vendor as dv
BASE_DIR = DATA_DIR + "/config_files_clear"
from unpack_nat_parser import Detail_FXOS_Parser, Detail_ASA_Parser


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

import re

from typing import Union, Optional

from unpack_nat_parser import CiscoASA_NAT_Parser, Detail_FXOS_Parser


@router.get("/detail")
async def get_nat_rule_detail(
        device: str,
        line: Union[int, str] = 1,
        index: Optional[Union[int, str]] = None
):
    try:
        line_num = int(line)
    except (TypeError, ValueError):
        try:
            line_num = int(index) if index is not None else 1
        except (TypeError, ValueError):
            line_num = 1

    file_path = find_device_config(device)
    if not file_path:
        raise HTTPException(status_code=404, detail=f"Конфиг устройства {device} не найден")

    vendor = os.path.basename(os.path.dirname(file_path))
    vendor_lower = vendor.lower()

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            config_text = f.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка чтения конфига: {str(e)}")

    # Чистое разделение по классам вендоров
    if "fxos" in vendor_lower:
        parser = Detail_FXOS_Parser(config_text)
        return parser.get_details(line_num)

    elif "asa" in vendor_lower:
        # Аналогично вынесем в Detail_ASA_Parser следующим шагом
        parser = Detail_ASA_Parser(config_text)  # пока временно через тот же класс или фоллбэк
        return parser.get_details(line_num)

    elif "ios" in vendor_lower:
        # Логика для IOS XE
        # ...
        pass

    raise HTTPException(status_code=400, detail=f"Неподдерживаемый вендор: {vendor}")