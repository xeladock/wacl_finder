# unpack_nat_gui.py
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from path import DATA_DIR
from unpack_nat_core import get_object_group as gog
from unpack_nat_core import detect_vendor as dv
BASE_DIR = DATA_DIR + "/config_files_clear"
from unpack_nat_parser import CiscoASA_NAT_Parser

class NatSearchRequest(BaseModel):
    device: str
    group: str = ""  # Это поле "NAT / IP / Port" из вашей формы
    ip: str = ""


router = APIRouter(prefix="/api/nat", tags=["NAT Viewer"])


@router.post("/search")

async def search_nat_rules(req: NatSearchRequest):
    device = req.device.strip()
    device = device.split(':')[0].strip()
    print('start')
    if not device:
        raise HTTPException(status_code=400, detail="Не указано имя устройства")
    file_path = gog(device)
    print(file_path)
    data = dv(file_path)
    print('data is', data)
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Устройство '{device}' не найдено")

    try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                config_text = f.read()
    except Exception as e:
            raise HTTPException(status_code=500, detail=f"Ошибка чтения конфига: {str(e)}")
    try:
        parser = CiscoASA_NAT_Parser(config_text)

        all_rules = parser.parse_all_nat_rules()
        # print(all_rules)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка парсинга NAT: {str(e)}")

    # Фильтрация, если запрос `group` (NAT / IP / Port) не пустой
    query = req.group.strip()
    if not query:
        matched_rules = all_rules
    else:
        matched_rules = []
        for rule in all_rules:
            # Вызываем наш метод интеллектуального поиска из класса парсера
            if parser.rule_matches_query(rule, query):
                matched_rules.append(rule)
    return {
        "device": req.device,
        "total_found": len(matched_rules),
        "rules": matched_rules
    }