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

import re

from typing import Union, Optional


@router.get("/detail")
async def get_nat_rule_detail(
        device: str,
        line: Union[int, str] = 1,
        index: Optional[Union[int, str]] = None
):
    # Безопасно преобразуем line в int, исключая падения валидации
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

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            config_text = f.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка чтения конфига: {str(e)}")

    # Динамически выбираем правильный парсер под вендора (ASA, FXOS, IOS XE)
    parser_class = vm.get(vendor)
    if not parser_class:
        parser_class = CiscoASA_NAT_Parser  # фоллбэк

    try:
        nat_parser = parser_class(config_text)
        all_rules = nat_parser.parse_all_nat_rules() if hasattr(nat_parser, "parse_all_nat_rules") else []
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка парсинга NAT правил: {str(e)}")

    # 1. Ищем правило по точному совпадению line_number или line_num
    target_rule = None
    for r in all_rules:
        if r.get("line_number") == line_num or r.get("line") == line_num or r.get("index") == line_num:
            target_rule = r
            break

    # Страховка по индексу с использованием line_num
    if not target_rule and all_rules:
        idx = line_num - 1
        if 0 <= idx < len(all_rules):
            target_rule = all_rules[idx]
        else:
            target_rule = all_rules[0]

    # Берем сырую строку из правила или из файла
    raw_line = ""
    if target_rule:
        raw_line = target_rule.get("raw_line") or target_rule.get("details") or ""

    if not raw_line and config_text:
        lines = config_text.splitlines()
        if 0 <= line_num - 1 < len(lines):
            raw_line = lines[line_num - 1].strip()

    group_parser = parser_class(config_text) if parser_class else None

    real_interface, mapped_interface = "", ""
    intf_match = re.search(r'nat\s*\(([^,]+),\s*([^)]+)\)', raw_line)
    if intf_match:
        real_interface = intf_match.group(1).strip()
        mapped_interface = intf_match.group(2).strip()

    src_orig, src_trans, dst_orig, dst_trans = "", "", "", ""

    try:
        src_match = re.search(r'source\s+(?:static|dynamic)\s+(\S+)(?:\s+(\S+))?', raw_line)
        if src_match:
            src_orig = src_match.group(1) or ""
            src_trans = src_match.group(2) or ""

        dst_match = re.search(r'destination\s+(?:static|dynamic)\s+(\S+)\s+(\S+)', raw_line)
        if dst_match:
            dst_orig = dst_match.group(1) or ""
            dst_trans = dst_match.group(2) or ""
    except Exception:
        pass

    def resolve_obj(obj_name, is_translated_side=False):
        obj_str = str(obj_name).strip()
        if obj_str.lower() == "interface" or not obj_str:
            if is_translated_side and mapped_interface:
                return [f"dynamic interface ({mapped_interface})"]
            return [obj_str if obj_str else "—"]

        if obj_str in ["any", "—"]:
            return [obj_str]

        if not group_parser or not hasattr(group_parser, "get_object_group"):
            return [obj_str]

        unpacked = group_parser.get_object_group(obj_str)
        if not unpacked:
            return [obj_str]

        res = []
        for item in unpacked:
            if isinstance(item, dict):
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