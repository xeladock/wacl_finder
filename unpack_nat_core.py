# unpack_nat_core.py
import os
from unpack_nat_parser import CiscoASA_NAT_Parser
from path import DATA_DIR
BASE_DIR = DATA_DIR + "/config_files_clear"


def find_device_config(device):

    for root, dirs, files in os.walk(BASE_DIR):
        for f in files:
            if f == device:
                return os.path.join(root, f)
    return None




# def detect_vendor(path):
#     if not path or not isinstance(path, str):
#         return None
#
#     detect_vendor_map = {
#         "Cisco ASA": CiscoASA_NAT_Parser,
#         "Cisco IOS XE": "cisco_ios_xe",
#         "Cisco FXOS": "cisco_fxos",
#         "Cisco NX-OS": "cisco_nxos",
#         "FortiOS": "fortigate",
#         "Huawei VRP": "huawei_vrp",
#         "Eltex ESR": "eltex_esr",
#         "Cisco PIX": "cisco_pix"
#     }
#     try:
#         spath = path.split('/')[-2]
#     except Exception:
#         return None
#     # spath = "abc"
#     print('spath is', spath)
#     print(detect_vendor_map.get(spath))
#     return detect_vendor_map.get(spath)


# def detect_vendor(path):
#     print("функ детект")
#     if not path or not isinstance(path, str):
#         return None
#
#     detect_vendor_map = {
#         "Cisco ASA": CiscoASA_NAT_Parser,
#         "Cisco IOS XE": "cisco_ios_xe",
#         "Cisco FXOS": "cisco_fxos",
#         "Cisco NX-OS": "cisco_nxos",
#         "FortiOS": "fortigate",
#         "Huawei VRP": "huawei_vrp",
#         "Eltex ESR": "eltex_esr",
#         "Cisco PIX": "cisco_pix"
#     }
#
#     try:
#         # Кроссплатформенно извлекаем имя папки вендора (например, "Cisco ASA") независимо от / или \
#         spath = os.path.basename(os.path.dirname(path))
#     except Exception as e:
#         print(f"Ошибка определения вендора: {e}")
#         return None
#
#     print(f"[DETECT VENDOR] Определен вендор (spath): '{spath}'")
#     return detect_vendor_map.get(spath)


def get_object_group(device):
    path = find_device_config(device)
    print('path is', path)
    if not path:
        return None, None, "Устройство не найдено."

    # Кроссплатформенно извлекаем вендора из пути (например, "Cisco ASA")
    vendor = os.path.basename(os.path.dirname(path))
    print(vendor)
    # Единый словарь соответствия вендоров и их NAT-парсеров
    detect_vendor_map = {
        "Cisco ASA": CiscoASA_NAT_Parser,
        # При необходимости здесь можно добавить другие вендоры в будущем
    }

    parser_class = detect_vendor_map.get(vendor)
    if not parser_class:
        return None, None, "Вендор не поддерживается или не имеет функции NAT."

    return path, parser_class, None