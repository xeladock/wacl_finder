import ipaddress
import os

from unpack_group_parser import (CiscoASAParserSVC, CiscoIOSXEParserSVC, CiscoFirepowerParserSVC, CiscoNexusParserSVC,
                                 CiscoPIXParserSVC, HuaweiVRPParserSVC, FortigateParserSVC,EltexObjectGroupParserSVC)

# BASE_DIR = "data/config_files_clear"



# BASE_DIR = DATA_DIR + "/config_files_clear"
from path import DATA_DIR
BASE_DIR = DATA_DIR+"/config_files_clear"


def find_device_config(device):
    # print("devise is", device)

    # if device == "":
    #     return "пусто"
    for root, dirs, files in os.walk(BASE_DIR):
        for f in files:
            if f == device:
                return os.path.join(root, f)


    return None


# VENDOR_MAP = {
#     "Cisco ASA": CiscoASAParser,
#     "Cisco IOS XE": CiscoIOSXEParser,
#     "Cisco FXOS": CiscoFirepowerParser,
#     "Cisco NX-OS": CiscoNexusParser,
#
# }

def detect_vendor(path):

    if "Cisco ASA" in path:
        return "cisco_asa"
    if "Cisco IOS XE" in path:
        return "cisco_ios_xe"
    if "Cisco FXOS" in path:
        return "cisco_fxos"
    if "Cisco NX-OS" in path:
        return "cisco_nxos"
    if "FortiOS" in path:
        return "fortigate"
    if "Cisco PIX" in path:
        return "cisco_pix"
    if "Huawei VRP" in path:
        return "huawei_vrp"
    if "Eltex ESR" in path:
        return "eltex_esr"

    return None
def get_object_group(device, group):

    path = find_device_config(device)
    # print("path is", path)
    if not path:
        return None, None, "Устройство не найдено."

    vendor = detect_vendor(path)
    # print("vendor is", vendor)
    with open(path, encoding="utf8", errors="ignore") as f:
        config = f.read()

    if vendor == "cisco_asa":
        parser = CiscoASAParserSVC(config)
    elif vendor == "cisco_ios_xe":
        parser = CiscoIOSXEParserSVC(config)
    elif vendor == "cisco_fxos":
        parser = CiscoFirepowerParserSVC(config)
    elif vendor == "cisco_nxos":
        parser = CiscoNexusParserSVC(config)
    elif vendor == "fortigate":
        parser = FortigateParserSVC(config)
    elif vendor == "huawei_vrp":
        parser = HuaweiVRPParserSVC(config)
    elif vendor == "cisco_pix":
        parser = CiscoPIXParserSVC(config)
    elif vendor == "eltex_esr":
        parser = EltexObjectGroupParserSVC(config)


    else:
        return None, None, "Вендор не поддерживается или не имеет функции object-group."
    # output.config(state="disabled")
    objects = parser.get_object_group(group)

    return parser, objects, None


# def get_object_group(device, group):
#     path = find_device_config(device)
#     print(path)
#     if not path:
#         return None, "Device not found"
#     vendor = detect_vendor(path)
#     with open(path, encoding="utf8", errors="ignore") as f:
#         config = f.read()
#     if vendor == "cisco_asa":
#         parser = CiscoASAParser(config)
#     elif vendor == "huawei_vrp":
#         parser = HuaweiVRPParser(config)
#     else:
#         return None, "Unsupported vendor"
#     objects = parser.get_object_group(group)
#     return objects, None

