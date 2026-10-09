import ipaddress
import os

from get_acl_from_local.unpack_group_core import detect_vendor
from unpack_group_parser import (CiscoASAParserSVC, CiscoIOSXEParserSVC, CiscoFirepowerParserSVC, CiscoNexusParserSVC,
                                 CiscoPIXParserSVC, HuaweiVRPParserSVC, FortigateParserSVC,EltexObjectGroupParserSVC)

# BASE_DIR = "data/config_files_clear"



# BASE_DIR = DATA_DIR + "/config_files_clear"
from path import DATA_DIR
BASE_DIR = DATA_DIR+"/config_files_clear"


def find_device_config(device):

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

detect_vendor_map={
    "Cisco ASA": "cisco_asa",
    "Cisco IOS XE": "cisco_ios_xe",
    "Cisco FXOS" : "cisco_fxos",
    "Cisco NX-OS" : "cisco_nxos",
    "FortiOS" : "fortigate",
    "Huawei VRP" : "huawei_vrp",
    "Eltex ESR" : "eltex_esr",
    "Cisco PIX" : "cisco_pix"
}

def detect_vendor(path):
    detect_vendor_map = {
        "Cisco ASA": "cisco_asa",
        "Cisco IOS XE": "cisco_ios_xe",
        "Cisco FXOS": "cisco_fxos",
        "Cisco NX-OS": "cisco_nxos",
        "FortiOS": "fortigate",
        "Huawei VRP": "huawei_vrp",
        "Eltex ESR": "eltex_esr",
        "Cisco PIX": "cisco_pix"
    }
    spath = path.split('/')[-2]
    return detect_vendor_map.get(spath)


def get_object_group(device, group):

    path = find_device_config(device)
    print("path is", path)
    if not path:
        return None, None, "Устройство не найдено."

    vendor_map={
        "cisco_asa":CiscoASAParserSVC,
        "cisco_ios_xe":CiscoIOSXEParserSVC,
        "cisco_fxos":CiscoFirepowerParserSVC,
        "cisco_nxos":CiscoNexusParserSVC,
        "fortigate":FortigateParserSVC,
        "huawei_vrp":HuaweiVRPParserSVC,
        "cisco_pix":CiscoPIXParserSVC,
        "eltex_esr":EltexObjectGroupParserSVC
    }

    vendor = detect_vendor(path)
    # print("vendor is", vendor)
    with open(path, encoding="utf8", errors="ignore") as f:
        config = f.read()

    parser=vendor_map.get(vendor)(config)

    if not parser:
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

