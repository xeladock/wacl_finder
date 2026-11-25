import ipaddress
import os

# from get_acl_from_local.unpack_group_core import detect_vendor
from unpack_group_parser import (CiscoASAParserSVC, CiscoIOSXEParserSVC, CiscoFirepowerParserSVC, CiscoNexusParserSVC,
                                 CiscoPIXParserSVC, HuaweiVRPParserSVC, FortigateParserSVC,EltexObjectGroupParserSVC)

# BASE_DIR = "data/config_files_clear"



# BASE_DIR = DATA_DIR + "/config_files_clear"
from path import DATA_DIR
BASE_DIR = DATA_DIR+"/config_files_clear"

vm = {"Cisco ASA": CiscoASAParserSVC,
      "Cisco IOS XE": CiscoIOSXEParserSVC,
      "Cisco FXOS": CiscoFirepowerParserSVC,
      "Cisco NX-OS": CiscoNexusParserSVC,
      "FortiOS": FortigateParserSVC,
      "Huawei VRP": HuaweiVRPParserSVC,
      "Eltex ESR": EltexObjectGroupParserSVC,
      "Cisco PIX": CiscoPIXParserSVC}

def find_device_config(device):

    for root, dirs, files in os.walk(BASE_DIR):
        for f in files:
            if f == device:
                return os.path.join(root, f)
    return None


def get_object_group(device, group):

    path = find_device_config(device)
    # print("path is", path)
    if not path:
        return None, None, "Устройство не найдено."

    vendor = os.path.basename(os.path.dirname(path))
    # print("vendor is", vendor)
    with open(path, encoding="utf8", errors="ignore") as f:
        config = f.read()

    parser=vm.get(vendor)(config)

    if not parser:
        return None, None, "Вендор не поддерживается или не имеет функции object-group."
    # output.config(state="disabled")
    objects = parser.get_object_group(group)

    return parser, objects, None




