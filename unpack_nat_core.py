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




def detect_vendor(path):
    detect_vendor_map = {
        "Cisco ASA": CiscoASA_NAT_Parser,
        "Cisco IOS XE": "cisco_ios_xe",
        "Cisco FXOS": "cisco_fxos",
        "Cisco NX-OS": "cisco_nxos",
        "FortiOS": "fortigate",
        "Huawei VRP": "huawei_vrp",
        "Eltex ESR": "eltex_esr",
        "Cisco PIX": "cisco_pix"
    }

    spath = path.split('/')[-2]
    print('spath is', spath)
    return detect_vendor_map.get(spath)


def get_object_group(device):

    path = find_device_config(device)
    # print("path is", path)
    if not path:
        return None, None, "Устройство не найдено."

    return path