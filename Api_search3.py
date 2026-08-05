import os
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
from collections import defaultdict
from class_resolver import (CiscoNexusParser, JuniperACLParser, FortiOSParser,
                            CiscoIOSXEParser, CiscoIOSParser, EltexACLParser, CiscoASAParser3, EltexESRParser,
                            HPEParser, HuaweiParser3
                            )

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

output_dir = "data/config_files_clear"

# PREFIX_LABELS = {
#     "(Волга)": "PRNG-DC",
#     "(Дальний Восток)": "DV",
#     "(Северо-Запад)": "SZSP-DC",
#     "(Центр)": "CEMO-DC",
#     "(Корпоративный Центр)": "CEMS-DC",
#     "(Урал)": "UREK-DC",
#     "(Юг)": "UFKR-DC",
#     "(Сибирь)": "SI",
# }
# для вывода PREFIX_LABELS
PREFIX_LABELS = {
    "(Корпоративный Центр)": "CEMS",
    "(Центр)": "CE",
    "(Волга)": "PR",
    "(Дальний Восток)": "DV",
    "(Северо-Запад)": "SZ",
    "(Урал)": "UR",
    "(Юг)": "UF",
    "(Сибирь)": "SI"
}
# для расчета в список dd
FIX_LABELS = {"КЦ": "CEMS",
    "Центр": "CE",
    "Волга": "PR",
    "ДВ": "DV",
    "СЗ": "SZ",
    "Урал": "UR",
    "Юг": "UF",
    "Сибирь": "SI"}




def region(vv):
    region_name = next(
        (label for label, prefix in PREFIX_LABELS.items() if vv.startswith(prefix))
    )
    # print("vv:",vv)
    return region_name

def main(src_ip, dst_ip, allowed_prefixes=None, allowed_platforms=None, allowed_ues=None, strict_mode=False):
    print(allowed_prefixes, allowed_platforms,allowed_ues)

    if not os.path.exists(output_dir):
        yield  ["❌ Папка с конфигурациями не найдена"]
        return

    search_text = [src_ip, dst_ip]
    # print("search_text:",search_text)
    dd = defaultdict(list)

    # prefix_to_region = {v: k for k, v in PREFIX_LABELS.items()}
    for root, dirs, files in os.walk(output_dir):
        # print(output_dir)
        parts = root.split(os.sep)
        # print(parts)
        if len(parts) < 4:
            continue

        loc = parts[-2]  # ЛВС / ЦОД

        pl = parts[-1]  # платформа (Cisco, FortiOS, Huawei...)

        # print("loc pl is:",loc,pl)
        # Фильтрация
        # print("проверка 1:", allowed_ues, loc)
        if loc not in allowed_ues:
            continue

            # Фильтр по платформе
        # print("проверка 2:", allowed_platforms, pl)
        if pl not in allowed_platforms:
            continue
        # print("фин пре: ", loc,pl)
        # После os.walk
        # print("ПРОВЕРКА 3:", allowed_prefixes)

        for i in allowed_prefixes:
            reg = FIX_LABELS.get(i)
            print("reg is:", reg, i)
            # print("reg is:", reg)
            # print("reg is:", reg)
            if reg:
                for file in files:
                    if i == "Центр":
                        if file.startswith("CE") and not file.startswith("CEMS"):
                            dd[(loc, pl)].append(file)

                        # 2. Стандартная логика для всех остальных регионов (КЦ, Волга, Урал и т.д.)
                    else:
                        if file.startswith(reg):
                            dd[(loc, pl)].append(file)



    print("DEBUG: dd после фильтрации =", dict(dd))
    # print(dd)
    # results = []
    # print(dd)
    print(allowed_ues, "allow_ues")
    print("allowed_prefixes:", allowed_prefixes)
    print("allowed_platforms:", allowed_platforms)
    print("dd: ",dd)
    for (k1, k2), v in dd.items():
        # print("k2 is:", k2)
        if allowed_platforms and k2 not in allowed_platforms:
            continue
        if k2 == 'FortiOS':
            # print(k1,k2,v)
            for vv in v:
                res = FortiOSParser.from_local_file(vv, search_text[0], search_text[1],strict_mode=strict_mode)
                # print(res)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k2 in ('Cisco ASA', 'Cisco FXOS', 'Cisco PIX'):
            # print(k ,v)
            for vv in v:
                res = CiscoASAParser3.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                # print(res)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k2 in ('Cisco IOS','HP ProCurve','B4COM BCOM-OS-DC', 'B4COM BCOM-OS-DC (VXLAN)','EdgeCore','IBM_Lenovo Network OS','Dell Networking OS') :
            for vv in v:
                res = CiscoIOSParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k2 in ('Cisco IOS XE','Cisco IOS XR'):
            for vv in v:
                # print(vv)
                res = CiscoIOSXEParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                # print(res)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k2 == 'Cisco NX-OS':
            for vv in v:
                res = CiscoNexusParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k2 in ('Huawei VRP','Huawei VRP 2403'):
            for vv in v:
                res = HuaweiParser3.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k2 == 'Juniper Junos':
            for vv in v:
                res = JuniperACLParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k2 == 'Eltex':
            for vv in v:
                res = EltexACLParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    # print(res)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k2 == 'Eltex ESR':
            # print(v)
            for vv in v:
                res = EltexESRParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                print(res)
                if res:
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        # if k2  == 'HP ProCurve' :
        #     for vv in v:
        #         res = CiscoIOSParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         if res:
        #             yield(f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        if k2 in ('HPE OfficeConnect', 'HPE Comware 1910', 'HPE Comware','3Com Comware 1910'):
            for vv in v:  # список файлов
                res = HPEParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")

    # return results


# if __name__ == "__main__":
#     if len(sys.argv) < 3:
#         print("Использование: python Api-search3.py <src_ip> <dst_ip> [prefix1 prefix2 ...] [--platforms ...]")
#         sys.exit(1)
#
#     src_ip, dst_ip = sys.argv[1], sys.argv[2]
#
#     if "--platforms" in sys.argv:
#         idx = sys.argv.index("--platforms")
#         allowed_prefixes = sys.argv[3:idx]
#         allowed_platforms = sys.argv[idx + 1:]
#     else:
#         allowed_prefixes = sys.argv[3:]
#         allowed_platforms = None
#
#     res = main(src_ip, dst_ip, allowed_prefixes, allowed_platforms)
#     for line in res:
#         print(line)