import os
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
from collections import defaultdict
from class_resolver import (CiscoNexusParser2, JuniperACLParser2, FortiOSParser2,
                            CiscoIOSXEParser2, CiscoIOSParser2, EltexACLParser2, CiscoASAParser5, EltexESRParser2,
                            HPEParser2, HuaweiParser4, ACLParserFactory, QTechParser
                            )

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
# print("здесь 1:",APP_DIR)

from path import DATA_DIR


output_dir = DATA_DIR+"/config_files_clear"

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
    "Корпоративный Центр": "CEMS",
    "Центр": "CE",
    "Волга": "PR",
    "Дальний Восток": "DV",
    "Северо-Запад": "SZ",
    "Урал": "UR",
    "Юг": "UF",
    "Сибирь": "SI"
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

PARSERS_MAP = {
    'Cisco ASA': CiscoASAParser5,
    'Cisco FXOS': CiscoASAParser5,
    'Cisco PIX': CiscoASAParser5,
    'FortiOS': FortiOSParser2,
    'Cisco IOS': ACLParserFactory,
    'Cisco IOS XE': CiscoIOSXEParser2,
    'Cisco IOS XR': CiscoIOSXEParser2,
    'HP ProCurve': ACLParserFactory,
    'B4COM BCOM-OS-DC': ACLParserFactory,
    'B4COM BCOM-OS-DC (VXLAN)': ACLParserFactory,
    'EdgeCore': CiscoIOSParser2,
    'IBM_Lenovo Network OS': ACLParserFactory,
    'Dell Networking OS': ACLParserFactory,
    'Cisco NX-OS':CiscoNexusParser2,
    'Huawei VRP': HuaweiParser4,
    'Huawei VRP 2403': HuaweiParser4,
    'Juniper Junos': JuniperACLParser2,
    'Eltex': EltexACLParser2,
    'Eltex ESR': EltexESRParser2,
    'HPE OfficeConnect': HPEParser2,
    'HPE Comware 1910': HPEParser2,
    'HPE Comware':HPEParser2,
    '3Com Comware 1910':HPEParser2,
    'QTECH NOS': QTechParser,
}




def region(vv):
    region_name = next(
        (label for label, prefix in PREFIX_LABELS.items() if vv.startswith(prefix))
    )
    # print("vv:",vv)
    return region_name

def main(src_ip, dst_ip, allowed_prefixes=None, allowed_platforms=None, allowed_ues=None, strict_mode=False,ignore_src_any=False,
        ignore_dst_any=False, src_mask_limit=None, dst_mask_limit=None):

    search_text = (src_ip, dst_ip)
    dd = defaultdict(list)
    # print("base dd")
    # prefix_to_region = {v: k for k, v in PREFIX_LABELS.items()}
    # print("begis any_boxes is: ", ignore_src_any, ignore_dst_any)
    for root, dirs, files in os.walk(output_dir,followlinks=True):
        # print("rdf", root, dirs, files)
        # parts = root.split(os.sep)[1:]
        parts = root.lstrip(os.sep).split(os.sep)
        # print("parts is:", parts)
        if len(parts) <= 4:
            # print("path is:",len(parts))
            continue
        # print("переход!")
        loc = parts[-2]  # ЛВС / ЦОД

        pl = parts[-1]  # платформа (Cisco, FortiOS, Huawei...)
        # print("allowed_ues is:",allowed_ues, loc, pl)
        # print("loc pl is:",loc,pl)
        # print("loc pl is:", loc, pl)
        # Фильтрация
        # print("проверка 1:", allowed_ues, loc)
        if loc not in allowed_ues:
            continue

            # Фильтр по платформе
        # print("allowed_platforms is:",allowed_platforms)
        if pl not in allowed_platforms:
            continue
        # print("фин пре: ", loc,pl)
        # После os.walk
        # print("ПРОВЕРКА 3:", allowed_prefixes)

        for i in allowed_prefixes:
            reg = FIX_LABELS.get(i)
            # print('reg is',reg)
            if reg:
                for file in files:
                    if i == "Центр":
                        if file.startswith("CE") and not file.startswith("CEMS"):
                            dd[(loc, pl)].append(file)

                        # 2. Стандартная логика для всех остальных регионов (КЦ, Волга, Урал и т.д.)
                    else:
                        if file.startswith(reg):
                            dd[(loc, pl)].append(file)

    # print("dd: ",dd)
    res_device=defaultdict(list)
    # ignore_dst_any=True
    for (k1, k2), v in dd.items():
        # print("k2 is:", k2)
        if allowed_platforms and k2 not in allowed_platforms:
            continue
        parser_cls = PARSERS_MAP.get(k2)
        if k2 in ('Cisco ASA', 'Cisco FXOS', 'Cisco PIX'):
        # if k2 in ('Cisco ASA', 'Cisco FXOS'):
        #     print(k ,v)
            for vv in v:
                res = parser_cls.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode,ignore_src_any=ignore_src_any,
        ignore_dst_any=ignore_dst_any, src_mask_limit=src_mask_limit, dst_mask_limit=dst_mask_limit)
        # print(res)
                if res:
                    res_device[k1, region(vv)].append(vv)
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        elif k2 == 'FortiOS':
            # print(k1,k2,v)
            for vv in v:
                res = FortiOSParser2.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode,ignore_src_any=ignore_src_any,
        ignore_dst_any=ignore_dst_any, src_mask_limit=src_mask_limit, dst_mask_limit=dst_mask_limit)
                # print(res)
                if res:
                    res_device[k1, region(vv)].append(vv)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")

        elif k2 in (
        'Cisco IOS', 'HP ProCurve', 'B4COM BCOM-OS-DC', 'B4COM BCOM-OS-DC (VXLAN)', 'QTECH NOS', 'EdgeCore', 'IBM_Lenovo Network OS',
        'Dell Networking OS'):
            for vv in v:
                res = ACLParserFactory.parse_from_file(k2, vv, search_text[0], search_text[1], strict_mode=strict_mode,ignore_src_any=ignore_src_any,
        ignore_dst_any=ignore_dst_any, src_mask_limit=src_mask_limit, dst_mask_limit=dst_mask_limit)
                if res:
                    res_device[k1, region(vv)].append(vv)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")
        elif k2 in ('Cisco IOS XE', 'Cisco IOS XR2'):
            for vv in v:
                # print(vv)
                res = CiscoIOSXEParser2.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode,ignore_src_any=ignore_src_any,
        ignore_dst_any=ignore_dst_any, src_mask_limit=src_mask_limit, dst_mask_limit=dst_mask_limit)
                # print(res)
                if res:
                    res_device[k1, region(vv)].append(vv)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")
        elif k2 == 'Cisco NX-OS':
            for vv in v:
                res = CiscoNexusParser2.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode,ignore_src_any=ignore_src_any,
        ignore_dst_any=ignore_dst_any, src_mask_limit=src_mask_limit, dst_mask_limit=dst_mask_limit)
                if res:
                    res_device[k1, region(vv)].append(vv)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")

        elif k2 in ('Huawei VRP', 'Huawei VRP 2403'):
            for vv in v:
                res = HuaweiParser4.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode,ignore_src_any=ignore_src_any,
        ignore_dst_any=ignore_dst_any, src_mask_limit=src_mask_limit, dst_mask_limit=dst_mask_limit)
                if res:
                    res_device[k1, region(vv)].append(vv)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")

        elif k2 == 'Juniper Junos':
            for vv in v:
                res = JuniperACLParser2.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode,ignore_src_any=ignore_src_any,
        ignore_dst_any=ignore_dst_any, src_mask_limit=src_mask_limit, dst_mask_limit=dst_mask_limit)
                if res:
                    res_device[k1, region(vv)].append(vv)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")

        elif k2 == 'Eltex':
            for vv in v:
                res = EltexACLParser2.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode,ignore_src_any=ignore_src_any,
        ignore_dst_any=ignore_dst_any, src_mask_limit=src_mask_limit, dst_mask_limit=dst_mask_limit)
                if res:
                    res_device[k1, region(vv)].append(vv)
                    # print(res)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")
        elif k2 == 'Eltex ESR':
            # print(v)
            for vv in v:
                res = EltexESRParser2.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode,ignore_src_any=ignore_src_any,
        ignore_dst_any=ignore_dst_any, src_mask_limit=src_mask_limit, dst_mask_limit=dst_mask_limit)
                # print(res)
                if res:
                    res_device[k1, region(vv)].append(vv)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")
        elif k2 == 'QTECH NOS':
            # print(v)
            for vv in v:
                res = QTechParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode,
                                                      ignore_src_any=ignore_src_any,
                                                      ignore_dst_any=ignore_dst_any, src_mask_limit=src_mask_limit,
                                                      dst_mask_limit=dst_mask_limit)
                # print(res)
                if res:
                    res_device[k1, region(vv)].append(vv)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")
            # if k2  == 'HP ProCurve' :
            #     for vv in v:
            #         res = CiscoIOSParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
            #         if res:
            #             yield(f"----{k2} {k1} {region(vv)}----")
            #             yield(vv + ": \n" + "\n".join(res) + "\n")
        elif k2 in ('HPE OfficeConnect', 'HPE Comware 1910', 'HPE Comware', '3Com Comware 1910'):
            for vv in v:  # список файлов
                res = HPEParser2.from_local_file(
                    vv,
                    search_text[0],
                    search_text[1],
                    strict_mode=strict_mode,
                    ignore_src_any=ignore_src_any,
                    ignore_dst_any=ignore_dst_any,
                    src_mask_limit=src_mask_limit,
                    dst_mask_limit=dst_mask_limit  # Вы упомянули, что передаете base_dir
                )
                if res:
                    res_device[k1, region(vv)].append(vv)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")

    if res_device:
        yield f"\n--------\n🔍 Найдены cовпадения на следующих устройствах: 🔍\n"

        for k,v in res_device.items():
            joined_values = '\n'.join(v)
            # yield f"УЭС{k[0], k[1]}: {v}"
            yield f"🎯 УЭС{k[0]} {k[1]}: \n{joined_values}\n----"
            # yield f"{v}"
        # print(res_device)
        # yield f"----{res_device}----"







        # if k2 in ('Cisco ASA', 'Cisco FXOS', 'Cisco PIX'):
        #     # print(k ,v)
        #     for vv in v:
        #         res = CiscoASAParser3.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         # print(res)
        #         if res:
        #             yield(f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        #
        # elif k2 == 'FortiOS':
        #     # print(k1,k2,v)
        #     for vv in v:
        #         res = FortiOSParser.from_local_file(vv, search_text[0], search_text[1],strict_mode=strict_mode)
        #         # print(res)
        #         if res:
        #             yield(f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        #
        #
        # elif k2 in ('Cisco IOS','HP ProCurve','B4COM BCOM-OS-DC', 'B4COM BCOM-OS-DC (VXLAN)','EdgeCore','IBM_Lenovo Network OS','Dell Networking OS') :
        #     for vv in v:
        #         res = CiscoIOSParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         if res:
        #             yield(f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        # elif k2 in ('Cisco IOS XE','Cisco IOS XR'):
        #     for vv in v:
        #         # print(vv)
        #         res = CiscoIOSXEParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         # print(res)
        #         if res:
        #             yield(f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        # elif k2 == 'Cisco NX-OS':
        #     for vv in v:
        #         res = CiscoNexusParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         if res:
        #             yield(f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        #
        # elif k2 in ('Huawei VRP','Huawei VRP 2403'):
        #     for vv in v:
        #         res = HuaweiParser3.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         if res:
        #             yield(f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        #
        # elif k2 == 'Juniper Junos':
        #     for vv in v:
        #         res = JuniperACLParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         if res:
        #             yield (f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        #
        # elif k2 == 'Eltex':
        #     for vv in v:
        #         res = EltexACLParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         if res:
        #             # print(res)
        #             yield (f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        # elif k2 == 'Eltex ESR':
        #     # print(v)
        #     for vv in v:
        #         res = EltexESRParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         # print(res)
        #         if res:
        #             yield (f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        # # if k2  == 'HP ProCurve' :
        # #     for vv in v:
        # #         res = CiscoIOSParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        # #         if res:
        # #             yield(f"----{k2} {k1} {region(vv)}----")
        # #             yield(vv + ": \n" + "\n".join(res) + "\n")
        # if k2 in ('HPE OfficeConnect', 'HPE Comware 1910', 'HPE Comware','3Com Comware 1910'):
        #     for vv in v:  # список файлов
        #         res = HPEParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         if res:
        #             yield (f"----{k2} {k1} {region(vv)}----")
        #             yield (vv + ": \n" + "\n".join(res) + "\n")

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