# logic_module.py
import pynetbox
import os
import sys
import requests

def get_systems_by_subnets(subnet_list, token):
    log = []
    if not subnet_list:
        return [], log

    pnurl = 'https://netbox.rt.ru'
    # pntoken = token

    def get_app_path():
        if getattr(sys, 'frozen', False):
            # Запущено из .exe
            return sys._MEIPASS if hasattr(sys, '_MEIPASS') else os.path.dirname(sys.executable)
        else:
            # Запущено из .py
            return os.path.dirname(os.path.abspath(__file__))


    session = requests.Session()
    session.verify = False

    nb = pynetbox.api(pnurl, token)
    nb.http_session = session
    headers = {
        'Authorization': f'Token {token}'
    }
    # Функция запроса адресов по подсетям
    def get_lst_of_ip(lst):
        result = []
        temp_url = f'{pnurl}/api/ipam/ip-addresses/?parent='

        for ip in lst:
            data = requests.get(temp_url + ip, headers=headers, verify=session.verify)
            if data.status_code == 200:
                req = data.json()
                addresses = [item['address'] for item in req.get('results', [])]
                result.append(addresses)
            else:
                log.append("Ошибка подключения к netbox.rt.ru.\n")
                break
        result = [i for inner in result for i in inner]
        return result

    def req(device_url):

        response = requests.get(device_url, headers=headers, verify=session.verify)

        if response.status_code == 200:
            device_data = response.json()
            custom_fields = device_data.get('custom_fields')
            if not custom_fields.get('project_infsys'):
                return False
            return custom_fields.get('project_infsys')[0]
        else:
            return f"Ошибка при запросе: {response.status_code}"
    all_ips = get_lst_of_ip(subnet_list)
    # if len(all_ips) > 256: return

    print("all_ips is:", all_ips)
    # if not all_ips:
    #    log.append("Ничего нет")

    res = []
    for ip in all_ips:
        ip_addresses = nb.ipam.ip_addresses.filter(address=ip)

        for ip_address in ip_addresses:
            cpj = ip_address.custom_fields.get("project_infsys")
            if cpj:
                # log.append(f"{cpj[0]} — {ip_address}")
                if cpj[0] not in res:
                    res.append(str(ip_address) + ' -- ' + cpj[0])
                break
            if not cpj and not ip_address.assigned_object_type:
                break
            try:
                try:
                    device_url = ip_address.assigned_object["virtual_machine"]["url"]
                    print(device_url)
                    # log.append(f"{device_url} [VM] — {ip_address}")
                except:
                    device_url = ip_address.assigned_object["device"]["url"]
                    print(device_url)
                    # log.append(f"{device_url} [Device] — {ip_address}")
            except:
                continue

            tmp = req(device_url)
            print("tmp is:")
            print(tmp)
            if tmp:
                if tmp not in res:
                    res.append(str(ip_address) + ' -- ' + tmp)
    # print(log)
    if res:
        for r in res:
            log.append(r)
    return res, log