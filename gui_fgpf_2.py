import asyncio
import ipaddress
import os

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel



# Подключаем вашу исходную функцию из get_itog.py
BASE_DIR = "/hdd_disk"
def load_creds():
    """Считывает токены из файла creds"""
    creds_path = os.path.join(BASE_DIR, "creds")
    # print(creds_path)
    # if not os.path.exists(creds_path) and os.path.exists(creds_path + ".txt"):
    #     creds_path += ".txt"

    if not os.path.exists(creds_path):
        # save_file(f"❌ Файл с доступом '{creds_path}' не найден!")
        return

    creds = {}
    with open(creds_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                creds[key.strip()] = value.strip()
                # print ("creds is: ", creds)

    return creds.get("NETBOX_TOKEN")

# Захардкоженный токен
NETBOX_TOKEN = load_creds()
# print(NETBOX_TOKEN)
MAX_TOTAL_IPS = 256
router = APIRouter(prefix="/api/nb", tags=["NB Viewer"])

class NBQueryRequest(BaseModel):
    text: str



from get_itog import get_systems_by_subnets

def is_valid_subnet(s: str) -> bool:
    try:
        ipaddress.IPv4Network(s.strip(), strict=False)
        return True
    except Exception:
        return False

def normalize_subnet(lst: list) -> list:
    res = []
    for i in lst:
        try:
            iface = ipaddress.ip_interface(i)
            # Если введён конкретный IP внутри сети (не адрес начала сети)
            if iface.ip != iface.network.network_address:
                res.append(f"{iface.ip}/32")
            else:
                # Превращаем сеть в каноничный вид (10.0.0.0/24)
                res.append(str(iface.network))
        except ValueError:
            # Если строка невалидна — просто пропускаем или оставляем как есть
            continue

    # Убираем дубликаты с сохранением порядка добавления
    return list(dict.fromkeys(res))


@router.post("/search")
async def nb_search_stream(data: NBQueryRequest):
    # Парсим и валидируем введенные подсети
    raw_lines = set(data.text.strip().splitlines())
    # print("raw_lines is:",raw_lines)
    total_ips = 0
    for net in raw_lines:
        try:
            net = ipaddress.ip_network(net)

            if net.prefixlen < 24:  # Маски /23, /22 ... /8 содержат > 256 адресов
                # print("сеть велика")
                async def error_generator():
                    yield f"data: ⚠️ Запрос слишком велик: сеть {net} превышает допустимый размер (разрешены сети /24 и меньше).\n\n"
                    yield "data: [DONE]\n\n"
                return StreamingResponse(error_generator(), media_type="text/event-stream")
            else:
                total_ips += net.num_addresses
                # print(total_ips)
                if total_ips > MAX_TOTAL_IPS:
                    async def error_generator():
                        yield f"data: ⚠️ Запрос слишком велик для исполнения. Уменьшите количество искомых сетей/ip-адресов.\n\n"
                        yield "data: [DONE]\n\n"
                return StreamingResponse(error_generator(), media_type="text/event-stream")
        except: pass
    #
    # total_ips = sum(net.num_addresses for net in raw_lines)
    # print(total_ips)
    # if total_ips > MAX_TOTAL_IPS:
    #     async def error_generator():
    #         yield f"data: ⚠️ Запрос слишком велик для исполнения. Уменьшите количество искомых сетей/ip-адресов.\n\n"
    #         yield "data: [DONE]\n\n"
    #     return StreamingResponse(error_generator(), media_type="text/event-stream")


    # print("raw_lines:", raw_lines)
    subnets = [line.strip() for line in raw_lines if line.strip() and is_valid_subnet(line)]
    subnets = normalize_subnet(subnets)


    # print("subnets:", subnets)
    if not subnets:
        async def error_generator():
            yield "data: ⚠️ Подсети/IP-адреса не введены или имеют неверный формат.\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(error_generator(), media_type="text/event-stream")
    async def event_generator():

        output_written = False

        # Обрабатываем подсети по очереди (или асинхронно)
        async def process_subnet(subnet_str):
            res, log = await asyncio.to_thread(get_systems_by_subnets, [subnet_str], NETBOX_TOKEN)
            return subnet_str, log

        tasks = [process_subnet(subnet) for subnet in subnets]
        # По мере готовности формируем красивый вывод с ▶ {subnet}
        for future in asyncio.as_completed(tasks):
            try:
                subnet_item, log = await future
                if log:
                    if log == ['⚠️']:
                        yield f"data: ⚠️ Ошибка подключение к БД netbox.\n\n"
                        yield "data: [DONE]\n\n"
                    result_text = f"▶ {subnet_item}\n" + "\n".join(log) + "\n\n"
                    formatted_data = "\n".join([f"data: {line}" for line in result_text.splitlines()])
                    yield f"{formatted_data}\n\n"
                    output_written = True
                # else: print("да")
            except Exception as e:
                yield f"data: ⚠️ Ошибка при обработке подсети: {e}\n\n"
                output_written = True

        if not output_written:
            yield "data: ❌<i> Наименований не найдено.</i>\n\ndata: \n\n"


        yield "data: ✅ Поиск в СТУ завершён.\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")