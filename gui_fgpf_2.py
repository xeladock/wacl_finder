import asyncio
import ipaddress
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel



# Подключаем вашу исходную функцию из get_itog.py


# Захардкоженный токен
NETBOX_TOKEN = "e4c732fd39ceed92b1e87931e78db912d71c33d3"
MAX_TOTAL_IPS = 256
router = APIRouter(prefix="/api/nb", tags=["NB Viewer"])

class NBQueryRequest(BaseModel):
    text: str


def parse_and_validate_subnets(raw_text: str):
    """
    Парсит подсети, считает общее число IP и проверяет ограничения.
    Возвращает (список_объектов_сетей, сообщение_об_ошибке)
    """
    raw_lines = raw_text.strip().splitlines()
    networks = []

    for line in raw_lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        try:
            # strict=False позволяет вводить как 10.0.0.0/24, так и IP с маской 10.0.0.5/24
            net = ipaddress.IPv4Network(line_clean, strict=False)
            networks.append(net)
        except ValueError:
            # Невалидные IP/сети просто пропускаем или игнорируем
            pass

    if not networks:
        return None, "⚠️ Подсети/IP-адреса не введены или имеют неверный формат."
    print("networks is:",networks)
    # 1. Проверка на маску: сети >= /23 (т.е. prefixlen <= 23, например /23, /22, /16)
    for net in networks:
        if net.prefixlen < 24:  # Маски /23, /22 ... /8 содержат > 256 адресов
            print("сеть велика")
            return None, f"⚠️ Запрос слишком велик: сеть {net} превышает допустимый размер (разрешены сети /24 и меньше)."

    # 2. Суммарный подсчёт IP-адресов во всех введенных подсетях
    total_ips = sum(net.num_addresses for net in networks)
    if total_ips > MAX_TOTAL_IPS:
        return None, f"⚠️ Запрос слишком велик для исполнения.."

    # return networks, None

    return [str(net) for net in networks], None

from get_itog import get_systems_by_subnets

def is_valid_subnet(s: str) -> bool:
    try:
        ipaddress.IPv4Network(s.strip(), strict=False)
        return True
    except Exception:
        return False


@router.post("/search")
async def nb_search_stream(data: NBQueryRequest):
    # Парсим и валидируем введенные подсети
    raw_lines = data.text.strip().splitlines()
    for net in raw_lines:
        net = ipaddress.ip_network(net)
        if net.prefixlen < 24:  # Маски /23, /22 ... /8 содержат > 256 адресов
            print("сеть велика")

            async def error_generator():
                yield f"data: ⚠️ Запрос слишком велик: сеть {net} (маска /{net.prefixlen}) превышает допустимый размер (разрешены сети /24 и меньше).\n\n"
                yield "data: [DONE]\n\n"

            return StreamingResponse(error_generator(), media_type="text/event-stream")

    print("raw_lines:", raw_lines)
    subnets = [line.strip() for line in raw_lines if line.strip() and is_valid_subnet(line)]

    if not subnets:
        async def empty_generator():
            yield "data: ⚠️ Подсети/IP-адреса не введены или имеют неверный формат.\n\n"
            yield "data: [DONE]\n\n"



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
                    result_text = f"▶ {subnet_item}\n" + "\n".join(log) + "\n\n"
                    formatted_data = "\n".join([f"data: {line}" for line in result_text.splitlines()])
                    yield f"{formatted_data}\n\n"
                    output_written = True
            except Exception as e:
                yield f"data: ⚠️ Ошибка при обработке подсети: {e}\n\n"
                output_written = True

        if not output_written:
            yield "data: ❌<i> Наименований не найдено.</i>\n\ndata: \n\n"

        yield "data: ✅ Поиск в СТУ завершён.\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")