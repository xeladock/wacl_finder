import asyncio
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List
from starlette.responses import StreamingResponse


# Импортируем твой парсер
from Api_search3 import main as parse_acl_main
from unpack_group_gui import router as og_router
from gui_fgpf_2 import router as nb_router


app = FastAPI(title="ACL Search Tool")
app.include_router(og_router)
app.include_router(nb_router)


app.mount("/static", StaticFiles(directory="static"), name="static")

PLATFORM_GROUPS = {
    "Cisco ASA": ["Cisco ASA"],
    "Cisco Firepower": ["Cisco FXOS"],
    "Cisco IOS": ["Cisco IOS"],
    "Cisco IOS XE": ["Cisco IOS XE"],
    "Cisco NX-OS": ["Cisco NX-OS"],
    "FortiOS": ["FortiOS"],
    "Huawei": ["Huawei VRP", "Huawei VRP 2403"],
    "Eltex":["Eltex"],
    "Eltex ESR":["Eltex ESR"],
    "HP ProCurve/HPE":["HPE Comware",'HP ProCurve',"HPE OfficeConnect", "HPE Comware 1910"],
    "Прочие устройства": [   # всё остальное
        "B4COM BCOM-OS-DC", "B4COM BCOM-OS-DC (VXLAN)", "EdgeCore", "IBM_Lenovo Network OS",
        "Dell Networking OS", "Juniper Junos", "Cisco IOS XR", "Cisco PIX"],
}

class SearchRequest(BaseModel):
    source_ip: str
    dest_ip: str
    strict_mode: bool = False
    sod: bool = False                    # Source or Destination
    ues: List[str] = []
    regions: List[str] = []
    vendors: List[str] = []




@app.get("/", response_class=HTMLResponse)
async def index():
    with open("templates/index.html", encoding="utf-8") as f:
        return f.read()

@app.get("/og-viewer")
async def read_og_viewer():
    return FileResponse("static/html/og_viewer.html")

@app.get("/nb-viewer", response_class=HTMLResponse)
async def get_nb_viewer():
    return FileResponse("static/html/nb_viewer.html")

@app.post("/search")
async def search(request: SearchRequest):
    async def event_generator():
        try:
            regions = ["Все"] if "Все" in request.regions else request.regions
            vendors = ["Все"] if "Все" in request.vendors else request.vendors

            allowed_platforms = []
            for v in vendors:
                if v in PLATFORM_GROUPS:
                    allowed_platforms.extend(PLATFORM_GROUPS[v])

            yield f"Выбранные УЭС: {', '.join(request.ues)}\nВыбранные регионы: {', '.join(regions)}\nВыбранные платформы: {', '.join(vendors)}\n\n"
            await asyncio.sleep(0.001)

            # Вспомогательная функция: копит данные в строку и шлет ровно по 10 строк
            async def stream_from_generator(gen, header_text=None, error_msg_ip_src="any", error_msg_ip_dst="any"):
                if header_text:
                    yield header_text + "\n"
                    await asyncio.sleep(0.001)

                buffer = ""
                cnt = 0
                found_any = False

                for row in gen:
                        # print("row is:", row)
                    # if row:
                        if not found_any:  # Сработает вхолостую только ОДИН раз
                            found_any = True
                        buffer += row + "\n"
                        cnt += 1

                        if cnt >= 10:  # Ровно по 10 строк накоплено
                            yield buffer
                            # Отправляем чистый текст + наш маркер окончания пачки
                            buffer = ""
                            cnt = 0
                            await asyncio.sleep(0.001)  # Форсируем отправку пакета

                if buffer:
                    yield buffer
                    await asyncio.sleep(0.001)

                if not found_any:
                    yield f"⭕ Ничего не найдено для {error_msg_ip_src} → {error_msg_ip_dst}\n"
                    await asyncio.sleep(0.001)

            # Логика запуска
            #нормальный запуск
            if request.sod:
                # Сценарий 1: Задан только Source IP (Destination IP пустой/any)
                if request.dest_ip == "any":
                    tmp_ip = request.source_ip

                    # 1. Прямой поиск: Source IP -> any
                    gen1 = parse_acl_main(tmp_ip, "any", request.regions, allowed_platforms, request.ues,
                                          request.strict_mode)
                    async for chunk in stream_from_generator(
                            gen1,
                            f"--- Поиск: {tmp_ip} → any ---\n",
                            tmp_ip,
                            "any"
                    ):
                        yield chunk

                    # 2. Обратный поиск: any -> Source IP
                    gen2 = parse_acl_main("any", tmp_ip, request.regions, allowed_platforms, request.ues,
                                          request.strict_mode)
                    async for chunk in stream_from_generator(
                            gen2,
                            f"\n--- 🔄 Обратный поиск: any → {tmp_ip} ---\n",
                            "any",
                            tmp_ip
                    ):
                        yield chunk

                # Сценарий 2: Задан только Destination IP (Source IP пустой/any)
                elif request.source_ip == "any":
                    tmp_ip = request.dest_ip

                    # 1. Прямой поиск: any -> Destination IP
                    gen1 = parse_acl_main("any", tmp_ip, request.regions, allowed_platforms, request.ues,
                                          request.strict_mode)
                    async for chunk in stream_from_generator(
                            gen1,
                            f"--- Поиск: any → {tmp_ip} ---\n",
                            "any",
                            tmp_ip
                    ):
                        yield chunk

                    # 2. Обратный поиск: Destination IP -> any
                    gen2 = parse_acl_main(tmp_ip, "any", request.regions, allowed_platforms, request.ues,
                                          request.strict_mode)
                    async for chunk in stream_from_generator(
                            gen2,
                            f"\n--- 🔄 Обратный поиск: {tmp_ip} → any ---\n",
                            tmp_ip,
                            "any"
                    ):
                        yield chunk
            else:
                generator = parse_acl_main(request.source_ip, request.dest_ip, request.regions, allowed_platforms,
                                           request.ues, request.strict_mode)
                async for chunk in stream_from_generator(generator, f"--- Поиск: {request.source_ip} → {request.dest_ip} ---\n", request.source_ip, request.dest_ip):
                    yield chunk

            yield "\n✅ Поиск завершен.\n\n"

        except Exception as e:
            yield f"\n❌ Ошибка бэкенда: {str(e)}\n"

    return StreamingResponse(event_generator(), media_type="text/plain")

@app.get("/help", response_class=HTMLResponse)
async def get_help():
    return FileResponse("static/html/help.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8087, reload=True)