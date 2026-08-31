import asyncio
import glob

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse,RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List
from starlette.responses import StreamingResponse, JSONResponse

# Импортируем твой парсер
from Api_search3 import main as parse_acl_main
from unpack_group_gui import router as og_router
from gui_fgpf_2 import router as nb_router

import sys
import os
# from pathlib import Path

# Получаем абсолютный путь к папке, где лежит исполняемый main.bin (или main.exe)
# BASE_DIR2 = os.path.dirname(os.path.abspath(sys.argv[0]))
# print("BASE_DIR2: ", BASE_DIR2)
#
# BASE_DIR = Path(sys.argv[0]).resolve().parent.parent
# print("BASE_DIR: ", BASE_DIR)
# APP_DIR = os.path.dirname(os.path.abspath(__file__))
# print("APP_DIR:", APP_DIR)
# # Путь к вашей внешней обновляемой папке
# DATA_DIR = os.path.join(BASE_DIR,'data')
# print("DATA_DIR:", DATA_DIR)

from path import APP_DIR, DATA_DIR

app = FastAPI(title="ACL Search Tool")
app.include_router(og_router)
app.include_router(nb_router)



app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")

PLATFORM_GROUPS = {
    "Cisco ASA": ("Cisco ASA",),
    "Cisco Firepower": ("Cisco FXOS",),
    "Cisco IOS": ("Cisco IOS",),
    "Cisco IOS XE": ("Cisco IOS XE",),
    "Cisco NX-OS": ("Cisco NX-OS",),
    "FortiOS": ("FortiOS",),
    "Huawei": ("Huawei VRP", "Huawei VRP 2403"),
    "Eltex": ("Eltex",),
    "Eltex ESR": ("Eltex ESR",),
    "HP ProCurve/HPE": ("HPE Comware", "HP ProCurve", "HPE OfficeConnect", "HPE Comware 1910"),
    "Прочие устройства": (
        "B4COM BCOM-OS-DC", "B4COM BCOM-OS-DC (VXLAN)", "EdgeCore", "IBM_Lenovo Network OS",
        "Dell Networking OS", "Juniper Junos", "Cisco IOS XR", "Cisco PIX"
    ),
}

# PLATFORM_GROUPS = {
#     "Cisco ASA": ["Cisco ASA"],
#     "Cisco Firepower": ["Cisco FXOS"],
#     "Cisco IOS": ["Cisco IOS"],
#     "Cisco IOS XE": ["Cisco IOS XE"],
#     "Cisco NX-OS": ["Cisco NX-OS"],
#     "FortiOS": ["FortiOS"],
#     "Huawei": ["Huawei VRP", "Huawei VRP 2403"],
#     "Eltex":["Eltex"],
#     "Eltex ESR":["Eltex ESR"],
#     "HP ProCurve/HPE":["HPE Comware",'HP ProCurve',"HPE OfficeConnect", "HPE Comware 1910"],
#     "Прочие устройства": [   # всё остальное
#         "B4COM BCOM-OS-DC", "B4COM BCOM-OS-DC (VXLAN)", "EdgeCore", "IBM_Lenovo Network OS",
#         "Dell Networking OS", "Juniper Junos", "Cisco IOS XR", "Cisco PIX"],
# }

class SearchRequest(BaseModel):
    source_ip: str
    dest_ip: str
    strict_mode: bool = False
    sod: bool = False                    # Source or Destination
    ues: List[str] = []
    regions: List[str] = []
    vendors: List[str] = []

@app.get("/")
async def index():
    if not is_data_valid():
        print("1 ошибка")
        return HTMLResponse(content=get_error_html(), status_code=503)
    return FileResponse("templates/index.html")

@app.post("/search")
async def search(request: SearchRequest):
    if not is_data_valid():
        # print("2 ошибка")
        return HTMLResponse(content=get_error_html(), status_code=503)
    async def event_generator():

        try:
            regions = ["Все"] if "Все" == request.regions[-1] else request.regions
            vendors = ["Все"] if "Все" == request.vendors[-1] else request.vendors
            print("regions main is:", regions)
            print("vendors main is:", vendors)

            if vendors == ["Все"]:
                # Объединяем все множества/списки из словаря в одно готовое множество
                allowed_platforms = set().union(*PLATFORM_GROUPS.values())
            else:
                allowed_platforms = set()
                for v in vendors:
                    if v in PLATFORM_GROUPS:
                        allowed_platforms.update(PLATFORM_GROUPS[v])


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

                # Безопасно получаем следующий элемент из синхронного генератора в отдельном потоке
                def safe_next(g):
                    try:
                        return next(g), False
                    except StopIteration:
                        return None, True

                while True:
                    # Выносим шаг парсинга в фоновый поток (не забиваем event loop!)
                    row, is_done = await asyncio.to_thread(safe_next, gen)
                    if is_done:
                        break

                    if row:
                        if not found_any:
                            found_any = True
                        buffer += row + "\n"
                        cnt += 1

                        if cnt >= 10:
                            yield buffer
                            buffer = ""
                            cnt = 0
                            await asyncio.sleep(0.001)

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

@app.get("/og-viewer")
async def read_og_viewer():
    if not is_data_valid():
        return HTMLResponse(content=get_error_html(), status_code=503)
    return FileResponse("static/html/og_viewer.html")

@app.get("/nb-viewer", response_class=HTMLResponse)
async def get_nb_viewer():
    if not is_data_valid():
        return HTMLResponse(content=get_error_html(), status_code=503)
    return FileResponse("static/html/nb_viewer.html")

@app.get("/help", response_class=HTMLResponse)
async def get_help():
    return FileResponse("static/html/help.html")

@app.get("/og-help", response_class=HTMLResponse)
async def nb_get_help():
    return FileResponse("static/html/help.html")

@app.get("/nb-help", response_class=HTMLResponse)
async def og_get_help():
    return FileResponse("static/html/help.html")

@app.get("/healthz/live", status_code=200)
async def liveness():
    """Проверка: жив ли процесс Python"""
    return {"status": "ok"}

@app.get("/healthz/ready", status_code=200)
async def readiness():
    """K8s Readiness Probe будет сообщать, что контейнер НЕ готов принимать трафик"""
    if is_data_valid():
        return JSONResponse(status_code=200, content={"status": "ready"})
    return JSONResponse(status_code=503, content={"status": "not ready, data missing"})

from time import time

DATA_VALID_CACHE = False
LAST_CHECK_TIME = 0
CACHE_TTL = 5  # Время жизни кэша в секундах


def is_data_valid() -> bool:
    global DATA_VALID_CACHE, LAST_CHECK_TIME

    current_time = time()

    # Если с последней проверки прошло меньше 5 секунд, отдаем значение из памяти
    if current_time - LAST_CHECK_TIME < CACHE_TTL:
        return DATA_VALID_CACHE

    # Иначе делаем реальную проверку на диске
    if (
        os.path.exists(DATA_DIR)
        and os.path.isdir(DATA_DIR)
        and os.listdir(DATA_DIR)
    ):
        matching_configs = glob.glob(
            os.path.join(DATA_DIR, "config_files_clear*")
        )
        DATA_VALID_CACHE = bool(matching_configs)
    else:
        DATA_VALID_CACHE = False

    LAST_CHECK_TIME = current_time
    return DATA_VALID_CACHE

# def is_data_valid() -> bool:
#     """Проверяет наличие папки data, её наполненность и наличие config_files_clear*"""
#     if not os.path.exists(DATA_DIR) or not os.path.isdir(DATA_DIR):
#         return False
#
#     if not os.listdir(DATA_DIR):
#         return False
#
#     matching_configs = glob.glob(os.path.join(DATA_DIR, "config_files_clear*"))
#     if not matching_configs:
#         return False
#
#     return True


def get_error_html() -> str:
    """Возвращает HTML-разметку служебной страницы ошибки"""
    return """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Сервис временно недоступен</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background-color: #f8fafc;
                color: #0f172a;
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
            }
            .card {
                background: white;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
                text-align: center;
                max-width: 420px;
            }
            h1 {
                font-size: 22px;
                color: #ef4444;
                margin-bottom: 12px;
            }
            p {
                color: #64748b;
                font-size: 15px;
                line-height: 1.5;
                margin: 0;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Сервис временно недоступен.</h1>
            <p>Выполняется загрузка или обновление конфигураций.<br>Пожалуйста, обновите страницу через некоторое время.</p>
        </div>
        <script>
            // Функция проверки готовности сервиса
            async function checkStatus() {
                try {
                    // Запрашиваем K8s probe эндпоинт
                    const response = await fetch('/healthz/ready', { cache: 'no-store' });
                    
                    // Если статус 200 OK — сервис восстановился!
                    if (response.ok) {
                        // Перезагружаем страницу для возврата на главный интерфейс
                        window.location.reload();
                    }
                } catch (e) {
                    // Ошибки сети игнорируем, просто ждем следующего интервала
                }
            }

            // Проверяем каждые 10 секунд (10000 мс)
            // (10 секунд обычно удобнее для пользователя, чем 60, чтобы не ждать долго)
            setInterval(checkStatus,60000);
        </script>
    </body>
    </html>
    """


# -------------------------------------------------------------
# ГЛАВНАЯ СТРАНИЦА ПРИЛОЖЕНИЯ
# -------------------------------------------------------------
@app.exception_handler(404)
async def custom_404_handler(request, exc):
    # Если путь начинается с /static/, отсылаем честную 404 ошибку,
    # чтобы случайно не загрузить главной страницей сломанный CSS/JS
    if request.url.path.startswith("/static/"):
        return JSONResponse(status_code=404, content={"message": "Not Found"})

    # Все остальные несуществующие урлы перенаправляем на главный URL "/"
    return RedirectResponse(url="/", status_code=307)


import uvicorn

if __name__ == "__main__":
        # uvicorn.run("main:app", host="0.0.0.0", port=8087, reload=True)
    uvicorn.run(app, host="0.0.0.0", port=8000, workers=1,access_log=False)