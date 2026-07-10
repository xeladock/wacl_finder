from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List

# Импортируем твой парсер
from Api_search3 import main as parse_acl_main

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
        "B4COM BCOM-OS-DC", "EdgeCore", "IBM_Lenovo Network OS",
        "Dell Networking OS", "Juniper Junos", "Cisco IOS XR", "Cisco PIX"
    ],
}

app = FastAPI(title="ACL Search Tool")

app.mount("/static", StaticFiles(directory="static"), name="static")



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


@app.post("/search")
async def search(request: SearchRequest):
    try:
        results = []
        regions = ["Все"] if "Все" in request.regions else request.regions
        vendors = ["Все"] if "Все" in request.vendors else request.vendors

        allowed_platforms = []
        for v in vendors:
            if v in PLATFORM_GROUPS:
                allowed_platforms.extend(PLATFORM_GROUPS[v])


        results.append(f"Выбранные УЭС: {', '.join(request.ues)}")
        results.append(f"Выбранные регионы: {', '.join(regions)}")
        results.append(f"Выбранные платформы: {', '.join(vendors)}\n")
        # results.append("")
        if request.sod:

            results.extend(["--- Поиск: " + request.source_ip + " → any ---\n"])
            # Source or Destination mode
            # Первый поиск
            if request.source_ip != "any":
                gen1 = parse_acl_main(
                    src_ip=request.source_ip,
                    dst_ip="any",
                    allowed_prefixes=request.regions,
                    allowed_platforms=request.vendors,
                    allowed_ues=request.ues,
                    strict_mode=request.strict_mode
                )
                # search_results = []
                search_results = list(gen1)
                if search_results:
                    results.extend(search_results)
                    del search_results
                else:
                    results.append(f"⭕ Ничего не найдено для {request.source_ip} → {request.dest_ip}")
            else:
                gen1 = parse_acl_main(
                    src_ip="any",
                    dst_ip=request.dest_ip,
                    allowed_prefixes=request.regions,
                    allowed_platforms=request.vendors,
                    allowed_ues=request.ues,
                    strict_mode=request.strict_mode
                )


                results.extend(["--- Поиск: any → " + request.dest_ip + " ---"])
                search_results = list(gen1)
                if search_results:
                    results.extend(search_results)
                    del search_results
                else:
                    results.append(f"⭕ Ничего не найдено для {request.source_ip} → {request.dest_ip}")

            # Разделитель
            results.extend(["\n--- 🔄 Обратный поиск: any → " + request.source_ip + " ---\n"])
            # results.append("--- Обратный поиск ---\n")

            # Второй поиск
            if request.source_ip != "any":
                gen2 = parse_acl_main(
                    src_ip="any",
                    dst_ip=request.source_ip,
                    allowed_prefixes=request.regions,
                    allowed_platforms=request.vendors,
                    allowed_ues=request.ues,
                    strict_mode=request.strict_mode
                )
                search_results = list(gen2)
                if search_results:
                    results.extend(search_results)
                    del search_results
                else:
                    results.append(f"⭕ Ничего не найдено для {request.source_ip} → {request.dest_ip}")
                # results.extend(list(gen2))
            else:
                gen2 = parse_acl_main(
                    src_ip=request.dest_ip,
                    dst_ip="any",
                    allowed_prefixes=request.regions,
                    allowed_platforms=request.vendors,
                    allowed_ues=request.ues,
                    strict_mode=request.strict_mode
                )
                search_results = list(gen2)
                if search_results:
                    results.extend(search_results)
                    del search_results
                else:
                    results.append(f"⭕ Ничего не найдено для {request.source_ip} → {request.dest_ip}")
                # results.extend(list(gen2))

        else:
            # Обычный режим
            # allowed_platforms=[]
            generator = parse_acl_main(
                src_ip=request.source_ip,
                dst_ip=request.dest_ip,
                allowed_prefixes=request.regions,
                allowed_platforms=allowed_platforms,
                allowed_ues=request.ues,
                strict_mode=request.strict_mode
            )


            search_results = list(generator)
            if search_results:
                results.extend(search_results)
                del search_results
            else:
                results.append(f"⭕ Ничего не найдено для {request.source_ip} → {request.dest_ip}")
            # results = list(generator)

        results.append("\n✅ Поиск завершен.\n")

        return {
            "status": "success",
            "results": results,
            "count": len([r for r in results if r.strip()])
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8084, reload=True)