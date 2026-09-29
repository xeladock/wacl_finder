import time
from datetime import datetime
import os
import re
import shutil
from pathlib import Path
# --- КОНФИГУРАЦИЯ ---

# Коренной каталог, куда складывается архив
ARCHIVE_BASE_DIR = Path("/archive")

# Корневая папка с входящими днями (где скрипт ищет папки вида config_files_clear_*)
INCOMING_BASE_DIR = Path("/hdd_disk/data/")  # Укажите реальный путь к вашей папке

ALTER_DIR = Path("/hdd_disk/")

BASE_DIR = "/hdd_disk"


def lg(message):
    date_str = datetime.now().strftime("%d_%m_%Y")
    log_path = os.path.join(BASE_DIR, f"save-{date_str}.log")

    # Открывает, дописывает 1 строку и ТУТ ЖЕ закрывает
    with open(log_path, "a", encoding="utf-8") as f:
        print(message, file=f, flush=True)


# Режим работы: 'move' — перемещать файлы, 'copy' — копировать
# FILE_ACTION = "move"

# Словарь префиксов имен файлов и соответствующих стран
# COUNTRY_MAP = {
#     "LV": "Латвия",
#     "ES": "Эстония",
#     "LT": "Литва",
#     "RU": "Россия",
#     "BY": "Беларусь",
#     "KZ": "Казахстан",
#     # Добавляйте новые префиксы по аналогии
# }
# MONTHS = {
#     1: "Январь",
#     2: "Февраль",
#     3: "Март",
#     4: "Апрель",
#     5: "Май",
#     6: "Июнь",
#     7: "Июль",
#     8: "Август",
#     9: "Сентябрь",
#     10: "Октябрь",
#     11: "Ноябрь",
#     12: "Декабрь",
# }

COUNTRY_MAP = {
    "CEMS":"Корпоративный Центр",
    "CE":"Центр",
    "PR": "Волга",
    "DV": "Дальний Восток",
    "SZ":"Северо-Запад",
    "UR":"Урал",
    "UF":"Юг",
    "SI":"Сибирь"
}



# Дефолтная папка, если префикс файла не найден в словаре
# DEFAULT_COUNTRY = "Другие"


def parse_date_from_foldername(folder_name: str):
    """
    Извлекает день, месяц и год из имени папки.
    Ожидаемый формат: config_files_clear_DD_MM_YYYY
    """
    match = re.search(r"config_files_clear_(\d{2})_(\d{2})_(\d{4})", folder_name)
    match_alter = re.search(r"alter_confs_(\d{2})_(\d{2})_(\d{4})", folder_name)
    if match:
        day, month, year = match.groups()
        # print(day, month, year)
        return year, month, day
    elif match_alter:
        day, month, year = match_alter.groups()
        # print(day, month, year)
        # print(match_alter.groups())
        return year, month, day
    return False


# if i == "Центр":
#     if file.startswith("CE") and not file.startswith("CEMS"):

def get_country_by_filename(filename: str) -> str:
    """Определяет страну по первому двухбуквенному префиксу в имени файла."""
    clean_filename = filename.upper()
    # print("clean_filename is: ",clean_filename)
    for prefix, country in COUNTRY_MAP.items():
        if clean_filename.startswith("CE") and not clean_filename.startswith("CEMS"):
                return "Центр"

        elif clean_filename.startswith(prefix.upper()):
            # print("country is: ", country)
            return country
    return False

# folder=[]
remove_folder = ""
def process_incoming_folder(source_folder: Path, today_str: str):
    """Обрабатывает папку выгрузки только за текущий день."""

    # 1. Проверяем шаблон имени
    date_info = parse_date_from_foldername(source_folder.name)
    if not date_info:
        lg(f"[SKIP] {source_folder.name}: не соответствует шаблону имени.")
        return

    year, month, day = date_info
    folder_date_str = f"{day}_{month}_{year}"

    # 2. УСЛОВИЕ: Сравниваем дату папки с сегодняшней датой
    if folder_date_str != today_str:
        lg(f"[WBC PASS] Папка {source_folder.name} не за сегодня ({today_str}). Пропускаем.")
        print(f"[WBC PASS] Папка {source_folder.name} не за сегодня ({today_str}). Пропускаем.")
        # pass  # Дата не равна текущей — ничего не делаем
        return
    else:
        if source_folder.name.startswith("alter_"):
            global remove_folder
            remove_folder = source_folder.name

    # month_int = int(month)
    # month_name = MONTHS.get(month_int, month_str)

    # print(f"\n=== Обработка актуальной папки за сегодня: {source_folder.name} ===")

    # 3. Раскладка файлов
    for root, _, files in os.walk(source_folder):
        for file in files:
            if file.startswith("."):
                continue

            file_path = Path(root) / file
            # print(file_path)
            rel_path = file_path.relative_to(source_folder)
            # print(rel_path)
            parts = rel_path.parts

            if len(parts) <= 2:
                continue
            # print(parts)
            segment = parts[0]  # "ЦОД" или "ЛВС"
            vendor = parts[1]
            # print(vendor)
            # if vendor == "Ignore": print(vendor, parts)
            country = get_country_by_filename(file)
            if country:

            # Формируем целевой путь: /archive/YYYY/MM/DD/{Сегмент}/{Страна}/{Вендор}/
                target_dir = (
                        ARCHIVE_BASE_DIR / year / month / day / segment / country / vendor
                )
                target_dir.mkdir(parents=True, exist_ok=True)

                target_file_path = target_dir / file

                try:
                    shutil.copy2(str(file_path), str(target_file_path))
                    time.sleep(0.06)
                    # print(f"[OK] {file} -> {target_file_path.relative_to(ARCHIVE_BASE_DIR)}")
                except Exception as e:
                    lg(f"[WBC ERROR] Ошибка при обработке файла {file}: {e}")
                    print(f"[ERROR] Ошибка при обработке файла {file}: {e}")

    # Очищаем исходную папку после перемещения
    # if FILE_ACTION == "move":
    #     try:
    #         shutil.rmtree(source_folder)
    #         print(f"[CLEANUP] Исходная папка {source_folder.name} удалена.")
    #     except Exception as e:
    #         print(f"[WARNING] Не удалось удалить папку: {e}")


def main():
    if not INCOMING_BASE_DIR.exists():
        lg(f"[WBC] Каталог с входящими данными не найден: {INCOMING_BASE_DIR}")
        print(f"[WBC] Каталог с входящими данными не найден: {INCOMING_BASE_DIR}")
        return

    # Получаем сегодняшнюю дату в формате DD_MM_YYYY (например, 17_09_2026)
    today_str = datetime.now().strftime("%d_%m_%Y")
    lg(f"[WBC] Запуск скрипта. Текущая дата календаря: {today_str}")
    print(f"[WBC] Запуск скрипта. Текущая дата календаря: {today_str}")

    # Сканируем входящий ОСНОВНОЙ каталог
    for item in INCOMING_BASE_DIR.iterdir():
        if item.is_dir() and item.name.startswith("config_files_clear_"):
            process_incoming_folder(item, today_str)
    # print(ALTER_DIR.iterdir())
    # Сканируем входящий ALTER каталог
    for item in ALTER_DIR.iterdir():
        if item.is_dir() and item.name.startswith("alter_confs_"):
            process_incoming_folder(item, today_str)
    # print("remove_folder is ",remove_folder)
    try:
            # print(os.path.join(ALTER_DIR,remove_folder))
        # print("remove_folder is ", remove_folder)
        if remove_folder and remove_folder.startswith("alter_"):
            # print("remove_folder is ", remove_folder)
            shutil.rmtree(os.path.join(ALTER_DIR,remove_folder))
            time.sleep(1)
            lg(f"[WBC CLEANUP] Исходная папка alter удалена.")
            print(f"[WBC CLEANUP] Исходная папка alter удалена.")
    except Exception as e:
            lg(f"[WBC WARNING] Не удалось удалить папку alter: {e}")
            print(f"[WBC WARNING] Не удалось удалить папку alter: {e}")

    # if os.path.exists(ALTER_DIR):
    #     shutil.rmtree(ALTER_DIR.iterdir(), ignore_errors=True)
        # sleep(1)


# def main():
#     if not INCOMING_BASE_DIR.exists():
#         print(f"Каталог с входящими данными не найден: {INCOMING_BASE_DIR}")
#         return
#     today_str = datetime.now().strftime("%d_%m_%Y")
#     print(f"Запуск скрипта. Текущая дата календаря: {today_str}")
#     # Сканируем входящий каталог на наличие папок config_files_clear_*
#     for item in INCOMING_BASE_DIR.iterdir():
#         if item.is_dir() and item.name.startswith("config_files_clear_"):
#             process_incoming_folder(item,today_str)


if __name__ == "__main__":
    main()