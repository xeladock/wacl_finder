import os
import sys
import shutil
import subprocess
import re
from datetime import datetime
from random import uniform
from time import sleep
import requests

# def try_lock(marker_path):
#     """Атомарно пытается создать файл-маркер.
#     Возвращает True только для Первого контейнера, успевшего его создать.
#     """
#     try:
#         # O_CREAT (создать) + O_EXCL (упасть с ошибкой, если файл УЖЕ существует)
#         fd = os.open(marker_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
#         os.close(fd)
#         return True
#     except FileExistsError:
#         return False

# def get_base_dir():
#     """Определяем папку, где лежит exe или скрипт"""
#     if getattr(sys, "frozen", False):
#         return os.path.dirname(sys.executable)
#     return os.path.dirname(os.path.abspath(__file__))

# def get_base_dir():
#     """Определяем реальную папку, где лежит бинарник Nuitka или .py скрипт"""
#     # 1. Проверяем флаг Nuitka
#     if "__compiled__" in globals() or hasattr(sys, "nuitka_binary"):
#         return os.path.dirname(os.path.realpath(sys.argv[0]))
#     # 2. Проверяем PyInstaller (на всякий случай)
#     if getattr(sys, "frozen", False):
#         return os.path.dirname(os.path.realpath(sys.executable))
#
#     # 3. Обычный запуск python3 script.py
#     return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = "/hdd_disk"
BASE_DIR_RAM = "/ram_disk"

print("BASE DIR IS", BASE_DIR)


def log(message):
    date_str = datetime.now().strftime("%d_%m_%Y")
    log_path = os.path.join(BASE_DIR, f"save-{date_str}.log")

    # Открывает, дописывает 1 строку и ТУТ ЖЕ закрывает
    with open(log_path, "a", encoding="utf-8") as f:
        print(message, file=f, flush=True)


def load_creds(save_file):
    """Считывает токены из файла creds"""
    creds_path = os.path.join(BASE_DIR, "creds")
    # if not os.path.exists(creds_path) and os.path.exists(creds_path + ".txt"):
    #     creds_path += ".txt"

    if not os.path.exists(creds_path):
        save_file(f"❌ Файл с доступом '{creds_path}' не найден!")
        sys.exit(1)

    creds = {}
    with open(creds_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                creds[key.strip()] = value.strip()

    return creds.get("GITLAB_TOKEN"), creds.get("NETBOX_TOKEN")


def make_writable(path):
    """Рекурсивно делает все файлы и папки доступными для удаления"""
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            try:
                os.chmod(os.path.join(root, name), 0o775)
            except Exception:
                pass
        for name in dirs:
            try:
                os.chmod(os.path.join(root, name), 0o775)
            except Exception:
                pass


def get_device_platform(device_name, netbox_token, save_file):
    NETBOX_URL = 'https://netbox.rt.ru/api'
    headers = {
        "Authorization": f"Token {netbox_token}",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; GitLabParser/1.0)"
    }
    url = f"{NETBOX_URL}/dcim/devices/?name={device_name}"
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=5)
        data = response.json()
        if data.get('count', 0) == 0:
            return None
        device = data['results'][0]
        platform = device.get('platform')
        if not platform:
            # print("no platform")
            return None

        # ignored_platforms = (
        #     'AlteonOS', 'Citrix MPX', 'D-Link', 'Cisco UCS',
        #     'Cisco WLC', 'Cisco Small Business Software', 'Juniper Junos E-Series'
        # )
        # if platform.get('name') in ignored_platforms:
        #     return None

        return platform.get('name')
    except Exception as e:
        save_file(f"❌ Ошибка запроса к NetBox для {device_name}: {e}")
        return None


def update_symlink(target_folder, symlink_path, save_file):
    """Атомарно обновляет символическую ссылку на новую папку"""
    tmp_symlink = symlink_path + "_tmp"

    # 1. Удаляем временный симлинк, если он остался от прошлых сбоев
    if os.path.lexists(tmp_symlink):
        os.remove(tmp_symlink)

    # 2. Создаем временный симлинк, указывающий на новую папку
    os.symlink(target_folder, tmp_symlink)

    # 3. Атомарно заменяем старый симлинк новым (работает в POSIX / Linux)
    os.replace(tmp_symlink, symlink_path)
    save_file(f"🔗 Симлинк '{os.path.basename(symlink_path)}' успешно перенаправлен на '{os.path.basename(target_folder)}'")


def cleanup_old_folders(base_dir, current_folder_name, save_file):
    res_dir= os.path.join(base_dir,"data")
    """Удаляет старые папки с датами, кроме текущей рабочей"""
    prefix = "config_files_clear_"
    save_file("🧹 Очистка устаревших папок с датами...")

    for item in os.listdir(res_dir):
        item_path = os.path.join(res_dir, item)
        # Проверяем, что это папка с нашим префиксом, но НЕ текущая свежая папка
        if os.path.isdir(item_path) and item.startswith(prefix) and item != current_folder_name:
            save_file(f"🗑️ Удаляем старую папку: {item}...")
            make_writable(item_path)
            sleep(1)
            shutil.rmtree(item_path, ignore_errors=True)
            sleep(1)


def main():
    print("!!! ЗАПУСК ПРОЦЕССОВ LOAD!!!")
    print("Рандомная пауза для упреждения гонки данных.")
    sleep(round(uniform(6.0, 66.0), 1))
    success, STOP, PROCESS = False, False, False

    try:
        log(f"📋 Запуск сессии: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n" + "=" * 10)

        if not os.path.exists("/usr/bin/git"):
            log("Не найден установленный git в /usr/bin.")
            PROCESS = True
            return PROCESS




        # 1. Формируем имя папки с текущей датой (например: config_files_clear_30_07_2026)
        date_str = datetime.now().strftime("%d_%m_%Y")
        current_today_folder_name = f"config_files_clear_{date_str}"
        # Полный путь к сегодняшней папке и к симлинку
        START_DIR = "data"


        TODAY_CONFIG_DIR = os.path.join(BASE_DIR, START_DIR, current_today_folder_name)

        print("TODAY_CONFIG_DIR is:", TODAY_CONFIG_DIR)

        if not os.path.exists(TODAY_CONFIG_DIR):
            os.makedirs(TODAY_CONFIG_DIR, exist_ok=True)


        READY_MARKER = os.path.join(BASE_DIR, START_DIR, current_today_folder_name, ".ready")
        print("READY_MARKER is:", READY_MARKER)

        log(f"Старт процесса сборки в целевую папку: {current_today_folder_name}")

        # 2. Очищаем временную папку скачивания репозиториев git


        # Если папка за СЕГОДНЯ уже была создана ранее (перезапуск в тот же день), пересоздадим её
        # if os.path.exists(TODAY_CONFIG_DIR):
        #     make_writable(TODAY_CONFIG_DIR)
        #     shutil.rmtree(TODAY_CONFIG_DIR, ignore_errors=True)

        if os.path.exists(TODAY_CONFIG_DIR) and os.path.exists(READY_MARKER):
            log("✅ Данные собраны другим контейнером.")
            print("Данные собраны другим контейнером")
            PROCESS = True
            return PROCESS
        else:
            open(READY_MARKER, 'a').close()


        FULL_PATH_RAM = os.path.join(BASE_DIR_RAM, START_DIR)
        if not os.path.exists(FULL_PATH_RAM):
            os.makedirs(FULL_PATH_RAM, exist_ok=True)
        print("FULL_PATH_RAM is", FULL_PATH_RAM)

        rem_dir = os.path.join(BASE_DIR, "config_files")

        if os.path.exists(rem_dir):
            make_writable(rem_dir)
            sleep(1)
            shutil.rmtree(rem_dir, ignore_errors=True)
            sleep(1)

        gitlab_token, netbox_token = load_creds(log)
        SYMLINK_PATH = os.path.join(BASE_DIR,START_DIR, "config_files_clear")
        SYMLINK_PATH_RAM = os.path.join(BASE_DIR_RAM,START_DIR, "config_files_clear")
        box = ("dc", "lan")
        # box = ["dc"]
        box_d={"dc":"ЦОД","lan":"ЛВС"}

        for check in box:
                target_type = box_d[check]
                # Создаем структуру подтипа внутри даты (например: .../config_files_clear_30_07_2026/ЛВС)
                clear_dir = os.path.join(TODAY_CONFIG_DIR, target_type)
                os.makedirs(clear_dir, exist_ok=True)

                clone_dir = os.path.join(BASE_DIR, "config_files", target_type)

                log(f"📥 Скачиваем файлы [{target_type}] с GitLab...")

                repo_url = f"https://oauth2:{gitlab_token}@configs.net.rt.ru/{check}/configs.git"


                result = subprocess.run(
                    ["git", "clone", "--depth=1", repo_url, clone_dir],
                    text=True,
                    capture_output=True,
                )

                if result.returncode != 0:
                    log(f"Ошибка при клонировании [{target_type}]:\n{result.stderr.strip()}")
                    now_str = datetime.now().strftime("%Y-%m-%d-%H:%M")
                    open(os.path.join(BASE_DIR, f"ERROR-{now_str}-gitlab_load"), 'a').close()
                    if os.path.exists(TODAY_CONFIG_DIR):
                        make_writable(TODAY_CONFIG_DIR)
                        sleep(1)
                        shutil.rmtree(TODAY_CONFIG_DIR, ignore_errors=True)
                        sleep(1)
                    if os.path.exists(rem_dir):
                        make_writable(rem_dir)
                        sleep(1)
                        shutil.rmtree(rem_dir, ignore_errors=True)
                        sleep(1)

                    PROCESS = True
                    return PROCESS

                log(f"Обработка и фильтрация файлов [{target_type}]...")

                data_platforms = (
                    'AlteonOS', 'Citrix MPX', 'D-Link', 'Cisco UCS',
                    'Cisco WLC', 'Cisco Small Business Software', 'Juniper Junos E-Series'
                )
                ALTER_DIR = os.path.join(BASE_DIR,"alter_confs_"+date_str)
                if not os.path.exists(ALTER_DIR):
                    os.makedirs(ALTER_DIR, exist_ok=True)

                for root, dirs, files in os.walk(clone_dir):
                    for file in files:
                        if file.startswith(("CE", "SZ", "SI", "PR", "UF", "UK", "DV")):
                        # if file.startswith(("CE","DV")):
                            src_path = os.path.join(root, file)
                            device_name = os.path.splitext(file)[0]

                            platform = get_device_platform(device_name, netbox_token, log)
                            if not platform or not platform.strip():
                                continue

                            if platform in data_platforms:
                                platform_dir = os.path.join(ALTER_DIR,target_type, platform)
                                os.makedirs(platform_dir, exist_ok=True)
                                dst_path = os.path.join(platform_dir, file)
                                shutil.copy2(src_path, dst_path)
                            else:
                                platform = platform.replace("/", os.sep)
                                platform = re.sub(r'[<>:"/\\|?*]', '_', platform)
                                platform_dir = os.path.join(clear_dir, platform)
                                os.makedirs(platform_dir, exist_ok=True)

                                dst_path = os.path.join(platform_dir, file)
                                shutil.copy2(src_path, dst_path)
                            # print(platform, dst_path)

                log(f"Обработка [{target_type}] завершена.")
                sleep(2)



        # 3. Временную папку для git сырцов чистим
        if os.path.exists(rem_dir):
            make_writable(rem_dir)
            sleep(1)
            shutil.rmtree(rem_dir, ignore_errors=True)
            sleep(1)


        # если папок нет или они пустые
        if not os.path.isdir(TODAY_CONFIG_DIR+"/ЦОД") or not os.listdir(TODAY_CONFIG_DIR+"/ЦОД"):
            # print(TODAY_CONFIG_DIR+"/ЦОД")
            now_str = datetime.now().strftime("%Y-%m-%d-%H:%M")
            print("Папки ЦОД не существует или она пустая")
            log("Папки ЦОД не существует или она пустая")
            open(os.path.join(BASE_DIR, f"ERROR-{now_str}-empty_folder_COD"), 'a').close()
            STOP = True
            return STOP
        else:
            print("проверка ЦОД: ", TODAY_CONFIG_DIR + "/ЦОД")
            print("папка ЦОД есть и не пустая")


        if not os.path.isdir(TODAY_CONFIG_DIR+"/ЛВС") or not os.listdir(TODAY_CONFIG_DIR+"/ЛВС"):
            # print(TODAY_CONFIG_DIR+"/ЛВС")
            now_str = datetime.now().strftime("%Y-%m-%d-%H:%M")
            print("Папки ЛВС не существует или она пустая")
            log("Папки ЛВС не существует или она пустая")
            open(os.path.join(BASE_DIR, f"ERROR-{now_str}-empty_folder_LVS"), 'a').close()
            STOP = True
            return STOP
        else:
            print("проверка ЛВС: ", TODAY_CONFIG_DIR + "/ЛВС")
            print("папка ЛВС есть и не пустая")


        # if not os.path.isdir(TODAY_CONFIG_DIR+"/ЛВС") and not os.listdir(TODAY_CONFIG_DIR+"/ЦОД"):
        #     now_str = datetime.now().strftime("%Y-%m-%d-%H:%M")
        #     open(os.path.join(BASE_DIR, f"ERROR-{now_str}-empty_folder LVS"), 'a').close()
        #     print("Папки ЛВС не существует или она пустая")
        #     log("Папки ЛВС не существует или она пустая")
        #     STOP = True
        #     return STOP




        # 4. ФИНАЛЬНЫЙ ЭТАП: Переключаем симлинк на новую готовую папку

        success = True
        print("success is", success)
    except Exception as e:
        success = False
        # print("success is", success)
        print("success is", success, e)
        log(f"❌ Перехвачено исключение: {e}")
    finally:
        if success:

            TODAY_CONFIG_DIR_RAM = os.path.join(BASE_DIR_RAM, START_DIR, current_today_folder_name)

            if not os.path.exists(FULL_PATH_RAM):
                os.makedirs(FULL_PATH_RAM, exist_ok=True)

            try:
                log("\nКопируем папку в RAM...")
                shutil.copytree(TODAY_CONFIG_DIR, TODAY_CONFIG_DIR_RAM, dirs_exist_ok=True)
                sleep(1)
            except:
                log("\nКопирование в RAM неуспешно...")
                return

            log("\nПереключаем символическую ссылку в RAM...")
            update_symlink(TODAY_CONFIG_DIR_RAM, SYMLINK_PATH_RAM, log)
            sleep(1)

            log("\nОчищаем все прошлые папки в RAM...")
            cleanup_old_folders(BASE_DIR_RAM, current_today_folder_name, log)
            sleep(1)

            log("\nПереключаем символическую ссылку в HDD...")
            update_symlink(TODAY_CONFIG_DIR, SYMLINK_PATH, log)
            sleep(1)

            log("\nОчищаем все прошлые папки в HDD...")
            cleanup_old_folders(BASE_DIR, current_today_folder_name, log)
            sleep(1)

            if os.path.exists(rem_dir):
                    make_writable(rem_dir)
                    sleep(1)
                    shutil.rmtree(rem_dir, ignore_errors=True)
                    sleep(1)
            from wbc import main as wbcmain
            try:
                wbcmain()
                sleep(1)
                log("\nСоздание архива WBC завершено успешно...")
                print("\nСоздание архива WBC завершено успешно...")
            except:
                log("\nСоздание архива WBC завершено неуспешно...")
                print("\nСоздание архива WBC завершено неуспешно...")


            # TODAY_CONFIG_DIR = os.path.join(BASE_DIR, START_DIR, current_today_folder_name)
            # if os.path.exists(READY_MARKER):
            #     os.remove(READY_MARKER)
            sleep(1)
            log("\nВсе операции успешно завершены!")
            print("\nВсе операции успешно завершены!")

        else:
            if PROCESS: log("\n Нормально выходим из программы!"); return
            if STOP:
                log("\nВышли из программы по STOP!");
                if os.path.isdir(TODAY_CONFIG_DIR+"/ЦОД") and not os.listdir(TODAY_CONFIG_DIR + "/ЦОД"):
                    log("\nОчищаем нескачанную папку ЦОД!");
                    shutil.rmtree(TODAY_CONFIG_DIR + "/ЦОД", ignore_errors=True)
                    sleep(1)
                if os.path.isdir(TODAY_CONFIG_DIR+"/ЛВС") and not os.listdir(TODAY_CONFIG_DIR + "/ЛВС"):
                    log("\nОчищаем нескачанную папку ЛВС!");
                    shutil.rmtree(TODAY_CONFIG_DIR + "/ЛВС", ignore_errors=True)
                    sleep(1)
                if os.path.isdir(TODAY_CONFIG_DIR) and len(os.listdir(TODAY_CONFIG_DIR)) < 2:
                    log("\nОчищаем нескачанную папку " + TODAY_CONFIG_DIR);
                    print("В папке только ready")
                    shutil.rmtree(TODAY_CONFIG_DIR, ignore_errors=True)
                    sleep(1)
                if os.path.exists(rem_dir):
                    log("\n Попытка обработки неуспешна. Удаляем папку config_files");
                    make_writable(rem_dir)
                    sleep(1)
                    shutil.rmtree(rem_dir, ignore_errors=True)
                    sleep(1)
                return

            log("\nПроизошла неизвестная ошибка!")
            now_str = datetime.now().strftime("%Y-%m-%d-%H:%M")
            open(os.path.join(BASE_DIR, f"ERROR-{now_str}-another_error"), 'a').close()
            if os.path.exists(TODAY_CONFIG_DIR):
                make_writable(TODAY_CONFIG_DIR)
                sleep(1)
                shutil.rmtree(TODAY_CONFIG_DIR, ignore_errors=True)
                sleep(1)
            if os.path.exists(rem_dir):
                    make_writable(rem_dir)
                    sleep(1)
                    shutil.rmtree(rem_dir, ignore_errors=True)
                    sleep(1)



if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()