import os
import sys
import shutil
import subprocess
import re
from datetime import datetime
from time import sleep

import requests
import time


def get_base_dir():
    """Определяем папку, где лежит exe или скрипт"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = get_base_dir()


def load_creds():
    """Считывает токены из файла creds"""
    creds_path = os.path.join(BASE_DIR, "creds")
    if not os.path.exists(creds_path) and os.path.exists(creds_path + ".txt"):
        creds_path += ".txt"

    if not os.path.exists(creds_path):
        print(f"❌ Файл с доступом '{creds_path}' не найден!")
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


def get_device_platform(device_name, netbox_token):
    NETBOX_URL = 'https://netbox.rt.ru/api'
    headers = {
        "Authorization": f"Token {netbox_token}",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; GitLabParser/1.0)"
    }
    url = f"{NETBOX_URL}/dcim/devices/?name={device_name}"
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30)
        data = response.json()
        if data.get('count', 0) == 0:
            return None
        device = data['results'][0]
        platform = device.get('platform')
        if not platform:
            return None

        ignored_platforms = (
            'AlteonOS', 'Citrix MPX', 'D-Link', 'Cisco UCS',
            'Cisco WLC', 'Cisco Small Business Software', 'Juniper Junos E-Series'
        )
        if platform.get('name') in ignored_platforms:
            return None

        return platform.get('name')
    except Exception as e:
        print(f"❌ Ошибка запроса к NetBox для {device_name}: {e}")
        return None


def update_symlink(target_folder, symlink_path):
    """Атомарно обновляет символическую ссылку на новую папку"""
    tmp_symlink = symlink_path + "_tmp"

    # 1. Удаляем временный симлинк, если он остался от прошлых сбоев
    if os.path.lexists(tmp_symlink):
        os.remove(tmp_symlink)

    # 2. Создаем временный симлинк, указывающий на новую папку
    os.symlink(target_folder, tmp_symlink)

    # 3. Атомарно заменяем старый симлинк новым (работает в POSIX / Linux)
    os.replace(tmp_symlink, symlink_path)
    print(f"🔗 Симлинк '{os.path.basename(symlink_path)}' успешно перенаправлен на '{os.path.basename(target_folder)}'")


def cleanup_old_folders(base_dir, current_folder_name):
    """Удаляет старые папки с датами, кроме текущей рабочей"""
    prefix = "config_files_clear_"
    print("🧹 Очистка устаревших папок с датами...")

    for item in os.listdir(base_dir):
        item_path = os.path.join(base_dir, item)
        # Проверяем, что это папка с нашим префиксом, но НЕ текущая свежая папка
        if os.path.isdir(item_path) and item.startswith(prefix) and item != current_folder_name:
            print(f"🗑️ Удаляем старую папку: {item}...")
            make_writable(item_path)
            sleep(1)
            shutil.rmtree(item_path, ignore_errors=True)
            sleep(1)


def main():
    if not os.path.exists("/usr/bin/git"):
        print("❌ Не найден установленный git в /usr/bin.")
        return

    gitlab_token, netbox_token = load_creds()

    # 1. Формируем имя папки с текущей датой (например: config_files_clear_30_07_2026)
    date_str = datetime.now().strftime("%d_%m_%Y")
    current_today_folder_name = f"config_files_clear_{date_str}"

    # Полный путь к сегодняшней папке и к симлинку
    TODAY_CONFIG_DIR = os.path.join(BASE_DIR, current_today_folder_name)
    SYMLINK_PATH = os.path.join(BASE_DIR, "config_files_clear")

    print(f"🚀 Старт процесса сборки в целевую папку: {current_today_folder_name}", flush=True)

    # 2. Очищаем временную папку скачивания репозиториев git
    rem_dir = os.path.join(BASE_DIR, "config_files")
    if os.path.exists(rem_dir):
        make_writable(rem_dir)
        shutil.rmtree(rem_dir, ignore_errors=True)

    # Если папка за СЕГОДНЯ уже была создана ранее (перезапуск в тот же день), пересоздадим её
    if os.path.exists(TODAY_CONFIG_DIR):
        make_writable(TODAY_CONFIG_DIR)
        shutil.rmtree(TODAY_CONFIG_DIR, ignore_errors=True)

    box = ["dc"]
    box_d={"dc":"ЦОД","lan":"ЛВС"}

    for check in box:
            target_type = box_d[check]
            # Создаем структуру подтипа внутри даты (например: .../config_files_clear_30_07_2026/ЛВС)
            clear_dir = os.path.join(TODAY_CONFIG_DIR, target_type)
            os.makedirs(clear_dir, exist_ok=True)

            clone_dir = os.path.join(BASE_DIR, "config_files", target_type)

            print(f"📥 Скачиваем файлы [{target_type}] с GitLab...", flush=True)

            repo_url = f"https://oauth2:{gitlab_token}@configs.net.rt.ru/{check}/configs.git"

            result = subprocess.run(
                ["git", "clone", "--depth=1", repo_url, clone_dir],
                text=True,
                capture_output=True,
            )

            if result.returncode != 0:
                print(f"❌ Ошибка при клонировании [{target_type}]:\n{result.stderr.strip()}")
                return

            print(f"⚙️ Обработка и фильтрация файлов [{target_type}]...", flush=True)

            for root, dirs, files in os.walk(clone_dir):
                for file in files:
                    if file.startswith(("DV")):
                        src_path = os.path.join(root, file)
                        device_name = os.path.splitext(file)[0]

                        platform = get_device_platform(device_name, netbox_token)
                        if not platform or not platform.strip():
                            continue

                        platform = platform.replace("/", os.sep)
                        platform = re.sub(r'[<>:"/\\|?*]', '_', platform)
                        platform_dir = os.path.join(clear_dir, platform)
                        os.makedirs(platform_dir, exist_ok=True)

                        dst_path = os.path.join(platform_dir, file)
                        shutil.copy2(src_path, dst_path)

            print(f"✅ Обработка [{target_type}] завершена.")

    # 3. Временную папку для git сырцов чистим
    if os.path.exists(rem_dir):
        make_writable(rem_dir)
        sleep(1)
        shutil.rmtree(rem_dir, ignore_errors=True)
        sleep(1)

    # 4. ФИНАЛЬНЫЙ ЭТАП: Переключаем симлинк на новую готовую папку
    print("\n🔄 Переключаем символическую ссылку...", flush=True)
    update_symlink(TODAY_CONFIG_DIR, SYMLINK_PATH)

    # 5. Очищаем все прошлые папки с датами
    cleanup_old_folders(BASE_DIR, current_today_folder_name)

    print("\n🎉 Все операции успешно завершены!", flush=True)


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()