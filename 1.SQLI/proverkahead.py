"""
=============================================================================
 proverkahead.py — CTF-разведчик: поиск флага в методах/заголовках/путях/куках
=============================================================================

ЗАЧЕМ:
    Быстрый перебор «где спрятан флаг» на web-задаче CTF. По очереди пробует:
      1) нестандартные HTTP-методы (GET/POST/HEAD/PUT/DELETE/OPTIONS/FLAG/CDB);
      2) фаззинг заголовков (X-Flag, Cdb-Flag, Think-With-Head, ...);
      3) фаззинг GET-параметров (?flag=1, ?debug=true, ...);
      4) распространённые пути (/flag, /cdb, /getflag, ...);
      5) подстановку кук.
    В каждом ответе ищет маркер флага `cdb{` (формат площадки Codeby) и печатает
    41 символ с этой позиции.

ГДЕ ПРИМЕНИМО:
    Web-категория CTF (в первую очередь Codeby/HackerLab). НЕ инструмент для
    продакшна — заточен под поиск строки-флага.

ЗАПУСК:
    python3 proverkahead.py  → ввести URL цели.

ЗАМЕЧАНИЯ:
    - Маркер флага 'cdb{' и длину 41 меняйте под формат конкретной площадки.
    - В конце печатает подсказки (robots.txt, Ctrl+U, ручной fuzzing в Burp).
=============================================================================
"""
import requests

target = input("Введите URL цели (например, http://172.23.144.24/index.php): ").strip()

# 1. Проверка HTTP-методов
methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "FLAG", "CDB"]
print("[*] Проверяем HTTP-методы...")
for method in methods:
    try:
        r = requests.request(method, target, timeout=3)
        print(f"{method} → {r.status_code} | Длина: {len(r.text)}")
        if "cdb{" in r.text:
            start = r.text.find("cdb{")
            print(f"[+] Флаг найден в {method}-ответе!")
            print(r.text[start:start+41])
    except Exception as e:
        print(f"{method} → Ошибка: {e}")

# 2. Фаззинг заголовков
headers_list = [
    {"X-Flag": "1"},
    {"Cdb-Flag": "1"},
    {"Think-With-Head": "1"},  # Подсказка "ГОЛОВОЙ"
    {"Flag": "true"},
]
print("\n[*] Фаззим заголовки...")
for headers in headers_list:
    try:
        r = requests.get(target, headers=headers, timeout=3)
        if "cdb{" in r.text:
            start = r.text.find("cdb{")
            print(f"[+] Флаг с headers={headers}")
            print(r.text[start:start+41])
    except Exception as e:
        print(f"Ошибка при запросе с headers={headers}: {e}")

# 3. Фаззинг параметров
params_list = [
    {"flag": "1"},
    {"cdb": "1"},
    {"getflag": "true"},
    {"debug": "true"},
]
print("\n[*] Фаззим параметры...")
for params in params_list:
    try:
        r = requests.get(target, params=params, timeout=3)
        if "cdb{" in r.text:
            start = r.text.find("cdb{")
            print(f"[+] Флаг с params={params}")
            print(r.text[start:start+41])
    except Exception as e:
        print(f"Ошибка при запросе с params={params}: {e}")

# 4. Проверка путей
paths = ["/flag", "/cdb", "/getflag", "/header", "/think"]
print("\n[*] Проверяем пути...")
for path in paths:
    try:
        r = requests.get(target.rstrip("/") + path, timeout=3)
        if "cdb{" in r.text:
            start = r.text.find("cdb{")
            print(f"[+] Флаг по пути {path}")
            print(r.text[start:start+41])
    except Exception as e:
        print(f"Ошибка при запросе пути {path}: {e}")

# 5. Проверка куки
cookies_list = [
    {"flag": "1"},
    {"cdb": "1"},
    {"think": "head"},
]
print("\n[*] Проверяем куки...")
for cookies in cookies_list:
    try:
        r = requests.get(target, cookies=cookies, timeout=3)
        if "cdb{" in r.text:
            start = r.text.find("cdb{")
            print(f"[+] Флаг с cookies={cookies}")
            print(r.text[start:start+41])
    except Exception as e:
        print(f"Ошибка при запросе с cookies={cookies}: {e}")

print("\n[+] Если флаг не найден, попробуйте:")
print("- Ручной fuzzing с Burp Suite")
print("- Проверить /robots.txt")
print("- Искать в исходном коде страницы (Ctrl+U)")

