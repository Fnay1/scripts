# scripts — наработки для пентеста

Личный набор Python-утилит и заготовок для тестирования веб-приложений и
сервисов: слепые SQL-инъекции, получение RCE (PHP/FTP/SSTI), command injection,
обход авторизации, готовые эксплойты под известные CVE и шпаргалки с payload'ами.

Каждый **собственный** скрипт снабжён подробным комментарием-докстрингом в начале
файла: что делает, зачем, где применимо, как запускать, ограничения. Сторонние
инструменты (со своими README/LICENSE) описаны ниже, но их код не изменялся.

> ⚠️ **Только для авторизованного использования.** Инструменты предназначены для
> собственных стендов, CTF и пентеста по письменному согласованию с владельцем
> системы. Использование против чужих систем без разрешения незаконно.
>
> Многие скрипты писались под конкретные учебные стенды (CTF/лаборатории),
> поэтому часть значений (URL, схемы БД, имена таблиц/параметров, маркеры успеха,
> IP листенера) **захардкожена/замаскирована** — перед применением к своей цели
> их нужно поправить. IP реального listener'а в примерах замаскирован (`195.58.x.x`).

---

## 1.SQLI — SQL-инъекции (blind: Boolean / Time / Error / UNION)

| Скрипт | Что делает | Техника |
|--------|-----------|---------|
| `test.py` | **Флагман**: тулкит — фаззинг параметров (многопоточно), детект инъекции, извлечение БД/таблиц/колонок/данных, меню атак | Boolean / Time / UNION |
| `happy_hack.py` | Авто-обёртка над **sqlmap**: DBMS → БД → таблицы → колонки → авто-дамп кредов | через sqlmap |
| `perebor_name_bd_universal_metod.py` | Сам подбирает рабочий метод и извлекает имя БД | union/boolean/error/time |
| `perebor_name_bd_universal_metod_s_knopkoy.py` | То же + конструктор запроса (кавычки/оператор/комментарий/кнопка, детект text/count) | union/boolean/error/time |
| `perebor_name_bd_Boolean-Based Blind.py` | Имя БД по маркеру ответа | Boolean-Based |
| `perebor_name_table_Time-Based Blind.py` | Имена таблиц схемы | Time-Based |
| `perebor_kolonok_v_table.py` | Имена колонок таблицы | Time-Based |
| `podbor_znacheniya_id.py` | Значение поля по id (LENGTH → посимвольно) | Time-Based |
| `podbor_znacheniya_id_Time-Based Blind.py` | ⚠ **дубликат** предыдущего | Time-Based |
| `tablenamebd.py` | Имя одной таблицы (мини-версия) | Boolean (`\|\|`) |
| `slqi1_hard.py` | Дамп таблицы через инъекцию в **cookie** (колонки+данные по ASCII) | Boolean-Based |
| `slqi2_hard.py` | Дамп users в форме логина + обход авторизации admin через UNION | Boolean + UNION |
| `zagolovki.py` | Печать HTTP-заголовков (HEAD) — разведка | — |
| `proverkahead.py` | CTF-поиск флага `cdb{}` в методах/заголовках/параметрах/путях/куках | fuzzing |

## 2.PHPI — PHP-инъекции / вебшеллы

| Объект | Что делает |
|--------|-----------|
| `created_file.py` | Эксплойт **ProFTPD mod_copy (CVE-2015-3306)**: без auth пишет `backdoor.php` в webroot и проверяет RCE. ⚠ Создаёт вебшелл |
| `wso-webshell-master/` | **Сторонний** PHP-вебшелл WSO (файловый менеджер, выполнение команд, БД). Пароль по умолчанию `ghost287`. Для загрузки после RCE |

## 3.CMDi — Command Injection

| Скрипт | Что делает |
|--------|-----------|
| `1.F_perebor_paramenra.py` | Обёртка **ffuf**: перебор имён GET-параметров с payload `/etc/passwd` (поиск LFI/Path Traversal). Нужен ffuf + SecLists |
| `2.F_proverka_simvol.py` | Карта фильтра символов (что режет WAF), затем подбор рабочего разделителя команд (`;`, `\|`, `&&`, `$()`, `%0a`…) только из разрешённых символов |

## 4.obhod_autorizac — Обход авторизации

| Скрипт | Что делает |
|--------|-----------|
| `F_serialize_auth.py` | Декод PHP-сериализованной cookie (URL+base64) → подмена роли в поле `auth` с пересчётом длины → кодирование обратно. Privesc user → admin/root, если cookie без подписи/HMAC |

## 5.systemexploit — эксплойты под сервисы/CVE

| Объект | Что делает | CVE |
|--------|-----------|-----|
| `ftp21/create_backdoor.py` | Шаг 1: заливка вебшелла через ProFTPD mod_copy | CVE-2015-3306 |
| `ftp21/ftp21.py` | Шаг 2: интерактивный шелл к залитому `backdoor.php` | — |
| `phpMailer/40974.py` | PHPMailer RCE → reverse shell (публичный PoC anarc0der) | CVE-2016-10033 |
| `phpMailer/40974_serveo_AUTO.py` | То же, интерактивная версия (ввод цели/хоста/порта, serveo-туннель, рандом UA) | CVE-2016-10033 |
| `joomla/CVE-2017-8917-Joomla/` | **Сторонний**: SQLi в Joomla! 3.7.0 (TryHackMe Dailybugle) | CVE-2017-8917 |
| `struts-pwn/` | **Сторонний** (Mazin Ahmed): RCE в Apache Struts (S2-045) | CVE-2017-5638 |

> Папки `.../reports/`, `.../Result/`, `*.json` — артефакты запусков по учебным
> стендам (целевые адреса — приватные `172.23.x.x`).

## os — Повышение привилегий (PEASS-ng)

Пост-эксплуатация: автоматический поиск путей эскалации до root/SYSTEM.
Сторонний набор **PEASS-ng** (MIT), подробности — в [`os/`](os).

| Объект | Инструмент | ОС |
|--------|-----------|-----|
| [`os/linpeas/`](os/linpeas) | **linPEAS** (`linpeas.sh`, `linpeas_small.sh`) | Linux / Unix / macOS |
| [`os/winpeas/`](os/winpeas) | **winPEAS** (`winPEAS.bat` + `download-exe.sh` для `.exe`) | Windows |

## Корневые файлы

| Файл | Назначение |
|------|-----------|
| `scan_SSTI.py` | Сканер **SSTI** (Jinja2/Twig/Freemarker/Mako): детект движка `{{7*7}}` → генерация RCE-payload → выполнение команды |
| `xss_payload.txt` | Коллекция XSS-payload'ов (обходы фильтров, кодировки, события, SVG/JS) |
| `revers_shell.txt` | Шпаргалка: reverse shell one-liner + трюк с base64 для обхода фильтров |

---

## Зависимости

```bash
pip install requests requests_toolbelt lxml termcolor colorama
# для отдельных инструментов: sqlmap, ffuf, SecLists (/usr/share/seclists)
# os/ (PEASS-ng): готовые бинарники/скрипты, зависимостей не требуют

```

## Типовой рабочий процесс (blind SQLi)

1. `zagolovki.py` / `proverkahead.py` — разведка.
2. `test.py` или `perebor_name_bd_universal_metod*.py` — найти параметр/метод, вытащить имя БД.
3. `perebor_name_table_*` → `perebor_kolonok_v_table` — таблицы и колонки.
4. `podbor_znacheniya_id` / `slqi*_hard` — дамп нужных значений.
5. `happy_hack.py` — если проще довериться sqlmap.

---
_Наработки [@Fnay1](https://github.com/Fnay1). Материалы — для легального пентеста, обучения и CTF._
