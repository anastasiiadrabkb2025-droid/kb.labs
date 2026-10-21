# Лабораторна робота №2. Варіант 10

## Опис проєкту
У цій лабораторній роботі реалізовано:
1. Завдання 1 (ООП): Систему користувачів, адміністраторів, безпечних сесій та логування аутентифікації.
2. Завдання 2 (CLI-утиліта): Монітор термінів дії SSL/TLS сертифікатів, виявлення прострочених доменів та слабких алгоритмів підпису (SHA1/MD5) на основі файлу certificates.json.

## Інструкція запуску

Запускайте утиліти з кореня репозиторію через python -m:

1. Запуск демонстрації Завдання 1 (demo):
   ```bash
   python -m labs.lab02.main demo
   
2. Запуск демонстрації Завдання 2 (analyze) з дефолтними параметрами:
   ```bash
   python -m labs.lab02.main analyze
   
3. Запуск демонстрації Завдання 2 із кастомними параметрами:
   ```bash
   python -m labs.lab02.main analyze --certs-data labs/lab02/data/certificates.json --days-warning 30 --output-report labs/lab02/data/ssl_expiry_report.csv --format csv

Параметри для запуску завд. 2:

--certs-data ('str', за замовчуванням: "labs/lab02/data/certificates.json") - Шлях до файлу certificates.json

--days-warning ('int', за замовчуванням: 30) - Поріг попередження про закінчення терміну (у днях)

--output-report ('str', за замовчуванням: "labs/lab02/data/ssl_expiry_report.csv") - Шлях для збереження звіту

--format ('str', за замовчуванням: "csv") - Формат звіту (json або csv)