import csv
import datetime
import hashlib
import json
import random
from functools import wraps
from pathlib import Path

STUDENT_NAME = "Драб Анастасія Андріївна"
GROUP_NAME = "КБ-106"
VARIANT_NUMBER = 10

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USERS_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)

SALT = str(VARIANT_NUMBER).zfill(5)
MIN_PASSWORD_LENGTH = 10
HASH_ALGORITHM = "sha3_384"


# TASK 1
# Перевірка та оцінювання паролів
# Варіант 10


passwords = [
    "S0cial@Engineer",
    "basic",
    "Phish1ng@D3tect",
    "client",
    "Ransomwar3@Protect",
    "general",
    "Zero@D4y",
    "generic",
    "Bug@B0unty",
    "standard123",
]

criteria = {
    "min_length": 11,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "basic",
    "client",
    "general",
    "generic",
    "standard123",
    "guest",
}


def check_password(password, criteria):
    """Перевіряє пароль за заданими критеріями."""
    result = {
        "length": len(password) >= criteria["min_length"],
        "digit": any(char.isdigit() for char in password),
        "upper": any(char.isupper() for char in password),
        "special": any(not char.isalnum() for char in password),
    }

    return result


def evaluate_password(password, criteria, duplicated=False):
    """Визначає рівень надійності пароля."""
    if password.lower() in forbidden_passwords:
        return "Forbidden"

    checks = check_password(password, criteria)

    passed = sum(checks.values())

    if passed == 0:
        return "Weak"

    if passed <= 2:
        return "Medium"

    if passed == 4 and len(password) >= 15 and not duplicated:
        return "Very Strong"

    return "Strong"


def prepare_passwords():
    """Додає до списку три випадково вибрані дублікати."""
    result = passwords.copy()

    random_indexes = random.sample(range(len(passwords)), 3)

    for index in random_indexes:
        result.append(passwords[index])

    return result, random_indexes


def task1():
    """Виконання першого завдання."""
    print("TASK 1. Перевірка паролів")

    password_list, duplicate_indexes = prepare_passwords()

    print("\nВипадково вибрані дублікати:")

    for index in duplicate_indexes:
        print(f"  {index + 1}. {passwords[index]}")

    print("\nРезультати перевірки:")
    print("-" * 70)

    print(f"{'№':<4}{'Пароль':<25}{'Довжина':<10}{'Статус':<15}")

    print("-" * 70)

    for number, password in enumerate(password_list, start=1):
        duplicated = number > len(passwords)

        status = evaluate_password(
            password,
            criteria,
            duplicated,
        )

        print(f"{number:<4}{password:<25}{len(password):<10}{status:<15}")


# TASK 2
# Система контролю доступу
# Варіант 10


users = {
    "iot_specialist": {
        "role": "iot_security",
        "clearance": 3,
        "department": "IoT",
        "active": True,
    },
    "mobile_analyst": {
        "role": "mobile_security",
        "clearance": 3,
        "department": "Mobile",
        "active": True,
    },
    "web_developer": {
        "role": "web_developer",
        "clearance": 2,
        "department": "Web",
        "active": True,
    },
    "api_consumer": {
        "role": "api_user",
        "clearance": 2,
        "department": "Integration",
        "active": True,
    },
    "demo_account": {
        "role": "demonstration",
        "clearance": 1,
        "department": "Demo",
        "active": False,
    },
}

resources = [
    ("iot_firmware", 3),
    ("mobile_policies", 3),
    ("web_applications", 2),
    ("api_gateway", 2),
    ("device_certificates", 3),
    ("app_store", 1),
    ("vulnerability_database", 3),
    ("device_management", 3),
    ("integration_docs", 2),
    ("demo_content", 1),
]

security_levels = (
    "Consumer",
    "Business",
    "Enterprise",
    "Critical Systems",
)

blocked_users = {
    "demo_account",
    "compromised_device",
    "malicious_app",
}


def get_level_name(level):
    """Повертає назву рівня безпеки."""
    if 1 <= level <= len(security_levels):
        return security_levels[level - 1]

    return "Unknown"


def check_access(username, resource_name, required_level):
    """Перевіряє право користувача на доступ до ресурсу."""

    if username not in users:
        return "DENY", "User not found"

    if username in blocked_users:
        return "DENY", "User is blocked"

    user = users[username]

    if not user["active"]:
        return "DENY", "Account inactive"

    if user["clearance"] >= required_level:
        return "ALLOW", "Access allowed"

    return "DENY", "Insufficient clearance"


def task2():
    """Виконання другого завдання."""
    print("TASK 2. Контроль доступу")

    print("\nРівні безпеки:")
    for number, level in enumerate(
        security_levels,
        start=1,
    ):
        print(f"  {number} - {level}")

    print("\nРесурси:")
    print("-" * 70)

    for resource_name, level in resources:
        print(f"{resource_name:<30}Level {level} ({get_level_name(level)})")

    print("\nРезультати перевірки доступу:")
    print("-" * 70)

    for username in users:
        for resource_name, required_level in resources:
            status, reason = check_access(
                username,
                resource_name,
                required_level,
            )

            print(f"{username:<20} -> {resource_name:<25} -> {status:<5} ({reason})")


# TASK 3
# Хешування паролів, CSV, авторизація та логування
# Варіант 10


class ValidationError(Exception):
    """Помилка перевірки пароля."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """
    Створює SHA3-384 хеш пароля з використанням солі.
    """

    if not password:
        raise ValueError("Password cannot be empty")

    if not salt:
        raise ValueError("Salt cannot be empty")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError("Password is too short")

    data = salt + password

    hash_object = hashlib.sha3_384(data.encode("utf-8"))

    return hash_object.hexdigest()


def create_user(username, password):
    """
    Створює користувача у форматі:
    (username, hash)
    """

    password_hash = generate_hash(
        password,
        SALT,
    )

    return username, password_hash


def create_users(users_list):
    """
    Створює користувачів та записує їх у users.csv.
    """

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        with open(
            USERS_FILE,
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.writer(file)

            writer.writerow(["username", "password_hash"])

            for username, password in users_list:
                user = create_user(
                    username,
                    password,
                )

                writer.writerow(user)

    except (
        OSError,
        FileNotFoundError,
        PermissionError,
        ValidationError,
        ValueError,
    ) as error:
        print(f"Помилка створення users.csv: {error}")


def read_users_db():
    """Зчитує користувачів із CSV у словник."""

    users_db = {}

    try:
        with open(
            USERS_FILE,
            "r",
            newline="",
            encoding="utf-8",
        ) as file:
            reader = csv.DictReader(file)

            for row in reader:
                users_db[row["username"]] = row["password_hash"]

    except (OSError, FileNotFoundError, PermissionError, ValueError) as error:
        print(f"Помилка читання users.csv: {error}")

    return users_db


def write_log_event(event):
    """Записує подію до log.json."""

    logs = []

    try:
        if LOG_FILE.exists():
            with open(
                LOG_FILE,
                "r",
                encoding="utf-8",
            ) as file:
                content = file.read().strip()

                if content:
                    logs = json.loads(content)

        logs.append(event)

        with open(
            LOG_FILE,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                logs,
                file,
                indent=4,
                ensure_ascii=False,
            )

    except (OSError, FileNotFoundError, PermissionError, ValueError) as error:
        print(f"Помилка запису log.json: {error}")


def log_event(function):
    """Декоратор для логування подій."""

    @wraps(function)
    def wrapper(*args, **kwargs):
        event = {
            "time": datetime.datetime.now().astimezone().isoformat(),
            "function": function.__name__,
        }

        try:
            result = function(*args, **kwargs)

            event["status"] = "success"

            return result

        except Exception as error:
            event["status"] = "error"
            event["error"] = str(error)

            raise

        finally:
            write_log_event(event)

    return wrapper


@log_event
def login(username, password):
    """
    Перевіряє логін та пароль користувача.
    """

    if not username:
        raise ValueError("Username cannot be empty")

    if not password:
        raise ValueError("Password cannot be empty")

    users_db = read_users_db()

    if username not in users_db:
        return False

    try:
        password_hash = generate_hash(
            password,
            SALT,
        )

    except (
        ValidationError,
        ValueError,
    ):
        return False

    return password_hash == users_db[username]


def print_users_table(users_db):
    """Виводить таблицю користувачів."""

    print("\nТаблиця користувачів:")
    print("-" * 100)

    print(f"{'Username':<15}{'Password hash':<85}")

    print("-" * 100)

    for username, password_hash in users_db.items():
        print(f"{username:<15}{password_hash}")


def task3():
    """Виконання третього завдання."""

    print("TASK 3. Хешування та авторизація")

    print(f"\nСтудент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print(f"Алгоритм хешування: {HASH_ALGORITHM}")
    print(f"Сіль: {SALT}")
    print(f"Мінімальна довжина пароля: {MIN_PASSWORD_LENGTH}")

    sample_users = (
        ("user01", "CorrectPassword01!"),
        ("user02", "SecurePassword02!"),
        ("user03", "StrongPassword03!"),
        ("user04", "SafePassword04!"),
        ("user05", "PythonPassword05!"),
        ("user06", "CyberPassword06!"),
        ("user07", "NetworkPass07!"),
        ("user08", "SecurityPass08!"),
        ("user09", "AccessPassword09!"),
        ("user10", "Protection10!"),
    )

    print("\nСтворення users.csv...")

    create_users(sample_users)

    users_db = read_users_db()

    print_users_table(users_db)

    print("\nПеревірка авторизації:")
    print("-" * 70)

    try:
        result = login(
            "user01",
            "CorrectPassword01!",
        )

        print(f"user01 / правильний пароль: {'ALLOW' if result else 'DENY'}")

        result = login(
            "user01",
            "WrongPassword!",
        )

        print(f"user01 / неправильний пароль: {'ALLOW' if result else 'DENY'}")

        result = login(
            "unknown",
            "CorrectPassword01!",
        )

        print(f"unknown / правильний пароль: {'ALLOW' if result else 'DENY'}")

    except (
        OSError,
        FileNotFoundError,
        PermissionError,
        ValidationError,
        ValueError,
    ) as error:
        print(f"Помилка авторизації: {error}")

    print("\nПеревірка помилок:")

    try:
        login("", "password")

    except ValueError as error:
        print(f"Порожній username: {error}")

    try:
        login("user01", "")

    except ValueError as error:
        print(f"Порожній password: {error}")


# Main


def main():
    """Запускає всі три завдання лабораторної."""

    print("=" * 70)
    print("Лабораторна робота №1")
    print("Python, Git та стандарти стилю коду")
    print("=" * 70)

    print(f"\nСтудент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")

    task1()
    task2()
    task3()


if __name__ == "__main__":
    main()
