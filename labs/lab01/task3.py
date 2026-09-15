"""Завдання 3: хешування, CSV-база та JSON-логування."""

import csv
import hashlib
import json
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USERS_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"

SALT = "00010"
MIN_PASSWORD_LENGTH = 10
HASH_ALGORITHM = "sha3_384"


class ValidationError(Exception):
    """Помилка перевірки даних."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Створює хеш пароля з використанням солі."""
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError("Пароль коротший за мінімальну довжину.")

    hash_function = hashlib.new(HASH_ALGORITHM)
    hash_function.update((password + salt).encode("utf-8"))

    return hash_function.hexdigest()


def create_user(username, password):
    """Створює запис користувача."""
    return username, generate_hash(password, SALT)


def create_users(users_list):
    """Створює CSV-базу користувачів."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with USERS_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.writer(file)

        for username, password in users_list:
            writer.writerow(create_user(username, password))


def read_users():
    """Читає користувачів із CSV-файлу."""
    users_db = []

    with USERS_FILE.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as file:
        reader = csv.reader(file)

        for row in reader:
            users_db.append(tuple(row))

    return users_db


def log_event(function):
    """Декоратор для журналювання спроб входу."""

    @wraps(function)
    def wrapper(username, password):
        result = function(username, password)

        event = {
            "event": "login",
            "user": username,
            "result": "success" if result else "failure",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "args": [],
            "kwargs": {},
        }

        DATA_DIR.mkdir(parents=True, exist_ok=True)

        logs = []

        if LOG_FILE.exists():
            try:
                with LOG_FILE.open(
                    "r",
                    encoding="utf-8",
                ) as file:
                    logs = json.load(file)
            except json.JSONDecodeError:
                logs = []

        logs.append(event)

        with LOG_FILE.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                logs,
                file,
                indent=2,
                ensure_ascii=False,
            )

        return result

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін і пароль."""
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми.")

    users_db = read_users()
    password_hash = generate_hash(password, SALT)

    for saved_username, saved_hash in users_db:
        if saved_username == username and saved_hash == password_hash:
            return True

    return False


def main():
    """Запускає Завдання 3."""
    users_to_register = (
        ("alice", "Secur3Pass!"),
        ("bob", "Str0ngPass@"),
        ("charlie", "MyP@ssword1"),
        ("diana", "SafePass#12"),
        ("eric", "CyberPass!1"),
        ("fiona", "Protect@123"),
        ("george", "SecureKey#1"),
        ("hannah", "Passw0rd!X"),
        ("ivan", "DataSafe@12"),
        ("julia", "Strong#Pass1"),
    )

    try:
        create_users(users_to_register)
        users_db = read_users()

        print("\n=== ЗАВДАННЯ 3 ===")
        print("База користувачів:")

        for username, password_hash in users_db:
            print(f"Логін: {username:<10} Хеш: {password_hash}")

        print("\nРезультати автентифікації:")
        print("alice:", login("alice", "Secur3Pass!"))
        print("bob:", login("bob", "wrongpassword"))

    except (
        OSError,
        FileNotFoundError,
        PermissionError,
        ValidationError,
        ValueError,
    ) as error:
        print(f"Помилка: {error}")


if __name__ == "__main__":
    main()
