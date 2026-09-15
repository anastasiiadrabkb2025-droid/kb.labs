"""Завдання 1: аналізатор надійності паролів."""

import random
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

from shared.student import VARIANT_NUMBER

PASSWORDS = [
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

CRITERIA = {
    "min_length": 11,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "basic",
    "client",
    "general",
    "generic",
    "standard123",
    "guest",
}


def check_password(password, all_passwords):
    """Оцінює надійність одного пароля."""
    min_length = CRITERIA["min_length"]

    if password in FORBIDDEN_PASSWORDS or len(password) < min_length:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_special = any(not char.isalnum() for char in password)
    has_lower = any(char.islower() for char in password)

    criteria_met = sum(
        [
            has_digit,
            has_upper,
            has_special,
            has_lower,
        ]
    )

    if criteria_met == 0:
        return "Слабкий"

    if criteria_met < 4:
        return "Середній"

    if (
            criteria_met == 4
            and len(password) >= min_length + 4
            and all_passwords.count(password) == 1
    ):
        return "Дуже сильний"


def analyze_passwords():
    """Аналізує список паролів."""
    passwords = PASSWORDS.copy()

    random_indices = random.sample(
        range(len(passwords)),
        3,
    )

    for index in random_indices:
        passwords.append(passwords[index])

    print("\n=== ЗАВДАННЯ 1 ===")
    print(f"Варіант: {VARIANT_NUMBER}")
    print("\nПароль                    Оцінка")
    print("-" * 40)

    for password in passwords:
        result = check_password(password, passwords)
        print(f"{password:<25} {result}")


if __name__ == "__main__":
    analyze_passwords()
