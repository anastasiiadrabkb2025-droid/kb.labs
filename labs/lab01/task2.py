"""Завдання 2: система контролю доступу."""

USERS = {
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

RESOURCES = [
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

SECURITY_LEVELS = (
    "Consumer",
    "Business",
    "Enterprise",
    "Critical Systems",
)

BLOCKED_USERS = {
    "demo_account",
    "compromised_device",
    "malicious_app",
}


def check_access(username, resource_name, resource_level):
    """Перевіряє доступ користувача до ресурсу."""
    if username not in USERS:
        return "DENY", "User not found"

    if username in BLOCKED_USERS:
        return "DENY", "User is blocked"

    user = USERS[username]

    if not user["active"]:
        return "DENY", "Account inactive"

    if user["clearance"] >= resource_level:
        return "ALLOW", "Access granted"

    return "DENY", "Insufficient clearance"


def show_resources():
    """Виводить список ресурсів."""
    print("\n=== РЕСУРСИ СИСТЕМИ ===")
    print(f"{'Ресурс':<30} Рівень безпеки")
    print("-" * 55)

    for resource_name, level in RESOURCES:
        level_name = SECURITY_LEVELS[level - 1]
        print(f"{resource_name:<30} {level_name}")


def check_all_access():
    """Перевіряє доступ усіх користувачів."""
    print("\n=== ПЕРЕВІРКА ДОСТУПУ ===")

    for username in USERS:
        for resource_name, resource_level in RESOURCES:
            result, reason = check_access(
                username,
                resource_name,
                resource_level,
            )

            print(f"user={username} resource={resource_name} -> {result} ({reason})")


def run_task2():
    """Запускає Завдання 2."""
    show_resources()
    check_all_access()


if __name__ == "__main__":
    run_task2()
