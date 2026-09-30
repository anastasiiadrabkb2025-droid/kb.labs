import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900


class User:
    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ):
        self.username = username
        self.role = role
        self.active = active
        self.email = email  # Викличе setter для валідації
        self.__password_salt: bytes = b""
        self.__password_hash: bytes = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        pattern = r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email: {value}")
        self._email = value

    def set_password(self, password: str) -> None:
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not self.__password_salt:
            return False
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(self.__password_hash, computed_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"User({self.username}, Email: {self.email}, Role: {self.role}, Status: {status})"


class Admin(User):
    def __init__(
        self, username: str, email: str, permissions: set[str] | list[str] | None = None
    ):
        super().__init__(username, email, role="admin")
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self.permissions)) or "None"
        return f"{super().__str__()} | Permissions: [{perms}]"


class Session:
    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Таймаут має бути додатним числом.")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)


@dataclass
class AuditRecord:
    timestamp: str
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.logs: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            username=username,
            action=action,
        )
        self.logs.append(record)

    def show_all(self) -> list[AuditRecord]:
        return self.logs


class UserAccount:
    def __init__(self, user: User, audit_log: AuditLog | None = None):
        self.user = user
        self.session: Session | None = None
        self.audit_log = audit_log or AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if not self.user.active or self.user.username != username:
            self.audit_log.add_log(username, "login_failure")
            return False

        if self.user.check_password(password):
            self.session = Session(ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True

        self.audit_log.add_log(username, "login_failure")
        return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, item: str):
        allowed_attrs = {
            "user": self.user,
            "session": self.session,
            "audit_log": self.audit_log,
        }
        if item in allowed_attrs:
            return allowed_attrs[item]
        raise KeyError(f"Доступ до атрибута '{item}' заборонено або атрибут відсутній.")

    def __setitem__(self, key: str, value):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення має бути екземпляром класу User.")
            self.user = value
        else:
            raise KeyError(f"Зміна атрибута '{key}' через indexing не підтримується.")


def run_demo():
    print("=== Демонстрація ООП (Завдання 1) ===")
    audit = AuditLog()
    admin = Admin("admin_user", "admin@corp.ua", permissions=["read", "write"])
    admin.set_password("SecurePass123!")

    account = UserAccount(admin, audit)

    # 1. Невдалий вхід
    print(
        "Спроба входу з невірним паролем:",
        account.login("admin_user", "WrongPass", "192.168.1.10"),
    )

    # 2. Успішний вхід
    print(
        "Спроба входу з вірним паролем:",
        account.login("admin_user", "SecurePass123!", "192.168.1.10"),
    )
    print("Авторизовано:", account.is_authenticated())

    # 3. Валідація Email
    try:
        admin.email = "bad_email"
    except ValueError as e:
        print("Помилка email валідації впіймана:", e)

    admin.email = "new.admin@corp.ua"
    print("Новий email:", admin.email)

    # 4. Вихід з системи
    account.logout()
    print("Авторизовано після виходу:", account.is_authenticated())

    # 5. Журнал аудиту
    print("\n--- Записи AuditLog ---")
    for log in audit.show_all():
        print(f"[{log.timestamp}] User: {log.username} | Action: {log.action}")
