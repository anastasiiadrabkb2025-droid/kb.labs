"""Скрипт заповнення БД початковими даними з seed.json."""

import json
import sqlite3

from labs.lab03.database import BASE_DIR, get_connection, initialize_database

SEED_FILE = BASE_DIR / "data" / "seed.json"


def seed_database() -> None:
    initialize_database()

    if not SEED_FILE.exists():
        print(f"Помилка: файл {SEED_FILE} не знайдено.")
        return

    with open(SEED_FILE, encoding="utf-8") as f:
        data = json.load(f)

    categories = data.get("categories", [])
    records = data.get("records", [])

    conn = get_connection()
    try:
        cursor = conn.execute("SELECT COUNT(*) FROM categories")
        if cursor.fetchone()[0] > 0:
            print("База даних вже містить дані. Заповнення скасовано.")
            conn.close()
            return

        with conn:
            for cat in categories:
                conn.execute(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    (cat["id"], cat["name"]),
                )
            for rec in records:
                conn.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        rec["code"],
                        rec["title"],
                        rec["category_id"],
                        rec["value"],
                        rec["status"],
                    ),
                )
        print("Базу даних успішно заповнено початковими даними.")
    except sqlite3.Error as e:
        print(f"Помилка при заповненні БД: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    seed_database()
