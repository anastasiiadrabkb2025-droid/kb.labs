"""Параметризований шар роботи з базою даних."""

from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection

# --- Категорії ---


def get_categories() -> list[dict[str, Any]]:
    with closing(get_connection()) as conn:
        cursor = conn.execute("SELECT id, name FROM categories ORDER BY id ASC")
        return [{"id": r[0], "name": r[1]} for r in cursor.fetchall()]


def get_category_by_id(category_id: int) -> dict[str, Any] | None:
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            "SELECT id, name FROM categories WHERE id = ?", (category_id,)
        )
        row = cursor.fetchone()
        return {"id": row[0], "name": row[1]} if row else None


def create_category(name: str) -> dict[str, Any]:
    with closing(get_connection()) as conn:
        with conn:
            cursor = conn.execute("INSERT INTO categories (name) VALUES (?)", (name,))
            cat_id = cursor.lastrowid
        return {"id": cat_id, "name": name}


def delete_category(category_id: int) -> bool:
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        return cursor.rowcount > 0


# --- Записи ---


def get_record_by_id(record_id: int) -> dict[str, Any] | None:
    sql = """
        SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE r.id = ?
    """
    with closing(get_connection()) as conn:
        cursor = conn.execute(sql, (record_id,))
        r = cursor.fetchone()
        if not r:
            return None
        return {
            "id": r[0],
            "code": r[1],
            "title": r[2],
            "category_id": r[3],
            "category_name": r[4],
            "value": r[5],
            "status": r[6],
        }


def get_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    conditions = []
    params: list[Any] = []

    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)

    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)

    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)

    if q is not None and q.strip():
        conditions.append("instr(r.title, ?) > 0")
        params.append(q.strip())

    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

    sql = f"""
        SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        {where_clause}
        ORDER BY r.id ASC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    with closing(get_connection()) as conn:
        cursor = conn.execute(sql, params)
        rows = cursor.fetchall()
        return [
            {
                "id": r[0],
                "code": r[1],
                "title": r[2],
                "category_id": r[3],
                "category_name": r[4],
                "value": r[5],
                "status": r[6],
            }
            for r in rows
        ]


def create_record(record_data: dict[str, Any]) -> dict[str, Any]:
    sql = "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)"
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute(
            sql,
            (
                record_data["code"],
                record_data["title"],
                record_data["category_id"],
                record_data["value"],
                record_data["status"],
            ),
        )
        rec_id = cursor.lastrowid
    return get_record_by_id(rec_id)  # type: ignore[return-value]


def update_record(record_id: int, record_data: dict[str, Any]) -> dict[str, Any] | None:
    sql = """
        UPDATE records
        SET code = ?, title = ?, category_id = ?, value = ?, status = ?
        WHERE id = ?
    """
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute(
            sql,
            (
                record_data["code"],
                record_data["title"],
                record_data["category_id"],
                record_data["value"],
                record_data["status"],
                record_id,
            ),
        )
        if cursor.rowcount == 0:
            return None
    return get_record_by_id(record_id)


def delete_record(record_id: int) -> bool:
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        return cursor.rowcount > 0


def create_records_bulk(records_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    created_ids = []
    sql = "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)"
    with closing(get_connection()) as conn, conn:
        for r in records_list:
            cursor = conn.execute(
                sql, (r["code"], r["title"], r["category_id"], r["value"], r["status"])
            )
            created_ids.append(cursor.lastrowid)

    res = []
    for r_id in created_ids:
        rec = get_record_by_id(r_id)
        if rec:
            res.append(rec)
    return res
