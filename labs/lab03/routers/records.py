"""Маршрути API для роботи із записами."""

import sqlite3
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, status

from labs.lab03.repository import (
    create_record,
    create_records_bulk,
    delete_record,
    get_category_by_id,
    get_record_by_id,
    get_records,
    update_record,
)
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["Records"])


@router.get("", response_model=list[RecordRead])
def read_records(
    category_id: int | None = Query(None, gt=0),
    status_filter: Literal["new", "in_progress", "done"] | None = Query(
        None, alias="status"
    ),
    min_value: float | None = Query(None, ge=0.0, le=100.0),
    q: str | None = Query(None, min_length=1, max_length=120),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return get_records(
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get("/{record_id}", response_model=RecordRead)
def read_record(record_id: int):
    if record_id <= 0:
        raise HTTPException(status_code=422, detail="ID має бути додатним.")
    rec = get_record_by_id(record_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Запис не знайдено.")
    return rec


@router.post("", response_model=RecordRead, status_code=status.HTTP_201_CREATED)
def add_record(record: RecordCreate):
    if not get_category_by_id(record.category_id):
        raise HTTPException(status_code=404, detail="Категорію не знайдено.")

    try:
        return create_record(record.model_dump())
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Запис із кодом '{record.code}' вже існує.",
        )


@router.post(
    "/bulk", response_model=list[RecordRead], status_code=status.HTTP_201_CREATED
)
def add_records_bulk(records: list[RecordCreate]):
    if not (1 <= len(records) <= 100):
        raise HTTPException(status_code=422, detail="Розмір пакета: 1–100 елементів.")

    codes = [r.code for r in records]
    if len(codes) != len(set(codes)):
        raise HTTPException(status_code=409, detail="Дублікати кодів у запиті.")

    for r in records:
        if not get_category_by_id(r.category_id):
            raise HTTPException(
                status_code=404, detail=f"Категорію ID {r.category_id} не знайдено."
            )

    try:
        return create_records_bulk([r.model_dump() for r in records])
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Конфлікт унікальності коду з базою даних."
        )


@router.put("/{record_id}", response_model=RecordRead)
def replace_record(record_id: int, record: RecordReplace):
    if record_id <= 0:
        raise HTTPException(status_code=422, detail="ID має бути додатним.")

    if not get_record_by_id(record_id):
        raise HTTPException(status_code=404, detail="Запис не знайдено.")

    if not get_category_by_id(record.category_id):
        raise HTTPException(status_code=404, detail="Категорію не знайдено.")

    try:
        return update_record(record_id, record.model_dump())
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Запис із кодом '{record.code}' вже існує.",
        )


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_record(record_id: int):
    if record_id <= 0:
        raise HTTPException(status_code=422, detail="ID має бути додатним.")

    if not delete_record(record_id):
        raise HTTPException(status_code=404, detail="Запис не знайдено.")
