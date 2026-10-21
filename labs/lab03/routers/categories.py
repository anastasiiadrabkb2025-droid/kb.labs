"""Маршрути API для роботи з категоріями."""

import sqlite3

from fastapi import APIRouter, HTTPException, status

from labs.lab03.repository import (
    create_category,
    delete_category,
    get_categories,
    get_category_by_id,
)
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Categories"])


@router.get("", response_model=list[CategoryRead])
def read_categories():
    return get_categories()


@router.post("", response_model=CategoryRead, status_code=status.HTTP_201_CREATED)
def add_category(category: CategoryCreate):
    try:
        return create_category(category.name)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Категорія з назвою '{category.name}' вже існує.",
        )


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_category(category_id: int):
    if category_id <= 0:
        raise HTTPException(status_code=422, detail="ID має бути додатним.")

    if not get_category_by_id(category_id):
        raise HTTPException(status_code=404, detail="Категорію не знайдено.")

    try:
        delete_category(category_id)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Неможливо видалити категорію з пов'язаними записами.",
        )
