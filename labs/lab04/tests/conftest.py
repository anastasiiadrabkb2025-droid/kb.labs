"""Спільні фікстури pytest для ізоляції тестового середовища."""

import pytest
import requests


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Видалити ключ API з оточення та заблокувати реальні мережеві запити."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    def _block_network(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Мережеві запити заборонені під час виконання тестів")

    monkeypatch.setattr(requests, "get", _block_network)