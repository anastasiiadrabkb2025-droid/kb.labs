"""Тести для інтерфейсу командного рядка (CLI)."""

import pathlib

import pytest

from labs.lab04 import main


def test_cli_local_input_success(capsys: pytest.CaptureFixture) -> None:
    """Перевірка локального запуску через --input."""
    sample_file = pathlib.Path("labs/lab04/data/nvd_sample.json")
    code = main.main(["--cve", "CVE-2099-10001", "--input", str(sample_file)])
    assert code == 0

    captured = capsys.readouterr()
    assert "CVE-2099-10001" in captured.out
    assert '"variant": 10' in captured.out


def test_cli_invalid_cve_format(capsys: pytest.CaptureFixture) -> None:
    """Перевірка некоректного формату CVE ID."""
    code = main.main(["--cve", "invalid-cve-format"])
    assert code == 2
    captured = capsys.readouterr()
    assert "Некоректний формат CVE ID" in captured.err


def test_cli_file_not_found(capsys: pytest.CaptureFixture) -> None:
    """Перевірка відсутності файла."""
    code = main.main(["--cve", "CVE-2099-10001", "--input", "non_existent_file.json"])
    assert code == 1
    captured = capsys.readouterr()
    assert "Помилка отримання даних" in captured.err


def test_cli_invalid_variant_number(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """Перевірка некоректного VARIANT_NUMBER."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", 99)
    code = main.main(["--cve", "CVE-2099-10001"])
    assert code == 2
    captured = capsys.readouterr()
    assert "VARIANT_NUMBER має бути цілим числом від 1 до 15" in captured.err
