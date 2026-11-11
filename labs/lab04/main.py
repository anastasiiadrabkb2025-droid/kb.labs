"""Точка входу CLI для аналізу вразливостей NVD CVE."""

import argparse
import json
import pathlib
import re
import sys
from collections.abc import Sequence

import requests

from labs.lab04.analysis import build_report, extract_record
from labs.lab04.api_client import fetch_response
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def load_response(path: pathlib.Path) -> dict:
    """Зчитати JSON-відповідь із локального файла."""
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"Помилка читання файла '{path}': {e}") from e

    if not isinstance(data, dict):
        raise TypeError("Вміст JSON-файла має бути об'єктом")
    return data


def main(argv: Sequence[str] | None = None) -> int:
    """Головна функція CLI."""
    if (
        isinstance(VARIANT_NUMBER, bool)
        or not isinstance(VARIANT_NUMBER, int)
        or VARIANT_NUMBER < 1
        or VARIANT_NUMBER > 15
    ):
        sys.stderr.write(
            f"Помилка: VARIANT_NUMBER має бути цілим числом від 1 до 15. Отримано: {VARIANT_NUMBER}\n"
        )
        return 2

    parser = argparse.ArgumentParser(description="Аналізатор вразливостей NVD CVE")
    parser.add_argument(
        "--cve", required=True, help="Ідентифікатор CVE (наприклад, CVE-2021-44228)"
    )
    parser.add_argument(
        "--input", type=pathlib.Path, help="Шлях до локального JSON-файла"
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2

    cve_id: str = args.cve
    if not CVE_PATTERN.fullmatch(cve_id):
        sys.stderr.write(
            f"Помилка: Некоректний формат CVE ID '{cve_id}'. Очікується формат CVE-YYYY-NNNN.\n"
        )
        return 2

    try:
        if args.input is not None:
            payload = load_response(args.input)
        else:
            payload = fetch_response(cve_id)
    except (requests.RequestException, ValueError, TypeError) as e:
        sys.stderr.write(f"Помилка отримання даних: {e}\n")
        return 1

    try:
        record = extract_record(payload, cve_id)
        report = build_report(record, cve_id, VARIANT_NUMBER)
    except (ValueError, TypeError) as e:
        sys.stderr.write(f"Помилка перевірки чи аналізу даних: {e}\n")
        return 1

    sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
