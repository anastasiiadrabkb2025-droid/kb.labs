"""Тести аналізу даних і правил за Варіантом 10."""

import pytest

from labs.lab04.analysis import build_report, extract_record


@pytest.fixture
def base_payload() -> dict:
    """Базовий словник із відповіддю NVD для CVE-2099-10001."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-10-26T00:00:00.000",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-10001",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "LOW",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "HIGH",
                                    "availabilityImpact": "HIGH",
                                    "baseScore": 7.5,
                                },
                            }
                        ]
                    },
                }
            }
        ],
    }


def test_variant_10_review_and_other(base_payload: dict) -> None:
    """Перевірка стану review та other для Варіанта 10."""
    rec = extract_record(base_payload, "CVE-2099-10001")
    rep = build_report(rec, "CVE-2099-10001", 10)
    assert rep["decision"] == "review"
    assert rep["observed"] == "LOW"

    base_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]["privilegesRequired"] = "NONE"
    rec = extract_record(base_payload, "CVE-2099-10001")
    rep = build_report(rec, "CVE-2099-10001", 10)
    assert rep["decision"] == "other"


@pytest.mark.parametrize(
    "score, expected_decision",
    [
        (5.9, "other"),
        (6.0, "review"),
        (8.5, "review"),
    ],
)
def test_variant_10_threshold_boundary(
    base_payload: dict, score: float, expected_decision: str
) -> None:
    """Перевірка межі порога (5.9, 6.0, 8.5) для Варіанта 10."""
    base_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]["baseScore"] = score
    rec = extract_record(base_payload, "CVE-2099-10001")
    rep = build_report(rec, "CVE-2099-10001", 10)
    assert rep["decision"] == expected_decision


def test_record_not_found() -> None:
    """Перевірка стану not_found."""
    payload = {"vulnerabilities": []}
    rec = extract_record(payload, "CVE-2099-10001")
    rep = build_report(rec, "CVE-2099-10001", 10)
    assert rep["decision"] == "not_found"


def test_record_rejected(base_payload: dict) -> None:
    """Перевірка стану rejected."""
    base_payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    rec = extract_record(base_payload, "CVE-2099-10001")
    rep = build_report(rec, "CVE-2099-10001", 10)
    assert rep["decision"] == "rejected"


def test_insufficient_data(base_payload: dict) -> None:
    """Перевірка стану insufficient_data."""
    base_payload["vulnerabilities"][0]["cve"]["metrics"] = {}
    rec = extract_record(base_payload, "CVE-2099-10001")
    rep = build_report(rec, "CVE-2099-10001", 10)
    assert rep["decision"] == "insufficient_data"


def test_primary_metric_priority(base_payload: dict) -> None:
    """Перевірка пріоритету оцінки Primary над Secondary."""
    sec_metric = {
        "source": "sec@example.com",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "privilegesRequired": "HIGH",
            "baseScore": 3.0,
        },
    }
    prim_metric = base_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]
    base_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        sec_metric,
        prim_metric,
    ]

    rec = extract_record(base_payload, "CVE-2099-10001")
    assert rec["score"] == 7.5
    assert rec["score_source"] == "nvd@nist.gov"


def test_invalid_field_value_raises_error(base_payload: dict) -> None:
    """Перевірка винятку при некоректному значенні поля."""
    base_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]["privilegesRequired"] = "INVALID_VAL"
    rec = extract_record(base_payload, "CVE-2099-10001")
    with pytest.raises(ValueError, match="Недопустиме значення поля"):
        build_report(rec, "CVE-2099-10001", 10)
