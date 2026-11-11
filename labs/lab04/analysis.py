"""Модуль перевірки структури відповіді NVD API та аналізу за варіантом."""

from typing import Any

VARIANT_RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}

ALLOWED_METRIC_VALUES: dict[str, set[str]] = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}


def extract_record(payload: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    """Вилучити дані про вразливість та метрики CVSS v3.1 із payload."""
    if not isinstance(payload, dict):
        raise TypeError("Payload має бути словником")

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise TypeError("Поле 'vulnerabilities' має бути списком")

    if len(vulnerabilities) == 0:
        return None

    if len(vulnerabilities) > 1:
        raise ValueError("Очікується не більше одного запису про вразливість")

    item = vulnerabilities[0]
    if not isinstance(item, dict) or "cve" not in item:
        raise TypeError("Елемент vulnerabilities має містити об'єкт 'cve'")

    cve = item["cve"]
    if not isinstance(cve, dict):
        raise TypeError("Поле 'cve' має бути словником")

    if cve.get("id") != cve_id:
        raise ValueError(
            f"ID у відповіді ({cve.get('id')}) не збігається із запитаним ({cve_id})"
        )

    vuln_status = cve.get("vulnStatus")
    if vuln_status is not None and not isinstance(vuln_status, str):
        raise TypeError("Поле 'vulnStatus' має бути рядком або None")

    description: str | None = None
    descriptions = cve.get("descriptions")
    if descriptions is not None:
        if not isinstance(descriptions, list):
            raise TypeError("Поле 'descriptions' має бути списком")
        for d in descriptions:
            if isinstance(d, dict) and d.get("lang") == "en":
                val = d.get("value")
                if isinstance(val, str) and val.strip():
                    description = val
                    break

    if vuln_status == "Rejected" or vuln_status is None:
        return {
            "vuln_status": vuln_status,
            "description": description,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "cvss_data": None,
        }

    metrics = cve.get("metrics")
    if metrics is None:
        cvss_list = None
    elif isinstance(metrics, dict):
        cvss_list = metrics.get("cvssMetricV31")
    else:
        raise TypeError("Поле 'metrics' має бути словником")

    if cvss_list is None:
        return {
            "vuln_status": vuln_status,
            "description": description,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "cvss_data": None,
        }

    if not isinstance(cvss_list, list):
        raise TypeError("Поле 'cvssMetricV31' має бути списком")

    if len(cvss_list) == 0:
        return {
            "vuln_status": vuln_status,
            "description": description,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "cvss_data": None,
        }

    selected_metric = None
    for m in cvss_list:
        if isinstance(m, dict) and m.get("type") == "Primary":
            selected_metric = m
            break
    if selected_metric is None:
        first_m = cvss_list[0]
        if isinstance(first_m, dict):
            selected_metric = first_m
        else:
            raise TypeError("Елементи cvssMetricV31 мають бути словниками")

    cvss_data = selected_metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise TypeError("Поле 'cvssData' має бути словником")

    base_score = cvss_data.get("baseScore")
    if isinstance(base_score, bool) or not isinstance(base_score, (int, float)):
        raise TypeError("Поле 'baseScore' має бути числом від 0 до 10")
    if base_score < 0 or base_score > 10:
        raise ValueError("Поле 'baseScore' має бути в діапазоні від 0 до 10")

    version = cvss_data.get("version")
    if version is not None:
        if not isinstance(version, str):
            raise TypeError("Поле 'version' має бути рядком '3.1'")
        if version != "3.1":
            raise ValueError("Поле 'version' має бути рядком '3.1'")

    vector = cvss_data.get("vectorString")
    if vector is not None and not isinstance(vector, str):
        raise TypeError("Поле 'vectorString' має бути рядком")

    source = selected_metric.get("source")
    if source is not None and not isinstance(source, str):
        raise TypeError("Поле 'source' має бути рядком")

    return {
        "vuln_status": vuln_status,
        "description": description,
        "cvss_version": version,
        "score": float(base_score),
        "score_source": source,
        "vector": vector,
        "cvss_data": cvss_data,
    }


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Сформувати фінальний словник звіту за правилом варіанта."""
    if variant not in VARIANT_RULES:
        raise ValueError(f"Некоректний номер варіанта: {variant}")

    rule_cfg = VARIANT_RULES[variant]
    threshold: float = rule_cfg["threshold"]
    field: str = rule_cfg["field"]
    expected: str = rule_cfg["expected"]

    rule = {
        "threshold": threshold,
        "field": field,
        "expected": expected,
    }

    if record is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": None,
            "vuln_status": None,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "not_found",
        }

    vuln_status = record["vuln_status"]
    if vuln_status == "Rejected":
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": record["description"],
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "rejected",
        }

    cvss_data = record["cvss_data"]
    score = record["score"]

    observed = None
    if cvss_data is not None and field in cvss_data:
        val = cvss_data[field]
        if (
            val is None
            or not isinstance(val, str)
            or val not in ALLOWED_METRIC_VALUES[field]
        ):
            raise ValueError(f"Недопустиме значення поля '{field}': {val}")
        observed = val

    if vuln_status is None or cvss_data is None or score is None or observed is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": record["description"],
            "vuln_status": vuln_status,
            "cvss_version": record["cvss_version"],
            "score": score,
            "score_source": record["score_source"],
            "vector": record["vector"],
            "rule": rule,
            "observed": observed,
            "decision": "insufficient_data",
        }

    if score >= threshold and observed == expected:
        decision = "review"
    else:
        decision = "other"

    return {
        "cve_id": cve_id,
        "variant": variant,
        "description": record["description"],
        "vuln_status": vuln_status,
        "cvss_version": record["cvss_version"],
        "score": score,
        "score_source": record["score_source"],
        "vector": record["vector"],
        "rule": rule,
        "observed": observed,
        "decision": decision,
    }
