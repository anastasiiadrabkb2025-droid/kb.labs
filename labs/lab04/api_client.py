"""Клієнт для взаємодії з NVD CVE API 2.0."""

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def build_headers() -> dict[str, str]:
    """Сформувати HTTP-заголовки для запиту до NVD API."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def fetch_response(cve_id: str) -> dict[str, Any]:
    """Виконати GET-запит до NVD API за вказаним cve_id."""
    params = {"cveId": cve_id}
    headers = build_headers()
    response = requests.get(
        NVD_API_URL,
        params=params,
        headers=headers,
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status()

    if response.status_code != 200:
        raise requests.HTTPError(
            f"Неочікуваний HTTP-статус: {response.status_code}",
            response=response,
        )

    data: dict[str, Any] = response.json()
    return data
