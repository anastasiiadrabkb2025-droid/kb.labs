"""Тести для мережевого клієнта NVD API."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client


def test_build_headers_without_and_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Перевірка формування заголовків без ключа та з ключем."""
    headers = api_client.build_headers()
    assert headers == {"Accept": "application/json"}

    monkeypatch.setenv("NVD_API_KEY", "  fake_test_key_123  ")
    headers_with_key = api_client.build_headers()
    assert headers_with_key == {
        "Accept": "application/json",
        "apiKey": "fake_test_key_123",
    }


def test_fetch_response_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Перевірка успішного виконання fetch_response."""
    payload = {"startIndex": 0, "totalResults": 1, "vulnerabilities": []}
    response_mock = Mock(spec=requests.Response)
    response_mock.status_code = 200
    response_mock.json.return_value = payload

    fake_get = Mock(return_value=response_mock)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    result = api_client.fetch_response("CVE-2099-10001")
    assert result == payload

    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )


def test_fetch_response_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Перевірка обробки HTTP-помилки."""
    response_mock = Mock(spec=requests.Response)
    response_mock.status_code = 404
    response_mock.raise_for_status.side_effect = requests.HTTPError("404 Client Error")

    fake_get = Mock(return_value=response_mock)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(requests.HTTPError):
        api_client.fetch_response("CVE-2099-10001")
