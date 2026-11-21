import pytest
from fastapi import HTTPException

from main import _normalize_wordpress_registration_url


def test_wordpress_registration_url_rejects_non_numeric_port():
    with pytest.raises(HTTPException) as exc:
        _normalize_wordpress_registration_url("https://example.com:notaport/")
    assert exc.value.status_code == 422


def test_wordpress_registration_url_rejects_nonstandard_https_port():
    with pytest.raises(HTTPException) as exc:
        _normalize_wordpress_registration_url("https://example.com:8443/")
    assert exc.value.status_code == 422


def test_wordpress_registration_url_accepts_and_normalizes_standard_https_port():
    assert _normalize_wordpress_registration_url("https://EXAMPLE.com:443/store/") == (
        "https://example.com/store/",
        "example.com",
    )


def test_wordpress_registration_url_rejects_non_https_and_credentials():
    for value in (
        "http://example.com/",
        "https://user:password@example.com/",
    ):
        with pytest.raises(HTTPException) as exc:
            _normalize_wordpress_registration_url(value)
        assert exc.value.status_code == 422


def test_wordpress_registration_url_rejects_query_and_fragment():
    for value in (
        "https://example.com/?token=value",
        "https://example.com/#section",
    ):
        with pytest.raises(HTTPException) as exc:
            _normalize_wordpress_registration_url(value)
        assert exc.value.status_code == 422
