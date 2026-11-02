import pytest
from fastapi import HTTPException

from hostinger_models import WordPressInstallation, WordPressSiteLinkChallenge
from wordpress_identity_api import _normalize_site_url, _token_digest, WordPressLinkClaim


def test_wordpress_link_challenge_schema_is_license_scoped_and_single_use():
    columns = set(WordPressSiteLinkChallenge.__table__.columns.keys())
    assert {"id", "license_key", "token_hash", "expires_at", "consumed_at", "created_at"} <= columns
    assert WordPressSiteLinkChallenge.__table__.c.token_hash.unique


def test_wordpress_installation_records_linked_wp_user_identity():
    columns = set(WordPressInstallation.__table__.columns.keys())
    assert {"license_key", "site_host", "wordpress_user_id", "wordpress_user_login"} <= columns


def test_wordpress_site_url_is_normalized_to_https_origin_and_path():
    assert _normalize_site_url("https://Shop.Example.com/store/") == (
        "https://shop.example.com/store/", "shop.example.com"
    )


@pytest.mark.parametrize("url", [
    "http://shop.example.com/",
    "https://user:pass@shop.example.com/",
    "https://shop.example.com/?token=secret",
    "https://shop.example.com/#fragment",
    "https://shop.example.com:8443/",
])
def test_wordpress_link_rejects_unsafe_site_urls(url):
    with pytest.raises(HTTPException):
        _normalize_site_url(url)


def test_wordpress_link_token_is_stored_as_sha256_digest():
    token = "a" * 48
    assert _token_digest(token) == _token_digest(token)
    assert _token_digest(token) != token


def test_wordpress_link_claim_requires_positive_wp_user_id():
    with pytest.raises(Exception):
        WordPressLinkClaim(
            token="t" * 48,
            site_url="https://shop.example.com/",
            wp_user_id=0,
            wp_user_login="storeadmin",
            wp_user_email="admin@example.com",
        )
