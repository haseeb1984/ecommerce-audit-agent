import hashlib
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
    assert _token_digest(token) == hashlib.sha256(token.encode("utf-8")).hexdigest()
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


def test_wordpress_identity_routes_are_registered_in_the_saas_application():
    import main

    paths = set(main.app.openapi()["paths"])
    assert "/api/v1/account/wordpress-link/challenges" in paths
    assert "/api/v1/integrations/wordpress/sites/claim" in paths


def test_wordpress_identity_forward_migration_matches_model_contract():
    from pathlib import Path

    migration = Path("migrations/20261103_wordpress_identity_linking.sql").read_text()
    assert "wordpress_user_id" in migration
    assert "wordpress_user_login" in migration
    assert "wordpress_site_link_challenges" in migration


def test_wordpress_plugin_uses_admin_nonce_for_identity_claim():
    from pathlib import Path

    plugin = Path("wordpress-plugin/ecommerce-audit-agent/ecommerce-audit-agent.php").read_text()
    assert "admin_post_eaa_link_customer_identity" in plugin
    assert "wp_verify_nonce($nonce, 'eaa_link_customer_identity')" in plugin
    assert "eaa_wp_dashboard_capability()" in plugin
    assert "/api/v1/integrations/wordpress/sites/claim" in plugin
