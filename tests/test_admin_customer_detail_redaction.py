import inspect

import main


def test_admin_customer_detail_does_not_return_license_or_authentication_secrets():
    source = inspect.getsource(main.admin_customer_account_detail)

    # Account detail is a support view, not a credential retrieval endpoint.
    # WordPress site metadata must remain useful without exposing the linked key.
    assert '"license_key": item.license_key' not in source
    assert '"api_key"' not in source
    assert '"bearer_token"' not in source
    assert '"token_hash"' not in source
    assert '"token_digest"' not in source
    assert '"site_url": item.site_url' in source
    assert '"site_host": item.site_host' in source



def test_admin_wordpress_link_inventory_exposes_bounded_connection_health_without_secrets():
    source = inspect.getsource(main.admin_list_client_wordpress_links)

    assert 'now = datetime.now(timezone.utc)' in source
    assert '"connection_health"' in source
    assert '"not_connected"' in source
    assert '"stale"' in source
    assert '"healthy"' in source
    assert 'timedelta(days=7)' in source
    assert '"token_hash"' not in source
    assert '"token_digest"' not in source
    assert '"license_key":' not in source


def test_admin_wordpress_connection_health_is_visible_in_operator_console():
    from pathlib import Path

    portal = Path(__file__).resolve().parents[1] / "admin_portal.html"
    source = portal.read_text(encoding="utf-8")

    assert 'item.connection_health' in source
    assert 'staleHeartbeat' in source
    assert 'Connection health ' in source
    assert 'No recent plugin heartbeat.' in source
