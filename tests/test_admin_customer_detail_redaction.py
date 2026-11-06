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


def test_admin_client_update_commits_before_writing_audit_and_returns_private_response():
    source = inspect.getsource(main.admin_update_client)
    assert 'previous_values = {' in source
    assert 'current_values = {' in source
    assert '"previous": previous_values' in source
    assert '"updated": current_values' in source
    assert source.index('await db.commit()') < source.index('await _write_admin_log(')
    assert 'response.headers["Cache-Control"] = "no-store, private"' in source
    assert 'response.headers["Pragma"] = "no-cache"' in source
