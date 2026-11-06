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


def test_admin_client_detail_panels_ignore_stale_client_responses():
    from pathlib import Path

    portal = Path("admin_portal.html").read_text()
    assert "let currentHistoryId=null,clientDetailVersion=0;" in portal
    assert "const detailVersion=++clientDetailVersion;currentHistoryId=id;" in portal
    assert "if(detailVersion!==clientDetailVersion||currentHistoryId!==id)return;" in portal
    assert "loadClientSessions(id,detailVersion)" in portal
    assert "loadClientWordPressLinks(id,detailVersion)" in portal
    assert "loadClientApiKeys(id,detailVersion)" in portal
    assert "clientDetailVersion+=1;currentHistoryId=null;" in portal
