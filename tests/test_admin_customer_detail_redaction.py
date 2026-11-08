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



def test_admin_customer_detail_sublist_pagination_is_independent_and_bounded():
    source = inspect.getsource(main.admin_customer_account_detail)

    for parameter in ("session_limit", "wordpress_limit", "note_limit"):
        assert f"{parameter}: int = Query(default=50, ge=1, le=100)" in source

    for parameter in ("session_offset", "wordpress_offset", "note_offset"):
        assert f"{parameter}: int = Query(default=0, ge=0, le=1000000)" in source

    assert '"session_page"' in source
    assert '"wordpress_page"' in source
    assert '"note_page"' in source
    assert "hostinger_identity_keys = identity_keys_query.subquery" in source
    assert "CustomerSession.license_key.in_(hostinger_license_keys)" in source
    assert "WordPressInstallation.license_key.in_(hostinger_license_keys)" in source
    assert "session_offset).limit(session_limit)" in source
    assert "wordpress_offset).limit(wordpress_limit)" in source
    assert "note_offset).limit(note_limit)" in source


def test_admin_customer_detail_does_not_reference_removed_identity_truncation_variable():
    source = inspect.getsource(main.admin_customer_account_detail)

    # The full identity-key stream has no arbitrary truncation state anymore.
    assert '"identity_keys_truncated": False' in source
    assert '"identity_keys_truncated": identity_keys_truncated' not in source



def test_admin_customer_detail_billing_history_has_independent_union_pagination():
    source = inspect.getsource(main.admin_customer_account_detail)

    assert "billing_limit: int = Query(default=50, ge=1, le=100)" in source
    assert "billing_offset: int = Query(default=0, ge=0, le=1000000)" in source
    assert "_count_sorted_billing_event_id_union(pg_event_ids, host_event_ids)" in source
    assert "candidate_limit = billing_offset + billing_limit" in source
    assert "billing_offset:billing_offset + billing_limit" in source
    assert '"billing_page"' in source
    assert "sql_func.lower(PaymentWebhookEvent.recipient_email) == normalized" in source


def test_admin_customer_detail_billing_load_more_control_is_scoped_to_selected_customer():
    from pathlib import Path

    portal = Path("admin_portal.html").read_text()
    assert '"Load more billing events"' in portal
    assert 'billing_offset="+(p.offset+p.limit)' in portal
    assert "if(selectedCustomerEmail!==d.email)return;appendBilling(next.billing_events)" in portal
