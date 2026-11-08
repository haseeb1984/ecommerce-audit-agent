from pathlib import Path


def test_admin_customer_directory_ignores_stale_search_and_pagination_responses():
    source = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert "let customerDirectoryRequestVersion = 0;" in source
    assert "const requestVersion=++customerDirectoryRequestVersion;" in source
    assert 'if(requestVersion!==customerDirectoryRequestVersion||search!==$("customerAccountSearch").value.trim())return;' in source
    assert 'const search=$("customerAccountSearch").value.trim();' in source


def test_admin_customer_detail_ignores_stale_account_responses_and_signout_invalidates_requests():
    source = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert "let customerDetailRequestVersion = 0;" in source
    assert "const requestVersion=++customerDetailRequestVersion;" in source
    assert "if(requestVersion!==customerDetailRequestVersion" in source
    assert "customerDirectoryRequestVersion++;customerDetailRequestVersion++;" in source
    assert 'selectedCustomerEmail="";' in source


def test_admin_customer_directory_merges_legacy_and_operational_identities():
    from datetime import datetime, timezone, timedelta
    from types import SimpleNamespace

    from main import _merge_admin_customer_directory_candidates

    recent = datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc)
    operational = [
        SimpleNamespace(email="shared@example.com", activity_at=recent),
        SimpleNamespace(email="operational-only@example.com", activity_at=None),
    ]
    legacy = [
        SimpleNamespace(email="shared@example.com", activity_at=recent - timedelta(days=1)),
        SimpleNamespace(email="legacy-only@example.com", activity_at=recent - timedelta(days=2)),
    ]

    merged = _merge_admin_customer_directory_candidates(operational, legacy)

    assert [item["email"] for item in merged] == [
        "shared@example.com",
        "legacy-only@example.com",
        "operational-only@example.com",
    ]
    assert merged[0]["activity_at"] == recent


def test_admin_customer_directory_resolves_page_licenses_in_one_batched_query():
    import inspect

    from main import admin_customer_directory

    source = inspect.getsource(admin_customer_directory)
    assert "page_license_keys = sorted({" in source
    assert "page_license_rows = (await db.execute(" in source
    assert "license_by_key = {item.license_key: item for item in page_license_rows}" in source
    assert "license_by_key[license_key]" in source
    assert "await db.execute(" not in source[source.index("items = []"):source.index('return {"items": items')]


def test_admin_customer_directory_counts_cross_database_email_union_with_sorted_streams():
    import asyncio

    from main import _count_sorted_admin_customer_email_union

    async def values(items):
        for item in items:
            yield item

    assert asyncio.run(_count_sorted_admin_customer_email_union(
        values(["a@example.com", "b@example.com", "d@example.com"]),
        values(["b@example.com", "c@example.com", "d@example.com", "e@example.com"]),
    )) == 5


def test_admin_customer_directory_streams_distinct_email_counts_and_closes_both_streams():
    import inspect

    from main import admin_customer_directory

    source = inspect.getsource(admin_customer_directory)
    assert "operational_email_stream = await operational_db.stream(" in source
    assert "legacy_email_stream = await db.stream(" in source
    assert "_count_sorted_admin_customer_email_union(" in source
    assert "await operational_email_stream.close()" in source
    assert "await legacy_email_stream.close()" in source
    assert "operational_emails = set(" not in source
    assert "legacy_emails = set(" not in source


def test_admin_customer_detail_streams_all_identity_keys_and_paginates_license_inventory():
    import inspect

    from main import admin_customer_account_detail

    source = inspect.getsource(admin_customer_account_detail)
    assert 'license_limit: int = Query(default=100, ge=1, le=100)' in source
    assert 'license_offset: int = Query(default=0, ge=0, le=1000000)' in source
    assert 'CREATE TEMP TABLE admin_customer_identity_keys' in source
    assert 'identity_values.fetchmany(500)' in source
    assert 'ON CONFLICT (license_key) DO NOTHING' in source
    assert 'await identity_key_stream.close()' in source
    assert 'identity_keys_truncated' not in source
    assert 'select(sql_func.count()).select_from(matched_license_ids)' in source
    assert '.offset(license_offset).limit(license_limit)' in source
    assert '"has_more": license_offset + len(rows) < license_total' in source


def test_admin_customer_detail_ui_supports_load_more_license_pages():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert 'Load more licenses' in source
    assert 'license_offset=' in source
    assert 'license_page.has_more' in source
    assert 'identity_keys_truncated' not in source


def test_admin_customer_note_chooses_canonical_key_with_database_minima():
    import inspect

    from main import admin_add_customer_note

    source = inspect.getsource(admin_add_customer_note)
    assert 'select(sql_func.min(operational_note_keys.c.license_key))' in source
    assert 'sql_func.min(SoftwareLicense.license_key)' in source
    assert 'candidate_note_keys = [key for key in (operational_note_key, legacy_note_key) if key]' in source
    assert 'note_license_keys = set(' not in source
    assert 'note_license_keys.update(' not in source



def test_account_wide_customer_lifecycle_actions_stream_and_lock_in_bounded_batches():
    import inspect

    from main import admin_customer_account_action

    source = inspect.getsource(admin_customer_account_action)
    assert "CREATE TEMP TABLE admin_customer_action_license_keys" in source
    assert "identity_stream = await operational_db.stream(operational_identity_query)" in source
    assert "identity_values.fetchmany(500)" in source
    assert "await identity_stream.close()" in source
    assert "locked_stream = await db.stream(locked_query)" in source
    assert "locked_rows.fetchmany(500)" in source
    assert ".order_by(SoftwareLicense.id.asc())" in source
    assert ".with_for_update()" in source
    assert "db.add_all([" in source
    assert '"license_count": license_count' in source
    assert "account_license_keys = set(" not in source
    assert "ids = set(" not in source
    assert "legacy_ids = (" not in source


def test_account_wide_customer_lifecycle_mirror_uses_operational_subquery_not_python_key_list():
    import inspect

    from main import admin_customer_account_action

    source = inspect.getsource(admin_customer_account_action)
    mirror_block = source[source.index("operational_license_keys ="):source.index("await operational_db.commit()")]
    assert "CustomerBillingEvent.recipient_email" in mirror_block
    assert "CustomerAccount.email" in mirror_block
    assert "CustomerSession.license_key.in_(operational_license_keys)" in mirror_block
    assert "in_(license_keys)" not in mirror_block
    assert "license_keys =" not in mirror_block
