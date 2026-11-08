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


def test_admin_customer_detail_bounds_identity_keys_and_paginates_license_inventory():
    import inspect

    from main import admin_customer_account_detail

    source = inspect.getsource(admin_customer_account_detail)
    assert 'license_limit: int = Query(default=100, ge=1, le=100)' in source
    assert 'license_offset: int = Query(default=0, ge=0, le=1000000)' in source
    assert '.limit(1001)' in source
    assert 'identity_keys_truncated = len(customer_license_keys) > 1000' in source
    assert 'select(sql_func.count()).select_from(matched_license_ids)' in source
    assert '.offset(license_offset).limit(license_limit)' in source
    assert '"has_more": license_offset + len(rows) < license_total' in source


def test_admin_customer_detail_ui_supports_load_more_license_pages():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert 'Load more licenses' in source
    assert 'license_offset=' in source
    assert 'license_page.has_more' in source
