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
        "operational-only@example.com",
        "shared@example.com",
        "legacy-only@example.com",
    ]
    assert merged[1]["activity_at"] == recent
