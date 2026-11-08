from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Response

import main


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows


class _WordPressSitesDB:
    def __init__(self, total, rows):
        self.total = total
        self.rows = rows
        self.count_query = None
        self.page_query = None

    async def scalar(self, query):
        self.count_query = query
        return self.total

    async def execute(self, query):
        self.page_query = query
        return _Rows(self.rows)


@pytest.mark.asyncio
async def test_customer_wordpress_site_listing_returns_bounded_page_metadata():
    site = SimpleNamespace(
        id="wp-site-101",
        site_url="https://store.example/",
        site_host="store.example",
        admin_email="admin@store.example",
        wordpress_user_id="12",
        wordpress_user_login="store-admin",
        wordpress_version="6.8",
        woocommerce_version="10.0",
        plugin_version="1.1.0",
        status="disconnected",
        last_seen_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        disconnected_at=datetime(2026, 11, 2, tzinfo=timezone.utc),
    )
    db = _WordPressSitesDB(total=101, rows=[site])
    response = Response()

    result = await main.list_account_wordpress_sites(
        response,
        limit=100,
        offset=100,
        license_obj=SimpleNamespace(license_key="license-77"),
        operational_db=db,
    )

    assert result["page"] == {
        "limit": 100,
        "offset": 100,
        "total": 101,
        "has_more": False,
    }
    assert result["items"][0]["site_id"] == "wp-site-101"
    assert result["items"][0]["status"] == "disconnected"
    assert db.page_query._limit_clause.value == 100
    assert db.page_query._offset_clause.value == 100
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"


def test_customer_wordpress_portal_loads_installations_in_session_safe_pages():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadWordPressSites")
    end = portal.index("async function loadProfile", start)
    source = portal[start:end]
    clear_start = portal.index("function clearAccountView")
    clear_end = portal.index("function ", clear_start + 10)
    clear_source = portal[clear_start:clear_end]

    assert 'id="loadMoreWordPressSites"' in portal
    assert '"/api/v1/account/wordpress-sites?limit=100&offset=" + offset' in source
    assert "if (wordpressSitesLoading) return;" in source
    assert "wordpressSitesLoading = true;" in source
    assert "wordpressSitesOffset = offset + items.length;" in source
    assert "wordpressSitesHasMore = Boolean(data.page && data.page.has_more);" in source
    assert "loadWordPressSites(wordpressSitesOffset, true).catch(() => {});" in source
    assert "requestVersion !== wordpressSitesRequestVersion || requestSessionVersion !== accountSessionVersion" in source
    assert "wordpressSitesRequestVersion += 1;" in clear_source
    assert "wordpressSitesLoading = false;" in clear_source
    assert ' $("loadMoreWordPressSites").hidden = true;' in clear_source or '$("loadMoreWordPressSites").hidden = true;' in clear_source
