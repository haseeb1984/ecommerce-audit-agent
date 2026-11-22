from types import SimpleNamespace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import Response

from main import list_account_wordpress_sites


class _ScalarRows:
    def all(self):
        return []


class _Result:
    def scalars(self):
        return _ScalarRows()


class _OperationalSession:
    def __init__(self):
        self.statement = None

    async def scalar(self, statement):
        self.count_statement = statement
        return 0

    async def execute(self, statement):
        self.statement = statement
        return _Result()


@pytest.mark.asyncio
async def test_customer_wordpress_inventory_prioritizes_active_site_before_history():
    operational_db = _OperationalSession()
    response = Response()

    result = await list_account_wordpress_sites(
        response=response,
        license_obj=SimpleNamespace(license_key="license-test"),
        operational_db=operational_db,
    )

    statement = operational_db.statement
    order_by = [
        str(expression.compile(compile_kwargs={"literal_binds": True}))
        for expression in statement._order_by_clauses
    ]
    sql = str(statement.compile(compile_kwargs={"literal_binds": True}))

    assert "CASE" in order_by[0]
    assert "wordpress_installations.status = 'active'" in order_by[0]
    assert order_by[1] == "wordpress_installations.last_seen_at DESC"
    assert "LIMIT 100" in sql
    assert result == {
        "items": [],
        "page": {"limit": 100, "offset": 0, "total": 0, "has_more": False},
    }
    assert response.headers["Cache-Control"] == "no-store, private"
    assert response.headers["Pragma"] == "no-cache"


def test_agency_wordpress_connection_ui_supports_health_refresh_and_token_replacement():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadAgencyDashboard")
    end = portal.index("async function loadAgencyClientAuditResults", start)
    section = portal[start:end]

    assert 'refreshWebsite.textContent = "Refresh connection status";' in section
    assert 'website.connection_health === "healthy"' in section
    assert 'website.connection_health === "stale"' in section
    assert 'connectWebsite.textContent = "Generate replacement token";' in section
    assert 'window.confirm("Generate a replacement token?' in section
    assert 'Generating another token invalidates this one.' in section
    assert 'refreshWebsiteStatus();' in section


class _ScalarSiteResult:
    def __init__(self, site):
        self.site = site

    def scalar_one_or_none(self):
        return self.site


class _DisconnectSession:
    def __init__(self, site):
        self.site = site
        self.commits = 0

    async def execute(self, statement):
        return _ScalarSiteResult(self.site)

    async def commit(self):
        self.commits += 1


class _CanonicalLicenseSession:
    async def scalar(self, statement):
        return SimpleNamespace(id=1, license_key="license-test")


@pytest.mark.asyncio
async def test_customer_wordpress_disconnect_is_idempotent_after_successful_disconnect():
    from types import SimpleNamespace
    from main import customer_disconnect_wordpress_site

    disconnected_at = datetime.now(timezone.utc)
    site = SimpleNamespace(
        id="wordpress-site-id-1234567890",
        license_key="license-test",
        status="disconnected",
        disconnected_at=disconnected_at,
    )
    operational_db = _DisconnectSession(site)
    response = Response()

    result = await customer_disconnect_wordpress_site(
        site_id=site.id,
        response=response,
        license_obj=SimpleNamespace(id=1, license_key="license-test"),
        db=_CanonicalLicenseSession(),
        operational_db=operational_db,
    )

    assert result == {"status": "already_disconnected", "site_id": site.id}
    assert operational_db.commits == 0
    assert site.disconnected_at == disconnected_at
    assert response.headers["Cache-Control"] == "no-store, private"


@pytest.mark.asyncio
async def test_legacy_wordpress_disconnect_is_idempotent_after_successful_disconnect():
    from types import SimpleNamespace
    from main import WordPressInstallationAction, disconnect_wordpress_site

    disconnected_at = datetime.now(timezone.utc)
    site = SimpleNamespace(
        id="wordpress-site-id-1234567890",
        license_key="license-test",
        status="disconnected",
        disconnected_at=disconnected_at,
    )
    operational_db = _DisconnectSession(site)
    response = Response()

    result = await disconnect_wordpress_site(
        payload=WordPressInstallationAction(site_id=site.id),
        response=response,
        license_obj=SimpleNamespace(id=1, license_key="license-test"),
        db=_CanonicalLicenseSession(),
        operational_db=operational_db,
    )

    assert result == {"status": "already_disconnected", "site_id": site.id}
    assert operational_db.commits == 0
    assert site.disconnected_at == disconnected_at
    assert response.headers["Pragma"] == "no-cache"



def test_wordpress_disconnect_serializes_with_identity_claim_and_revokes_pending_codes():
    import inspect
    from main import customer_disconnect_wordpress_site, disconnect_wordpress_site

    for endpoint in (customer_disconnect_wordpress_site, disconnect_wordpress_site):
        source = inspect.getsource(endpoint)
        canonical_lock = source.index("db.scalar(")
        operational_site_lock = source.index("operational_db.execute(select(WordPressInstallation)")
        challenge_revocation = source.index("update(WordPressSiteLinkChallenge)")
        assert canonical_lock < operational_site_lock < challenge_revocation
        assert "WordPressSiteLinkChallenge.consumed_at.is_(None)" in source
        assert ".values(consumed_at=disconnected_at)" in source
        assert 'if site.status == "active":' in source



def test_customer_wordpress_inventory_refresh_ignores_older_responses():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadWordPressSites")
    end = portal.index("async function loadProfile", start)
    source = portal[start:end]

    assert "const requestSessionVersion = accountSessionVersion;" in source
    assert "const requestVersion = ++wordpressSitesRequestVersion;" in source
    stale_guard = source.index("requestVersion !== wordpressSitesRequestVersion || requestSessionVersion !== accountSessionVersion")
    render = source.index("container.replaceChildren();")
    assert stale_guard < render
    assert "requestVersion === wordpressSitesRequestVersion && requestSessionVersion === accountSessionVersion" in source


def test_customer_wordpress_inventory_clear_invalidates_pending_refreshes():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("function clearAccountView")
    end = portal.index('$("requestLoginCode").addEventListener', start)
    source = portal[start:end]

    assert "wordpressSitesRequestVersion += 1;" in source
