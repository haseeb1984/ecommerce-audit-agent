"""Regression contracts for bounded agency client inventory pagination."""

import inspect
from pathlib import Path

import main


def test_agency_client_inventory_endpoint_has_deterministic_bounded_pagination():
    source = inspect.getsource(main.list_business_agency_clients)
    assert "limit: int = Query(default=100, ge=1, le=100)" in source
    assert "offset: int = Query(default=0, ge=0, le=1000000)" in source
    assert "func.count(AgencyClientWorkspace.id)" in source
    assert ".offset(offset).limit(limit)" in source
    assert "AgencyClientWorkspace.id.desc()" in source
    assert '"has_more": offset + len(clients) < total' in source
    assert ".limit(500)" not in source


def test_agency_client_portal_appends_pages_without_dropping_existing_workspace_options():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    start = portal.index("async function loadAgencyDashboard(")
    end = portal.index("async function loadAgencyClientAuditResults(", start)
    source = portal[start:end]
    assert 'limit=100&offset=' in source
    assert "agencyClientRequestVersion" in source
    assert "accountSessionVersion" in source
    assert "if (!append) {" in source
    assert "workspaceSelect.replaceChildren();" in source
    assert "if (!append) teamWorkspaceSelect.replaceChildren();" in source
    assert "if (!append) container.replaceChildren();" in source
    assert "data.page?.has_more" in source
    assert 'id="loadMoreAgencyClients"' in portal
    assert "loadAgencyDashboard(true)" in portal


def test_customer_account_clear_invalidates_agency_client_page_requests():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    start = portal.index("function clearAccountView()")
    end = portal.index('$("requestLoginCode")', start)
    source = portal[start:end]
    assert "agencyClientRequestVersion += 1;" in source
    assert '$("loadMoreAgencyClients").hidden = true;' in source
