"""Regression contracts for paginated agency usage visibility."""

import inspect
from pathlib import Path

import main


def test_agency_usage_endpoint_returns_bounded_workspace_pages_and_global_total():
    source = inspect.getsource(main.get_business_agency_usage)
    assert "limit: int = Query(default=100, ge=1, le=100)" in source
    assert "offset: int = Query(default=0, ge=0, le=1000000)" in source
    assert ".offset(offset).limit(limit)" in source
    assert "workspace_total" in source
    assert '"has_more": offset + len(workspaces) < workspace_total' in source
    assert '"agency_completed": agency_completed' in source
    assert "AgencyUsageEvent.workspace_id.in_(workspace_ids)" in source


def test_agency_usage_portal_supports_load_more_and_session_stale_response_guards():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    start = portal.index("async function loadAgencyUsage(")
    end = portal.index("async function loadAgencyDashboard(", start)
    source = portal[start:end]

    assert 'limit=100&offset=' in source
    assert "agencyUsageRequestVersion" in source
    assert "accountSessionVersion" in source
    assert "data.page?.has_more" in source
    assert 'id="loadMoreAgencyUsage"' in portal
    assert 'loadAgencyUsage(true)' in portal


def test_account_clear_invalidates_pending_agency_usage_requests():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text()
    start = portal.index("function clearAccountView()")
    end = portal.index('$("requestLoginCode")', start)
    source = portal[start:end]
    assert "agencyUsageRequestVersion += 1;" in source
    assert '$("loadMoreAgencyUsage").hidden = true;' in source
