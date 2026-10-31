from hostinger_models import AgencyAccount, AgencyClientWorkspace, AgencyClientWebsite, AgencyTeamMember, AgencyWorkspaceAccess, AgencyUsageEvent


def test_business_agency_tables_are_registered():
    expected = {"agency_accounts", "agency_client_workspaces", "agency_client_websites", "agency_team_members", "agency_workspace_access", "agency_usage_events"}
    actual = {AgencyAccount.__tablename__, AgencyClientWorkspace.__tablename__, AgencyClientWebsite.__tablename__, AgencyTeamMember.__tablename__, AgencyWorkspaceAccess.__tablename__, AgencyUsageEvent.__tablename__}
    assert actual == expected


def test_bulk_scan_payload_accepts_optional_agency_workspace():
    from scan_api import BulkScanSubmission

    personal = BulkScanSubmission(urls=["https://shop.example/"], request_id="request-12345678")
    agency = BulkScanSubmission(
        urls=["https://shop.example/"],
        request_id="request-abcdefgh",
        workspace_id="agency-client-workspace",
    )
    assert personal.workspace_id is None
    assert agency.workspace_id == "agency-client-workspace"


def test_agency_wordpress_audit_payload_requires_request_identity_and_urls():
    import pytest
    from pydantic import ValidationError
    from scan_api import AgencyWordPressAuditRequest

    payload = AgencyWordPressAuditRequest(
        urls=["https://shop.example/"],
        request_id="wp-agency-audit-123456",
    )
    assert payload.urls == ["https://shop.example/"]
    assert payload.request_id == "wp-agency-audit-123456"
    with pytest.raises(ValidationError):
        AgencyWordPressAuditRequest(urls=[], request_id="short")


from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request


class AgencyRouteSession:
    def __init__(self, *rows):
        self.rows = list(rows)
        self.committed = False

    async def scalar(self, _statement):
        return self.rows.pop(0)

    async def commit(self):
        self.committed = True


def _agency_request(headers=None):
    raw_headers = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    return Request({"type": "http", "method": "POST", "path": "/", "headers": raw_headers})


def test_agency_wordpress_audit_rejects_invalid_and_cross_site_urls():
    import scan_api

    with pytest.raises(ValueError):
        scan_api._normalize_bulk_target("https://user:password@shop.example/")
    with pytest.raises(ValueError):
        scan_api._normalize_bulk_target("https://shop.example/?session=private")
    with pytest.raises(ValueError, match="same ecommerce website"):
        scan_api._validate_single_site_submission([
            "https://shop.example/", "https://other.example/products",
        ])


@pytest.mark.asyncio
async def test_agency_wordpress_audit_requires_site_credential():
    from scan_api import AgencyWordPressAuditRequest, queue_agency_wordpress_site_audit

    payload = AgencyWordPressAuditRequest(
        urls=["https://shop.example/"],
        request_id="wp-agency-audit-auth-123",
    )
    with pytest.raises(HTTPException) as error:
        await queue_agency_wordpress_site_audit(
            payload, _agency_request(), Response(),
            licensing_db=AgencyRouteSession(),
            operational_db=AgencyRouteSession(),
        )
    assert error.value.status_code == 401


@pytest.mark.asyncio
async def test_agency_wordpress_audit_rejects_revoked_site_credential():
    from scan_api import AgencyWordPressAuditRequest, queue_agency_wordpress_site_audit

    payload = AgencyWordPressAuditRequest(
        urls=["https://shop.example/"],
        request_id="wp-agency-audit-revoked-123",
    )
    with pytest.raises(HTTPException) as error:
        await queue_agency_wordpress_site_audit(
            payload, _agency_request({"x-agency-site-token": "a" * 48}), Response(),
            licensing_db=AgencyRouteSession(),
            operational_db=AgencyRouteSession(None),
        )
    assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_agency_wordpress_audit_queues_only_its_connected_workspace(monkeypatch):
    import scan_api
    from scan_api import AgencyWordPressAuditRequest, queue_agency_wordpress_site_audit

    site = SimpleNamespace(
        id="agency-site-1", site_token_hash="unused", status="active",
        agency_id="agency-1", workspace_id="workspace-1",
        site_host="shop.example", admin_email="store-admin@shop.example",
        last_seen_at=None,
    )
    agency = SimpleNamespace(id="agency-1", owner_license_key="business-license")
    workspace = SimpleNamespace(id="workspace-1", agency_id="agency-1", status="active")
    owner_license = SimpleNamespace(
        license_key="business-license", is_active=True, expires_at=None,
        tier="business",
    )
    operational = AgencyRouteSession(site, agency, workspace)
    licensing = AgencyRouteSession(owner_license)
    queued = {}

    async def fake_enqueue(db, **kwargs):
        queued.update(kwargs)
        return {"batch_ids": ["batch-1"], "total_urls": 1}

    monkeypatch.setattr(scan_api, "enqueue_scan_request", fake_enqueue)
    monkeypatch.setattr(scan_api, "plan_features", lambda _tier: {
        "agency_management": True, "standard_audits": True,
    })
    payload = AgencyWordPressAuditRequest(
        urls=["https://shop.example/products/one"],
        request_id="wp-agency-audit-valid-123",
    )
    response = Response()
    result = await queue_agency_wordpress_site_audit(
        payload, _agency_request({"x-agency-site-token": "b" * 48}), response,
        licensing_db=licensing, operational_db=operational,
    )

    assert result["status"] == "accepted"
    assert queued["license_key"] == "business-license"
    assert queued["workspace_id"] == "workspace-1"
    assert queued["urls"] == ["https://shop.example/products/one"]
    assert operational.committed
    assert site.last_seen_at is not None


@pytest.mark.asyncio
async def test_agency_wordpress_audit_rejects_another_clients_domain(monkeypatch):
    import scan_api
    from scan_api import AgencyWordPressAuditRequest, queue_agency_wordpress_site_audit

    site = SimpleNamespace(
        id="agency-site-2", status="active", agency_id="agency-1",
        workspace_id="workspace-1", site_host="shop.example",
        admin_email="store-admin@shop.example", last_seen_at=None,
    )
    agency = SimpleNamespace(id="agency-1", owner_license_key="business-license")
    workspace = SimpleNamespace(id="workspace-1", agency_id="agency-1", status="active")
    owner_license = SimpleNamespace(
        license_key="business-license", is_active=True, expires_at=None,
        tier="business",
    )
    async def should_not_enqueue(*_args, **_kwargs):
        raise AssertionError("Cross-client URL must never be queued.")

    monkeypatch.setattr(scan_api, "enqueue_scan_request", should_not_enqueue)
    monkeypatch.setattr(scan_api, "plan_features", lambda _tier: {
        "agency_management": True, "standard_audits": True,
    })
    payload = AgencyWordPressAuditRequest(
        urls=["https://another-shop.example/"],
        request_id="wp-agency-audit-domain-123",
    )
    with pytest.raises(HTTPException) as error:
        await queue_agency_wordpress_site_audit(
            payload, _agency_request({"x-agency-site-token": "c" * 48}), Response(),
            licensing_db=AgencyRouteSession(owner_license),
            operational_db=AgencyRouteSession(site, agency, workspace),
        )
    assert error.value.status_code == 422
