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
        self.scalar_statements = []
        self.committed = False

    async def scalar(self, statement):
        self.scalar_statements.append(statement)
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
    agency = SimpleNamespace(id="agency-1", owner_license_key="business-license", display_name="Agency One")
    workspace = SimpleNamespace(id="workspace-1", agency_id="agency-1", status="active", display_name="Client Workspace")
    owner_license = SimpleNamespace(
        license_key="business-license", is_active=True, expires_at=None,
        tier="business",
    )
    operational = AgencyRouteSession(site, agency, workspace, site)
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
    assert operational.scalar_statements[0]._for_update_arg is None
    assert all(statement._for_update_arg is not None for statement in operational.scalar_statements[1:])
    lock_tables = [str(statement).split("FROM ", 1)[1].split(" ", 1)[0] for statement in operational.scalar_statements[1:]]
    assert lock_tables == ["agency_accounts", "agency_client_workspaces", "agency_client_websites"]


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
            operational_db=AgencyRouteSession(site, agency, workspace, site),
        )
    assert error.value.status_code == 422

class WebsiteInventoryResult:
    def __init__(self, value=None, rows=None):
        self.value = value
        self.rows = list(rows or [])

    def scalar_one(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.rows


class WebsiteInventorySession:
    def __init__(self, *, scalar_rows=None, execute_results=None):
        self.scalar_rows = list(scalar_rows or [])
        self.execute_results = list(execute_results or [])
        self.scalar_statements = []
        self.execute_statements = []
        self.committed = False
        self.refreshed = []

    async def scalar(self, statement):
        self.scalar_statements.append(statement)
        return self.scalar_rows.pop(0)

    async def execute(self, statement):
        self.execute_statements.append(statement)
        return self.execute_results.pop(0)

    async def commit(self):
        self.committed = True

    async def refresh(self, row):
        self.refreshed.append(row)


@pytest.mark.asyncio
async def test_customer_website_inventory_is_license_scoped_and_private():
    from scan_api import list_customer_websites

    license_obj = SimpleNamespace(license_key="license-customer-a")
    website = SimpleNamespace(
        id="website-a", url="https://shop-a.example/", host="shop-a.example",
        label="Store A", status="active", created_at=None, updated_at=None,
    )
    db = WebsiteInventorySession(execute_results=[
        WebsiteInventoryResult(value=1),
        WebsiteInventoryResult(rows=[website]),
    ])
    response = Response()

    result = await list_customer_websites(
        response, limit=100, offset=0, license_obj=license_obj, db=db,
    )

    assert result["page"] == {"limit": 100, "offset": 0, "total": 1, "has_more": False}
    assert result["items"][0]["id"] == "website-a"
    assert len(db.execute_statements) == 2
    for statement in db.execute_statements:
        assert "license_key" in str(statement).lower()
        assert "license-customer-a" in statement.compile().params.values()
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"


@pytest.mark.asyncio
async def test_customer_website_label_update_requires_owning_license():
    from scan_api import CustomerWebsiteUpdate, update_customer_website

    license_obj = SimpleNamespace(license_key="license-customer-a")
    website = SimpleNamespace(
        id="website-a", license_key="license-customer-a",
        url="https://shop-a.example/", host="shop-a.example",
        label=None, status="active", updated_at=None,
    )
    db = WebsiteInventorySession(scalar_rows=[website])
    response = Response()

    result = await update_customer_website(
        "website-a", CustomerWebsiteUpdate(label="  Main store  "), response,
        license_obj=license_obj, db=db,
    )

    statement = db.scalar_statements[0]
    assert "license_key" in str(statement).lower()
    assert "license-customer-a" in statement.compile().params.values()
    assert result["label"] == "Main store"
    assert db.committed and db.refreshed == [website]
    assert response.headers["cache-control"] == "no-store, private"


@pytest.mark.asyncio
async def test_customer_website_archive_is_license_scoped_and_preserves_record():
    from scan_api import archive_customer_website

    license_obj = SimpleNamespace(license_key="license-customer-a")
    website = SimpleNamespace(
        id="website-a", license_key="license-customer-a", status="active",
    )
    db = WebsiteInventorySession(scalar_rows=[website])
    response = Response()

    result = await archive_customer_website(
        "website-a", response, license_obj=license_obj, db=db,
    )

    statement = db.scalar_statements[0]
    assert "license_key" in str(statement).lower()
    assert "license-customer-a" in statement.compile().params.values()
    assert website.status == "archived"
    assert result["status"] == "archived"
    assert db.committed
    assert response.headers["cache-control"] == "no-store, private"


class PrivateScanApiResult:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    def scalars(self):
        return self

    def all(self):
        return self.rows


class PrivateScanApiSession:
    def __init__(self, *, scalar_rows=None, execute_rows=None):
        self.scalar_rows = list(scalar_rows or [])
        self.execute_rows = list(execute_rows or [])

    async def scalar(self, _statement):
        return self.scalar_rows.pop(0)

    async def execute(self, _statement):
        return self.execute_rows.pop(0)


@pytest.mark.asyncio
@pytest.mark.parametrize("handler_name", [
    "list_scan_batches",
    "get_scan_batch",
    "list_scan_history",
    "get_scan_job_result",
])
async def test_customer_scan_read_endpoints_disable_shared_caching(handler_name):
    import scan_api

    license_obj = SimpleNamespace(license_key="private-license")
    response = Response()
    if handler_name == "list_scan_batches":
        db = PrivateScanApiSession(execute_rows=[PrivateScanApiResult()])
        await scan_api.list_scan_batches(
            response, limit=50, offset=0, license_obj=license_obj, db=db,
        )
    elif handler_name == "get_scan_batch":
        batch = SimpleNamespace(
            id="batch-private", request_id="request-private", batch_number=1,
            package_tier="starter", status="queued", total_urls=0,
            queued_count=0, processing_count=0, completed_count=0,
            failed_count=0, cancelled_count=0,
        )
        db = PrivateScanApiSession(
            scalar_rows=[batch], execute_rows=[PrivateScanApiResult()],
        )
        await scan_api.get_scan_batch(
            response, "batch-private", license_obj=license_obj, db=db,
        )
    elif handler_name == "list_scan_history":
        db = PrivateScanApiSession(execute_rows=[PrivateScanApiResult()])
        await scan_api.list_scan_history(
            response, limit=50, offset=0, license_obj=license_obj, db=db,
        )
    else:
        job = SimpleNamespace(id="job-private")
        result = SimpleNamespace(
            id="result-private", job_id="job-private", website_id="website-private",
            target_url="https://shop.example/", status="completed", overall_score=90,
            finding_count=0, findings_json="[]", check_outcomes_json="[]",
            coverage_json="{}", summary_json="{}", created_at=None,
        )
        db = PrivateScanApiSession(scalar_rows=[job, result])
        await scan_api.get_scan_job_result(
            response, "job-private", license_obj=license_obj, db=db,
        )

    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"


@pytest.mark.asyncio
async def test_customer_workspace_scan_serializes_agency_workspace_and_site_lifecycle(monkeypatch):
    import scan_api
    from scan_api import BulkScanSubmission, submit_scan_batches

    agency = SimpleNamespace(id="agency-1", owner_license_key="business-license", status="active")
    workspace = SimpleNamespace(id="workspace-1", agency_id="agency-1", status="active")
    client_site = SimpleNamespace(site_host="shop.example", status="active")
    db = AgencyRouteSession(agency, workspace, client_site)
    license_obj = SimpleNamespace(license_key="business-license", tier="business")
    queued = {}

    async def fake_enqueue(_db, **kwargs):
        queued.update(kwargs)
        return {"batch_ids": ["batch-1"], "total_urls": 1}

    monkeypatch.setattr(scan_api, "enqueue_scan_request", fake_enqueue)
    monkeypatch.setattr(scan_api, "plan_features", lambda _tier: {
        "agency_management": True, "standard_audits": True,
    })
    response = Response()
    result = await submit_scan_batches(
        BulkScanSubmission(
            urls=["https://shop.example/products/one"],
            request_id="customer-workspace-lock-123",
            workspace_id="workspace-1",
        ),
        response,
        license_obj=license_obj,
        db=db,
    )

    assert result["status"] == "accepted"
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
    assert queued["workspace_id"] == "workspace-1"
    assert queued["license_key"] == "business-license"
    assert all(statement._for_update_arg is not None for statement in db.scalar_statements)
    lock_tables = [
        str(statement).split("FROM ", 1)[1].split(" ", 1)[0]
        for statement in db.scalar_statements
    ]
    assert lock_tables == [
        "agency_accounts", "agency_client_workspaces", "agency_client_websites",
    ]


@pytest.mark.asyncio
async def test_customer_website_detail_paginates_only_owning_license_scan_history():
    from scan_api import get_customer_website

    license_obj = SimpleNamespace(license_key="license-customer-a")
    website = SimpleNamespace(
        id="website-a", url="https://shop-a.example/", host="shop-a.example",
        label="Main store", status="active", created_at=None, updated_at=None,
    )
    jobs = [SimpleNamespace(
        id="job-a", batch_id="batch-a", status="completed", attempt_count=1,
        last_error_code=None, created_at=None, completed_at=None,
        result_reference="result-a",
    )]
    db = WebsiteInventorySession(
        scalar_rows=[website],
        execute_results=[WebsiteInventoryResult(value=3), WebsiteInventoryResult(rows=jobs)],
    )
    response = Response()

    result = await get_customer_website(
        "website-a", response, limit=1, offset=1,
        license_obj=license_obj, db=db,
    )

    assert result["scan_history"][0]["job_id"] == "job-a"
    assert result["history_page"] == {"limit": 1, "offset": 1, "total": 3, "has_more": True}
    assert len(db.execute_statements) == 2
    for statement in db.execute_statements:
        sql = str(statement).lower()
        assert "website_scan_jobs.license_key" in sql
        assert "license-customer-a" in statement.compile().params.values()
    assert "offset" in str(db.execute_statements[1]).lower()
    assert "limit" in str(db.execute_statements[1]).lower()
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"


def test_customer_scan_mutation_endpoints_disable_shared_caching():
    import inspect
    import scan_api

    for handler in (
        scan_api.submit_scan_batches,
        scan_api.cancel_customer_scan_batch,
        scan_api.retry_customer_scan_job,
    ):
        source = inspect.getsource(handler)
        assert 'response.headers["Cache-Control"] = "no-store, private"' in source
        assert 'response.headers["Pragma"] = "no-cache"' in source


def test_customer_scan_pagination_offsets_are_bounded():
    import inspect
    from scan_api import (
        get_customer_website,
        list_customer_websites,
        list_scan_batches,
        list_scan_history,
    )

    for handler in (
        list_scan_batches,
        list_scan_history,
        list_customer_websites,
        get_customer_website,
    ):
        offset = inspect.signature(handler).parameters["offset"].default
        metadata = getattr(offset, "metadata", ())
        bounds = {
            key: value
            for item in metadata
            for key, value in (
                ("ge", getattr(item, "ge", None)),
                ("le", getattr(item, "le", None)),
            )
            if value is not None
        }
        assert bounds.get("ge") == 0
        assert bounds.get("le") == 1_000_000
