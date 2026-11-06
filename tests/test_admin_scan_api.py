from types import SimpleNamespace
import inspect

import pytest
from fastapi import HTTPException

from admin_scan_api import _require_scan_admin, router


def test_scan_admin_requires_configured_admin_key(monkeypatch):
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    with pytest.raises(HTTPException) as exc:
        _require_scan_admin(SimpleNamespace(headers={"x-admin-key": "anything"}))
    assert exc.value.status_code == 503


def test_scan_admin_requires_header(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "a-long-test-admin-key")
    with pytest.raises(HTTPException) as exc:
        _require_scan_admin(SimpleNamespace(headers={}))
    assert exc.value.status_code == 401


def test_scan_admin_rejects_wrong_key(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "a-long-test-admin-key")
    with pytest.raises(HTTPException) as exc:
        _require_scan_admin(SimpleNamespace(headers={"x-admin-key": "wrong-key"}))
    assert exc.value.status_code == 403


def test_scan_admin_accepts_matching_key(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "a-long-test-admin-key")
    _require_scan_admin(SimpleNamespace(headers={"x-admin-key": "a-long-test-admin-key"}))


def test_scan_operations_route_is_read_only_get():
    route = next(route for route in router.routes if route.path == "/api/v1/admin/scan-operations")
    assert route.methods == {"GET"}


def test_scan_operations_exposes_bounded_failed_job_pagination():
    import inspect

    route = next(route for route in router.routes if route.path == "/api/v1/admin/scan-operations")
    params = inspect.signature(route.endpoint).parameters
    assert params["failed_limit"].default.default == 25
    assert any(getattr(item, "ge", None) == 1 for item in params["failed_limit"].default.metadata)
    assert any(getattr(item, "le", None) == 100 for item in params["failed_limit"].default.metadata)
    assert params["failed_offset"].default.default == 0
    assert any(getattr(item, "ge", None) == 0 for item in params["failed_offset"].default.metadata)


def test_scan_operations_route_has_stable_pagination_metadata_contract():
    route = next(route for route in router.routes if route.path == "/api/v1/admin/scan-operations")
    assert route.methods == {"GET"}
    # Pagination is read-only and reports whether more failed jobs remain.
    source = inspect.getsource(route.endpoint)
    assert '"failed_jobs_total"' in source
    assert '"failed_jobs_has_more"' in source
    assert ".offset(failed_offset)" in source
    assert ".limit(failed_limit)" in source


def test_admin_client_status_updates_enqueue_durable_lifecycle_sync():
    from main import admin_update_client

    source = inspect.getsource(admin_update_client)
    assert ".with_for_update()" in source
    assert "CustomerLifecycleSyncOutbox(" in source
    assert 'action="reactivate" if bool(client.is_active) else "suspend"' in source
    assert 'if "is_active" in changes and bool(client.is_active) != previous_active:' in source


def test_admin_client_non_status_updates_do_not_enqueue_lifecycle_sync():
    from main import admin_update_client

    source = inspect.getsource(admin_update_client)
    condition = 'if "is_active" in changes and bool(client.is_active) != previous_active:'
    assert condition in source
    assert source.index(condition) < source.index('await _write_admin_log(db, "client.updated"')



def test_admin_failed_scan_retry_route_is_registered_as_post():
    route = next(
        route for route in router.routes
        if route.path == "/api/v1/admin/scan-operations/jobs/{job_id}/retry"
    )
    assert route.methods == {"POST"}


def test_admin_failed_scan_retry_authenticates_before_loading_job():
    route = next(
        route for route in router.routes
        if route.path == "/api/v1/admin/scan-operations/jobs/{job_id}/retry"
    )
    source = inspect.getsource(route.endpoint)
    assert source.index("_require_scan_admin(request)") < source.index(
        "await operational_db.scalar"
    )
    assert "retry_failed_scan_job(" in source
    assert "status_code=409" in source
    assert "Cache-Control" in source


def test_admin_retry_response_does_not_expose_customer_target_or_license_key():
    route = next(
        route for route in router.routes
        if route.path == "/api/v1/admin/scan-operations/jobs/{job_id}/retry"
    )
    source = inspect.getsource(route.endpoint)
    response_block = source[source.index("return {"):]
    assert '"job_id"' in response_block
    assert '"batch_id"' in response_block
    assert '"next_attempt_at"' in response_block
    assert '"target_url"' not in response_block
    assert '"license_key"' not in response_block


def test_admin_portal_exposes_confirmed_failed_scan_retry_action():
    from pathlib import Path

    portal = Path("admin_portal.html").read_text(encoding="utf-8")
    assert "Retry failed job" in portal
    assert "Cancelled batches cannot be reopened." in portal
    assert "/api/v1/admin/scan-operations/jobs/" in portal


def test_scan_operations_reports_all_cross_database_reconciliation_outboxes():
    route = next(route for route in router.routes if route.path == "/api/v1/admin/scan-operations")
    source = inspect.getsource(route.endpoint)

    assert "CustomerLifecycleSyncOutbox" in source
    assert "BillingMirrorSyncOutbox" in source
    assert "CustomerEmailIdentitySyncOutbox" in source
    assert '"reconciliation_outboxes"' in source
    assert '"pending"' in source
    assert '"due"' in source
    assert '"completed"' in source
    assert '"oldest_pending_at"' in source


def test_admin_portal_renders_reconciliation_queue_health_without_identity_secrets():
    from pathlib import Path

    portal = Path("admin_portal.html").read_text(encoding="utf-8")

    assert 'id="syncOutboxMetrics"' in portal
    assert 'customer_lifecycle' in portal
    assert 'billing_mirror' in portal
    assert 'customer_email_identity' in portal
    assert "No customer email addresses or license secrets are displayed." in portal


def test_admin_all_scan_jobs_route_is_registered_with_pagination_and_filters():
    route = next(
        route for route in router.routes
        if route.path == "/api/v1/admin/scan-jobs"
    )
    assert route.methods == {"GET"}
    params = inspect.signature(route.endpoint).parameters
    assert params["limit"].default.default == 50
    assert any(getattr(item, "ge", None) == 1 for item in params["limit"].default.metadata)
    assert any(getattr(item, "le", None) == 200 for item in params["limit"].default.metadata)
    assert params["offset"].default.default == 0
    assert params["status_filter"].default.default == "all"
    assert params["license_id"].default.default is None


def test_admin_all_scan_jobs_endpoint_is_license_scoped_and_never_returns_license_keys():
    route = next(
        route for route in router.routes
        if route.path == "/api/v1/admin/scan-jobs"
    )
    source = inspect.getsource(route.endpoint)
    assert source.index("_require_scan_admin(request)") < source.index("operational_db.execute")
    assert "WebsiteScanJob.license_key == license_key" in source
    assert "SoftwareLicense.license_key.in_(keys)" in source
    assert '"license_id"' in source
    assert '"license_key"' not in source
    assert '"result_available"' in source
    assert ".offset(offset)" in source
    assert ".limit(limit)" in source


def test_admin_scan_job_retry_alias_preserves_existing_guarded_retry_contract():
    routes = [
        route for route in router.routes
        if route.path in {
            "/api/v1/admin/scan-jobs/{job_id}/retry",
            "/api/v1/admin/scan-operations/jobs/{job_id}/retry",
        }
    ]
    assert len(routes) == 2
    assert all(route.methods == {"POST"} for route in routes)
    assert routes[0].endpoint is routes[1].endpoint


def test_admin_portal_exposes_paginated_all_status_scan_queue():
    from pathlib import Path

    portal = Path("admin_portal.html").read_text(encoding="utf-8")
    assert 'id="scanJobStatus"' in portal
    assert 'id="scanJobs"' in portal
    assert 'id="scanJobsPageInfo"' in portal
    assert "/api/v1/admin/scan-jobs?" in portal
    assert "Retry failed scan" in portal


def test_admin_disconnect_clears_scan_and_cross_database_sync_diagnostics():
    from pathlib import Path

    portal = Path("admin_portal.html").read_text(encoding="utf-8")
    start = portal.index("function clearAdminData(")
    end = portal.index('$("createClientApiKey").addEventListener', start)
    clear_handler = portal[start:end]

    assert "failedScanJobsOffset=0" in clear_handler
    assert '$("scanQueueMetrics").replaceChildren' in clear_handler
    assert '$("syncOutboxMetrics").replaceChildren' in clear_handler
    assert '$("failedScanJobs").replaceChildren' in clear_handler
    assert '$("failedScanJobsPrev").disabled=true' in clear_handler
    assert '$("failedScanJobsNext").disabled=true' in clear_handler


from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
from fastapi import HTTPException, Request

import main


class _Scalars:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values


class _RetryDB:
    def __init__(self, items):
        self.items = items
        self.statement = None
        self.committed = False

    async def execute(self, statement):
        self.statement = statement
        return _Scalars(self.items)

    async def commit(self):
        self.committed = True


def _admin_request(path="/api/v1/admin/sync-outboxes/retry"):
    return Request({
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [(b"x-admin-key", b"test-admin-secret")],
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("testclient", 50000),
    })


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("queue", "model"),
    [
        ("customer_lifecycle", main.CustomerLifecycleSyncOutbox),
        ("customer_email_identity", main.CustomerEmailIdentitySyncOutbox),
    ],
)
async def test_admin_sync_outbox_retry_requeues_bounded_pending_rows(
    monkeypatch, queue, model
):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    now_old = datetime(2026, 11, 1, tzinfo=timezone.utc)
    items = [
        SimpleNamespace(status="pending", next_attempt_at=now_old, created_at=now_old),
        SimpleNamespace(status="pending", next_attempt_at=now_old, created_at=now_old),
    ]
    db = _RetryDB(items)
    logs = []

    async def write_log(*args, **kwargs):
        logs.append((args, kwargs))

    monkeypatch.setattr(main, "_write_admin_log", write_log)
    result = await main.admin_retry_sync_outbox(
        request=_admin_request(), queue=queue, limit=2, db=db
    )

    assert result["queue"] == queue
    assert result["status"] == "queued"
    assert result["queued"] == 2
    assert result["next_worker_cycle"] is True
    checked_at = datetime.fromisoformat(result["checked_at"])
    assert all(item.next_attempt_at == checked_at for item in items)
    assert db.committed is True
    assert db.statement._for_update_arg.skip_locked is True
    assert f"FROM {model.__tablename__}" in str(db.statement)
    assert "status" in str(db.statement)
    assert len(logs) == 1
    assert logs[0][0][1] == "sync_outbox.retry_queued"
    assert logs[0][0][2] == queue
    assert logs[0][0][4] == {"requested_limit": 2, "queued": 2}


@pytest.mark.asyncio
async def test_admin_sync_outbox_retry_reports_empty_queue(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    db = _RetryDB([])
    async def write_log(*args, **kwargs):
        return None

    monkeypatch.setattr(main, "_write_admin_log", write_log)
    result = await main.admin_retry_sync_outbox(
        request=_admin_request(), queue="customer_lifecycle", limit=200, db=db
    )

    assert result["status"] == "empty"
    assert result["queued"] == 0
    assert result["next_worker_cycle"] is False
    assert db.committed is True


@pytest.mark.asyncio
async def test_admin_sync_outbox_retry_rejects_unknown_queue(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    db = _RetryDB([])

    with pytest.raises(HTTPException) as raised:
        await main.admin_retry_sync_outbox(
            request=_admin_request(), queue="unknown_queue", limit=10, db=db
        )

    assert raised.value.status_code == 422
    assert db.committed is False


@pytest.mark.asyncio
async def test_admin_sync_outbox_retry_requires_admin_authentication(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    db = _RetryDB([])

    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/admin/sync-outboxes/retry",
        "headers": [(b"x-admin-key", b"incorrect-secret")],
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("testclient", 50000),
    })

    with pytest.raises(HTTPException) as raised:
        await main.admin_retry_sync_outbox(
            request=request, queue="customer_lifecycle", limit=10, db=db
        )

    assert raised.value.status_code == 403
    assert db.statement is None
    assert db.committed is False
