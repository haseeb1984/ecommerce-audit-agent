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
    assert params["failed_limit"].default.ge == 1
    assert params["failed_limit"].default.le == 100
    assert params["failed_offset"].default.default == 0
    assert params["failed_offset"].default.ge == 0


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
