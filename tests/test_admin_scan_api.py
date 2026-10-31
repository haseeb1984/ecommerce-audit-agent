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
