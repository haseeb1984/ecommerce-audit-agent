from types import SimpleNamespace

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
