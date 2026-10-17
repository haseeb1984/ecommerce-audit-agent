from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

import main
from audit_checks import AuditCheckResult
from ecommerce_agent import StoreAuditMetrics


class FakeDB:
    def __init__(self):
        self.added = []
        self.execute = AsyncMock()
        self.commit = AsyncMock()
        self.rollback = AsyncMock()

    def add(self, item):
        self.added.append(item)


@pytest.mark.asyncio
async def test_comprehensive_audit_returns_pdf_and_commits_one_quota_record(monkeypatch):
    db = FakeDB()
    license_obj = SimpleNamespace(id=44)
    reserved_at = datetime(2026, 10, 17, tzinfo=timezone.utc)
    monkeypatch.setattr(main, "reserve_audit_slot", AsyncMock(return_value=(101, reserved_at)))
    monkeypatch.setattr(main, "release_audit_reservation", AsyncMock())
    monkeypatch.setattr(main.agent, "run_audit", AsyncMock(return_value=StoreAuditMetrics(
        domain="shop.example", mobile_score=82, speed_index_sec=3.1, is_slow=False
    )))
    monkeypatch.setattr(main, "run_phase_one_checks", AsyncMock(return_value=AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc="2026-10-17T00:00:00+00:00",
        findings=[],
        pages_checked=["https://shop.example/"],
        limitations=["Homepage-only phase one."],
    )))
    monkeypatch.setattr(main, "render_audit_pdf", lambda result: b"%PDF-test-content")

    main.app.dependency_overrides[main.verify_license_or_api_key] = lambda: license_obj
    main.app.dependency_overrides[main.get_async_db] = lambda: db
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app),
            base_url="http://testserver",
        ) as client:
            response = await client.post(
                "/api/v1/comprehensive-audit",
                params={"domain": "shop.example"},
            )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/pdf")
        assert "ecommerce-audit-shop.example.pdf" in response.headers["content-disposition"]
        assert response.content == b"%PDF-test-content"
        assert len(db.added) == 1
        assert db.added[0].source_channel == "comprehensive_audit"
        db.commit.assert_awaited_once()
        main.reserve_audit_slot.assert_awaited_once_with(db, license_obj.id) if hasattr(main.reserve_audit_slot, "assert_awaited_once_with") else None
    finally:
        main.app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_comprehensive_audit_rejects_private_target_before_quota(monkeypatch):
    db = FakeDB()
    license_obj = SimpleNamespace(id=44)
    reserve = AsyncMock()
    monkeypatch.setattr(main, "reserve_audit_slot", reserve)
    main.app.dependency_overrides[main.verify_license_or_api_key] = lambda: license_obj
    main.app.dependency_overrides[main.get_async_db] = lambda: db
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app),
            base_url="http://testserver",
        ) as client:
            response = await client.post(
                "/api/v1/comprehensive-audit",
                params={"domain": "http://127.0.0.1/admin"},
            )
        assert response.status_code == 422
        reserve.assert_not_awaited()
        db.added == []
    finally:
        main.app.dependency_overrides.clear()
