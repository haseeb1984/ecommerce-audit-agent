"""End-to-end coverage for real audit-result PDF rendering.

Only network-dependent audit stages and persistence are stubbed. The PDF renderer
is deliberately real so this test exercises the actual response artifact.
"""
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

import main
from audit_checks import AuditCheckResult, AuditFinding
from ecommerce_agent import StoreAuditMetrics


class FakeDB:
    def __init__(self):
        self.added = []
        self.execute = AsyncMock()
        self.commit = AsyncMock()
        self.rollback = AsyncMock()
        self._next_id = 500

    def add(self, item):
        self.added.append(item)

    async def flush(self):
        for item in self.added:
            if hasattr(item, "id") and getattr(item, "id", None) is None:
                item.id = self._next_id
                self._next_id += 1


@pytest.mark.asyncio
async def test_comprehensive_audit_returns_real_rendered_pdf_with_findings(monkeypatch):
    db = FakeDB()
    license_obj = SimpleNamespace(id=44)
    reserved_at = datetime(2026, 10, 17, tzinfo=timezone.utc)
    monkeypatch.setattr(main, "reserve_audit_slot", AsyncMock(return_value=(101, reserved_at)))
    monkeypatch.setattr(main, "release_audit_reservation", AsyncMock())
    monkeypatch.setattr(
        main.agent,
        "run_audit",
        AsyncMock(return_value=StoreAuditMetrics(
            domain="shop.example", mobile_score=82, speed_index_sec=3.1, is_slow=False
        )),
    )
    monkeypatch.setattr(
        main,
        "run_phase_one_checks",
        AsyncMock(return_value=AuditCheckResult(
            target_url="https://shop.example/",
            checked_at_utc="2026-10-17T00:00:00+00:00",
            findings=[
                AuditFinding(
                    category="technical_seo",
                    title="Google indexing status not verified",
                    status="not_tested",
                    severity="info",
                    evidence="This audit does not query Google Search Console URL Inspection.",
                    explanation="A sitemap entry does not prove that Google has indexed a URL.",
                    recommendation="Check the exact URL in the authorized Google Search Console property.",
                    verification_steps=["Use URL Inspection for the exact canonical URL."],
                    source_url="https://shop.example/",
                ),
                AuditFinding(
                    category="accessibility",
                    title="Product form control may lack an accessible name",
                    status="manual_review_required",
                    severity="medium",
                    evidence="A form control has no detectable associated label in sampled HTML.",
                    explanation="Some assistive-technology users may not know what the control does.",
                    recommendation="Provide a programmatic label and verify it in the browser.",
                    verification_steps=["Inspect the control's accessible name in browser devtools."],
                    source_url="https://shop.example/products/example",
                ),
            ],
            pages_checked=["https://shop.example/", "https://shop.example/products/example"],
            limitations=[
                "Homepage checks and bounded crawl use static HTML; JavaScript-rendered behavior is not fully tested.",
                "Google indexing is not verified because Search Console access is not connected.",
            ],
        )),
    )
    monkeypatch.setattr(
        main, "run_bounded_site_crawl",
        AsyncMock(return_value=([], [], ["Crawl was bounded to the configured page budget."])),
    )
    monkeypatch.setattr(
        main, "run_conversion_paid_traffic_checks",
        AsyncMock(return_value=([], [], ["Ad spend and conversion outcomes were not measured."])),
    )

    # Do not mock main.render_audit_pdf: the purpose is to exercise real rendering.
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
        assert response.content.startswith(b"%PDF-")
        assert b"%%EOF" in response.content[-2048:]
        assert len(response.content) > 1000
        assert len(db.added) == 2
        assert any(item.source_channel == "comprehensive_audit" for item in db.added)
        assert any(item.__class__.__name__ == "AuditReport" for item in db.added)
        db.commit.assert_awaited_once()
    finally:
        main.app.dependency_overrides.clear()
