from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

import main
from audit_checks import AuditCheckResult, AuditFinding, CheckOutcome
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
async def test_comprehensive_audit_returns_pdf_and_commits_one_quota_record(monkeypatch):
    db = FakeDB()
    license_obj = SimpleNamespace(id=44, tier="starter")
    reserved_at = datetime(2026, 10, 17, tzinfo=timezone.utc)
    monkeypatch.setattr(main, "reserve_audit_slot", AsyncMock(return_value=(101, reserved_at)))
    monkeypatch.setattr(main, "release_audit_reservation", AsyncMock())
    monkeypatch.setattr(main.agent, "run_audit", AsyncMock(return_value=StoreAuditMetrics(
        domain="shop.example", mobile_score=82, speed_index_sec=3.1, is_slow=False,
        field_metrics={
            "url:LARGEST_CONTENTFUL_PAINT_MS": {
                "percentile": 2400, "normalized_value": 2400, "unit": "ms", "category": "AVERAGE",
                "distribution": [
                    {"min": 0, "max": 2500, "proportion": 0.7},
                    {"min": 2500, "max": 4000, "proportion": 0.2},
                    {"min": 4000, "max": None, "proportion": 0.1},
                ],
            },
        },
        field_data_context={
            "provider": "PageSpeed Insights loadingExperience field data (Chrome UX Report)",
            "collection_window": "Rolling 28-day field-data window; exact dates not exposed.",
            "sample_size": "Sample count is not exposed.",
            "device_scope": "Device-specific field-data scope is not exposed; Lighthouse form_factor describes the lab run only.",
            "url_overall_category": "AVERAGE",
        },
    )))
    indexing_finding = AuditFinding(
        category="technical_seo",
        title="Google indexing status not verified",
        status="not_tested",
        severity="info",
        evidence="This audit does not query Google Search Console URL Inspection.",
        explanation="A sitemap entry does not prove that Google has indexed a URL.",
        recommendation="Check the exact URL in the authorized Google Search Console property.",
        verification_steps=["Use URL Inspection for the exact canonical URL."],
        source_url="https://shop.example/",
    )
    monkeypatch.setattr(main, "run_phase_one_checks", AsyncMock(return_value=AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc="2026-10-17T00:00:00+00:00",
        findings=[indexing_finding],
        pages_checked=["https://shop.example/"],
        limitations=["Homepage-only phase one."],
        check_outcomes=[
            CheckOutcome(
                check_id="html.title_present",
                category="on_page_seo",
                page_url="https://shop.example/",
                outcome="pass",
                observed_at_utc="2026-10-17T00:00:00+00:00",
                method="bounded static HTML source inspection",
                evidence="Title element count: 1; extracted title: 'Shop'.",
                evidence_ref="html.title_present:https://shop.example/",
            )
        ],
    )))
    monkeypatch.setattr(main, "run_bounded_site_crawl", AsyncMock(return_value=([], [], ["Bounded crawl test."])))
    monkeypatch.setattr(main, "run_conversion_paid_traffic_checks", AsyncMock(return_value=([], [], ["Conversion checks test."])))
    monkeypatch.setattr(main, "run_browser_audit", AsyncMock(
        side_effect=main.BrowserAuditUnavailable("Isolated browser service is not configured")
    ))
    captured_results = []
    monkeypatch.setattr(
        main, "render_audit_pdf",
        lambda result, **kwargs: (captured_results.append(result), b"%PDF-test-content")[1],
    )

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
        assert len(captured_results) == 1
        reported = captured_results[0]
        assert any(
            finding.title == "Google indexing status not verified"
            and finding.status == "not_tested"
            for finding in reported.findings
        )
        performance_finding = next(
            finding for finding in reported.findings
            if finding.category == "performance" and finding.title == "Google PageSpeed mobile performance snapshot"
        )
        assert "provider: PageSpeed Insights loadingExperience field data" in performance_finding.evidence
        assert "collection_window: Rolling 28-day" in performance_finding.evidence
        assert "sample_size: Sample count is not exposed" in performance_finding.evidence
        assert "device_scope: Device-specific field-data scope is not exposed" in performance_finding.evidence
        assert "url:LARGEST_CONTENTFUL_PAINT_MS distribution (ms): 0–2500: 70.0%; 2500–4000: 20.0%; ≥4000: 10.0%" in performance_finding.evidence
        assert any("Homepage-only phase one." in item for item in reported.limitations)
        assert len(db.added) == 2
        assert any(getattr(item, "source_channel", None) == "comprehensive_audit" for item in db.added)
        saved_report = next(item for item in db.added if item.__class__.__name__ == "AuditReport")
        persisted_metadata = __import__("json").loads(saved_report.coverage_json)
        assert persisted_metadata["check_outcomes"][0]["check_id"] == "html.title_present"
        assert persisted_metadata["check_outcomes"][0]["outcome"] == "pass"
        assert persisted_metadata["check_outcomes"][0]["evidence_ref"] == "html.title_present:https://shop.example/"
        db.commit.assert_awaited_once()
        main.reserve_audit_slot.assert_awaited_once_with(db, license_obj.id) if hasattr(main.reserve_audit_slot, "assert_awaited_once_with") else None
    finally:
        main.app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_comprehensive_audit_rejects_private_target_before_quota(monkeypatch):
    db = FakeDB()
    license_obj = SimpleNamespace(id=44, tier="business")
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
        assert db.added == []
    finally:
        main.app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_comprehensive_audit_merges_isolated_rendered_browser_findings_and_coverage(monkeypatch):
    db = FakeDB()
    license_obj = SimpleNamespace(id=45, tier="pro")
    monkeypatch.setattr(main, "reserve_audit_slot", AsyncMock(return_value=(102, datetime(2026, 10, 17, tzinfo=timezone.utc))))
    monkeypatch.setattr(main, "release_audit_reservation", AsyncMock())
    monkeypatch.setattr(main.agent, "run_audit", AsyncMock(return_value=StoreAuditMetrics(
        domain="shop.example", mobile_score=82, speed_index_sec=3.1, is_slow=False
    )))
    monkeypatch.setattr(main, "run_phase_one_checks", AsyncMock(return_value=AuditCheckResult(
        target_url="https://shop.example/", checked_at_utc="2026-10-17T00:00:00+00:00",
        findings=[], pages_checked=["https://shop.example/"], limitations=["Static checks completed."],
        check_outcomes=[],
    )))
    monkeypatch.setattr(main, "run_bounded_site_crawl", AsyncMock(return_value=([], [], [])))
    monkeypatch.setattr(main, "run_conversion_paid_traffic_checks", AsyncMock(return_value=([], [], [])))
    rendered_finding = AuditFinding(
        category="mobile_ux", title="Rendered mobile viewport inspection",
        status="verified", severity="info",
        evidence="Rendered DOM inspected at 320, 390 and 768 CSS px.",
        explanation="A bounded browser run inspected rendered layout at configured viewports.",
        recommendation="Review any viewport-specific findings before changing layout.",
        verification_steps=["Repeat in a real device/browser matrix for final acceptance."],
        source_url="https://shop.example/",
    )
    rendered_outcome = CheckOutcome(
        check_id="browser.rendered_viewport",
        category="mobile_ux", page_url="https://shop.example/",
        outcome="pass", observed_at_utc="2026-10-17T00:00:00+00:00",
        method="isolated Playwright browser audit",
        evidence="Rendered page completed at 320, 390 and 768 CSS px.",
        evidence_ref="browser.rendered_viewport",
    )
    monkeypatch.setattr(main, "run_browser_audit", AsyncMock(return_value={
        "request_id": "browser-test-1",
        "findings": [rendered_finding.dict()],
        "check_outcomes": [rendered_outcome.dict()],
        "summary": {
            "viewports": [320, 390, 768],
            "rendered_pages": ["https://shop.example/"],
            "navigation_error": None,
        },
    }))
    captured = []
    monkeypatch.setattr(main, "render_audit_pdf", lambda result, **kwargs: (captured.append(result), b"%PDF-browser-test")[1])
    main.app.dependency_overrides[main.verify_license_or_api_key] = lambda: license_obj
    main.app.dependency_overrides[main.get_async_db] = lambda: db
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://testserver") as client:
            response = await client.post("/api/v1/comprehensive-audit", params={"domain": "shop.example"})
        assert response.status_code == 200
        assert main.run_browser_audit.await_count == 1
        reported = captured[0]
        assert any(item.title == "Rendered mobile viewport inspection" for item in reported.findings)
        assert any(item.check_id == "browser.rendered_viewport" and item.outcome == "pass" for item in reported.check_outcomes)
        saved_report = next(item for item in db.added if item.__class__.__name__ == "AuditReport")
        metadata = __import__("json").loads(saved_report.coverage_json)
        assert metadata["audit_run_context"]["modules"]["browser_rendered"] == "completed"
        assert any("Rendered-browser diagnostics completed" in item for item in reported.limitations)
    finally:
        main.app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_comprehensive_audit_records_browser_service_unavailable_without_failing_audit(monkeypatch):
    db = FakeDB()
    license_obj = SimpleNamespace(id=46, tier="starter")
    monkeypatch.setattr(main, "reserve_audit_slot", AsyncMock(return_value=(103, datetime(2026, 10, 17, tzinfo=timezone.utc))))
    monkeypatch.setattr(main, "release_audit_reservation", AsyncMock())
    monkeypatch.setattr(main.agent, "run_audit", AsyncMock(return_value=StoreAuditMetrics(
        domain="shop.example", mobile_score=82, speed_index_sec=3.1, is_slow=False
    )))
    monkeypatch.setattr(main, "run_phase_one_checks", AsyncMock(return_value=AuditCheckResult(
        target_url="https://shop.example/", checked_at_utc="2026-10-17T00:00:00+00:00",
        findings=[], pages_checked=["https://shop.example/"], limitations=[],
        check_outcomes=[],
    )))
    monkeypatch.setattr(main, "run_bounded_site_crawl", AsyncMock(return_value=([], [], [])))
    monkeypatch.setattr(main, "run_conversion_paid_traffic_checks", AsyncMock(return_value=([], [], [])))
    monkeypatch.setattr(main, "run_browser_audit", AsyncMock(
        side_effect=main.BrowserAuditUnavailable("Isolated browser service is not configured")
    ))
    captured = []
    monkeypatch.setattr(main, "render_audit_pdf", lambda result, **kwargs: (captured.append(result), b"%PDF-browser-unavailable")[1])
    main.app.dependency_overrides[main.verify_license_or_api_key] = lambda: license_obj
    main.app.dependency_overrides[main.get_async_db] = lambda: db
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://testserver") as client:
            response = await client.post("/api/v1/comprehensive-audit", params={"domain": "shop.example"})
        assert response.status_code == 200
        saved_report = next(item for item in db.added if item.__class__.__name__ == "AuditReport")
        metadata = __import__("json").loads(saved_report.coverage_json)
        assert metadata["run_context"]["modules"]["browser_rendered"] == "unavailable"
        assert any("Rendered-browser diagnostics were not assessed" in item for item in captured[0].limitations)
        assert any(item.check_id.startswith("browser.") and item.outcome == "not_assessed" for item in captured[0].check_outcomes)
    finally:
        main.app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_comprehensive_audit_does_not_mark_empty_browser_response_as_completed(monkeypatch):
    db = FakeDB()
    license_obj = SimpleNamespace(id=47, tier="starter")
    monkeypatch.setattr(main, "reserve_audit_slot", AsyncMock(return_value=(104, datetime(2026, 10, 17, tzinfo=timezone.utc))))
    monkeypatch.setattr(main, "release_audit_reservation", AsyncMock())
    monkeypatch.setattr(main.agent, "run_audit", AsyncMock(return_value=StoreAuditMetrics(
        domain="shop.example", mobile_score=82, speed_index_sec=3.1, is_slow=False
    )))
    monkeypatch.setattr(main, "run_phase_one_checks", AsyncMock(return_value=AuditCheckResult(
        target_url="https://shop.example/", checked_at_utc="2026-10-17T00:00:00+00:00",
        findings=[], pages_checked=["https://shop.example/"], limitations=[],
        check_outcomes=[],
    )))
    monkeypatch.setattr(main, "run_bounded_site_crawl", AsyncMock(return_value=([], [], [])))
    monkeypatch.setattr(main, "run_conversion_paid_traffic_checks", AsyncMock(return_value=([], [], [])))
    monkeypatch.setattr(main, "run_browser_audit", AsyncMock(return_value={
        "request_id": "browser-test-empty", "findings": [], "check_outcomes": [],
        "summary": {"viewports": [320, 390, 768], "rendered_pages": [], "navigation_error": None},
    }))
    captured = []
    monkeypatch.setattr(main, "render_audit_pdf", lambda result, **kwargs: (captured.append(result), b"%PDF-browser-empty")[1])
    main.app.dependency_overrides[main.verify_license_or_api_key] = lambda: license_obj
    main.app.dependency_overrides[main.get_async_db] = lambda: db
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://testserver") as client:
            response = await client.post("/api/v1/comprehensive-audit", params={"domain": "shop.example"})
        assert response.status_code == 200
        saved_report = next(item for item in db.added if item.__class__.__name__ == "AuditReport")
        metadata = __import__("json").loads(saved_report.coverage_json)
        assert metadata["run_context"]["modules"]["browser_rendered"] == "partial"
        assert any("could not complete page navigation" in item for item in captured[0].limitations)
    finally:
        main.app.dependency_overrides.clear()
