from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

import scan_worker
from audit_checks import AuditCheckResult


def _base_result():
    return AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc=datetime.now(timezone.utc).isoformat(),
        pages_checked=["https://shop.example/"],
    )


def _browser_outcome():
    return {
        "check_id": "mobile_ux.rendered_viewport_matrix",
        "category": "mobile_ux",
        "page_url": "https://shop.example/",
        "outcome": "pass",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "method": "Playwright test",
        "evidence": "Seven viewport widths checked; no overflow.",
        "evidence_ref": "browser.viewport_matrix",
    }


def _install_static_audit_mocks(monkeypatch):
    from ecommerce_agent import StoreAuditMetrics

    monkeypatch.setattr(scan_worker, "run_phase_one_checks", AsyncMock(return_value=_base_result()))
    monkeypatch.setattr(scan_worker, "run_bounded_site_crawl", AsyncMock(return_value=([], [], [])))
    monkeypatch.setattr(scan_worker, "run_conversion_paid_traffic_checks", AsyncMock(return_value=([], [], [])))

    class FakeAgent:
        async def run_audit(self, target_url):
            return StoreAuditMetrics(
                domain="shop.example", mobile_score=80, speed_index_sec=2.5, is_slow=False
            )

    monkeypatch.setattr(scan_worker, "UniversalEcommerceAgent", FakeAgent)


@pytest.mark.asyncio
async def test_scan_worker_persists_successful_browser_outcomes_in_existing_result(monkeypatch):
    _install_static_audit_mocks(monkeypatch)
    monkeypatch.setattr(
        scan_worker,
        "run_browser_audit",
        AsyncMock(return_value={
            "findings": [],
            "check_outcomes": [_browser_outcome()],
            "summary": {"viewports": [320, 360, 375, 390, 414, 768, 1365]},
        }),
    )

    result = await scan_worker._execute_audit("https://shop.example/")
    outcomes = {item["check_id"]: item for item in result["check_outcomes"]}

    assert result["summary"]["modules"]["browser_rendered"] == "completed"
    assert outcomes["mobile_ux.rendered_viewport_matrix"]["outcome"] == "pass"
    assert "crawl.javascript_rendered_dom" not in outcomes
    assert result["summary"]["overall_score"] if "overall_score" in result["summary"] else True


@pytest.mark.asyncio
async def test_scan_worker_marks_browser_checks_not_assessed_when_service_unavailable(monkeypatch):
    _install_static_audit_mocks(monkeypatch)

    async def unavailable(_target_url):
        raise scan_worker.BrowserAuditUnavailable("Isolated browser service is not configured")

    monkeypatch.setattr(scan_worker, "run_browser_audit", unavailable)
    result = await scan_worker._execute_audit("https://shop.example/")
    outcomes = {item["check_id"]: item for item in result["check_outcomes"]}

    assert result["summary"]["modules"]["browser_rendered"] == "unavailable"
    assert outcomes["crawl.javascript_rendered_dom"]["outcome"] == "not_assessed"
    assert outcomes["mobile_ux.rendered_viewport_matrix"]["outcome"] == "not_assessed"
    assert outcomes["performance.browser_console_errors"]["outcome"] == "not_assessed"
    assert outcomes["performance.browser_network_failures"]["outcome"] == "not_assessed"
