import asyncio
import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

import main
from database import AsyncSessionLocal
from models import APIKey, AuditLead, AuditQuotaReservation, AuditReport, PaymentWebhookEvent, SoftwareLicense
from ecommerce_agent import ContactInfo, LeadDossier, PersonalizedPitch, StoreAuditMetrics
from audit_checks import AuditCheckResult
from coverage_manifest import build_coverage_manifest


async def create_license(
    *,
    key="test-license",
    quota=10,
    active=True,
    expires_at=None,
):
    async with AsyncSessionLocal() as db:
        license_obj = SoftwareLicense(
            license_key=key,
            client_name="Automated Test",
            tier="test",
            max_monthly_audits=quota,
            is_active=active,
            expires_at=expires_at,
        )
        db.add(license_obj)
        await db.commit()
        await db.refresh(license_obj)
        return license_obj.id


async def table_count(model):
    async with AsyncSessionLocal() as db:
        return (await db.execute(select(func.count(model.id)))).scalar_one()


def make_dossier(domain, email="", source="web_audit"):
    contact_email = email or f"contact@{domain}"
    return LeadDossier(
        store_url=domain,
        audit=StoreAuditMetrics(
            domain=domain,
            mobile_score=78,
            speed_index_sec=2.34,
            is_slow=False,
        ),
        contact=ContactInfo(first_name="Test Owner", email=contact_email),
        pitch=PersonalizedPitch(
            revenue_leak_hypothesis="Slow mobile experience may reduce conversion.",
            email_subject="A quick performance idea",
            email_body="I noticed an opportunity to improve your mobile experience.",
        ),
    )


@pytest.fixture
def mock_process_lead(monkeypatch):
    async def fake_process_lead(domain, user_email, source="web_audit"):
        return make_dossier(domain, user_email, source)

    monkeypatch.setattr(main.agent, "process_lead", fake_process_lead)
    return fake_process_lead


def test_coverage_manifest_does_not_infer_aria_or_alt_text_from_general_accessibility():
    finding = SimpleNamespace(
        category="accessibility",
        title="Form controls may lack accessible labels",
        status="manual_review_required",
        severity="medium",
        source_url="https://shop.example/",
    )
    manifest = build_coverage_manifest(
        target_url="https://shop.example/",
        pages_checked=["https://shop.example/"],
        findings=[finding],
        limitations=[],
        executed_categories=["accessibility"],
    )
    categories = {
        item["category"]: item
        for item in (
            manifest["observed_categories"]
            + manifest["checked_without_findings_categories"]
            + manifest["not_proven_categories"]
        )
    }
    assert categories["accessibility"]["status"] == "recorded"
    assert categories["aria"]["status"] == "not_proven"
    assert categories["aria_alt_text"]["status"] == "not_proven"


def test_coverage_manifest_redacts_credentials_query_and_fragment_from_all_urls():
    finding = SimpleNamespace(
        category="technical_seo",
        title="Canonical URL needs review",
        status="manual_review_required",
        severity="low",
        source_url="https://shop.example/products/item?token=private-evidence#section",
    )
    manifest = build_coverage_manifest(
        target_url="https://shop.example/?session=secret#checkout",
        pages_checked=[
            "https://shop.example/?access_token=secret",
            "https://shop.example/products/item?token=private-evidence#section",
            "https://user:password@shop.example/private",
            "javascript:alert(1)",
        ],
        findings=[finding],
        limitations=[],
        executed_categories=["technical_seo"],
    )

    assert manifest["target_url"] == "https://shop.example/"
    assert manifest["pages_checked"] == [
        "https://shop.example/",
        "https://shop.example/products/item",
    ]
    assert manifest["pages_checked_count"] == 2
    serialized = json.dumps(manifest)
    for secret in ("session=secret", "access_token=secret", "private-evidence", "user:password"):
        assert secret not in serialized
    assert manifest["recorded_observations"][0]["source_url"] == "https://shop.example/products/item"


@pytest.mark.asyncio
async def test_account_usage_reports_monthly_quota_without_exposing_license_key(client):
    license_id = await create_license(key="usage-private-license", quota=5)
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        db.add(AuditLead(
            license_id=license_id,
            domain="used.example",
            mobile_score=80,
            speed_index_sec=2.0,
            created_at=now,
        ))
        db.add(AuditQuotaReservation(
            license_id=license_id,
            created_at=now,
            expires_at=now + timedelta(minutes=10),
        ))
        await db.commit()

    response = await client.get(
        "/api/v1/account/usage",
        headers={"X-License-Key": "usage-private-license"},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["monthly_limit"] == 5
    assert data["used"] == 1
    assert data["in_progress"] == 1
    assert data["remaining"] == 3
    assert data["usage_percent"] == 40
    assert data["tier"] == "test"
    assert "license_key" not in data
    assert "usage-private-license" not in response.text
    assert data["period_resets_at"]
    assert response.headers["cache-control"] == "no-store, private"


@pytest.mark.asyncio
async def test_account_usage_requires_authentication(client):
    response = await client.get("/api/v1/account/usage")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_portal_pages_send_browser_security_headers_and_disable_caching(client):
    for path in ("/app", "/admin"):
        response = await client.get(path)
        assert response.status_code == 200, path
        assert response.headers["cache-control"] == "no-store, private"
        assert response.headers["pragma"] == "no-cache"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
        assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"


@pytest.mark.asyncio
async def test_root_and_database_health(client):
    root = await client.get("/")
    assert root.status_code == 200
    assert root.json()["status"] == "AI Agent Commercial Engine Operational"

    health = await client.get("/health-check")
    assert health.status_code == 200
    assert health.json() == {"status": "success", "db_connected": True, "result": 1}


@pytest.mark.asyncio
async def test_missing_authentication_returns_401(client):
    response = await client.post("/api/v1/audit-lead", params={"domain": "shop.example"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_invalid_license_returns_403(client):
    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "shop.example"},
        headers={"X-License-Key": "not-a-real-license"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_expired_license_returns_402(client):
    await create_license(
        key="expired-license",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "shop.example"},
        headers={"X-License-Key": "expired-license"},
    )
    assert response.status_code == 402


@pytest.mark.asyncio
async def test_inactive_license_returns_403(client):
    await create_license(key="inactive-license", active=False)
    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "shop.example"},
        headers={"X-License-Key": "inactive-license"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_successful_audit_saves_exactly_one_record_and_releases_reservation(
    client, mock_process_lead
):
    await create_license(key="valid-license", quota=1)
    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "shop.example", "email": "owner@example.com"},
        headers={"X-License-Key": "valid-license"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["audit"]["domain"] == "shop.example"
    assert await table_count(AuditLead) == 1
    assert await table_count(AuditQuotaReservation) == 0


@pytest.mark.asyncio
async def test_exhausted_monthly_quota_returns_429(client, mock_process_lead):
    license_id = await create_license(key="quota-license", quota=1)
    async with AsyncSessionLocal() as db:
        db.add(
            AuditLead(
                license_id=license_id,
                domain="already-audited.example",
                mobile_score=50,
                speed_index_sec=5.0,
                created_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "another-shop.example"},
        headers={"X-License-Key": "quota-license"},
    )
    assert response.status_code == 429
    assert await table_count(AuditLead) == 1
    assert await table_count(AuditQuotaReservation) == 0


@pytest.mark.asyncio
async def test_failed_audit_does_not_save_lead_and_releases_reservation(client, monkeypatch):
    await create_license(key="failure-license", quota=1)

    async def fail_audit(domain, user_email, source="web_audit"):
        raise RuntimeError("simulated upstream failure")

    monkeypatch.setattr(main.agent, "process_lead", fail_audit)
    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "shop.example"},
        headers={"X-License-Key": "failure-license"},
    )

    assert response.status_code == 500
    assert await table_count(AuditLead) == 0
    assert await table_count(AuditQuotaReservation) == 0


@pytest.mark.asyncio
async def test_parallel_requests_with_one_slot_return_one_200_and_one_429(
    client, monkeypatch
):
    await create_license(key="parallel-license", quota=1)

    async def slow_audit(domain, user_email, source="web_audit"):
        await asyncio.sleep(0.15)
        return make_dossier(domain, user_email, source)

    monkeypatch.setattr(main.agent, "process_lead", slow_audit)
    headers = {"X-License-Key": "parallel-license"}

    responses = await asyncio.gather(
        client.post(
            "/api/v1/audit-lead",
            params={"domain": "shop-one.example"},
            headers=headers,
        ),
        client.post(
            "/api/v1/audit-lead",
            params={"domain": "shop-two.example"},
            headers=headers,
        ),
    )

    assert sorted(response.status_code for response in responses) == [200, 429]
    assert await table_count(AuditLead) == 1
    assert await table_count(AuditQuotaReservation) == 0


@pytest.mark.asyncio
async def test_configured_concurrency_limit_rejects_extra_active_audit(client, monkeypatch):
    license_id = await create_license(key="concurrency-license", quota=10)
    monkeypatch.setenv("LICENSE_MAX_CONCURRENT_AUDITS_TEST", "1")
    async with AsyncSessionLocal() as db:
        db.add(
            AuditQuotaReservation(
                license_id=license_id,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            )
        )
        await db.commit()

    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "second-shop.example"},
        headers={"X-License-Key": "concurrency-license"},
    )

    assert response.status_code == 429
    assert "Concurrent audit limit of 1" in response.json()["detail"]
    assert await table_count(AuditQuotaReservation) == 1


@pytest.mark.asyncio
async def test_invalid_configured_concurrency_limit_fails_closed(client, monkeypatch):
    await create_license(key="invalid-concurrency-license", quota=10)
    monkeypatch.setenv("LICENSE_MAX_CONCURRENT_AUDITS_TEST", "not-a-number")

    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "shop.example"},
        headers={"X-License-Key": "invalid-concurrency-license"},
    )

    assert response.status_code == 503
    assert await table_count(AuditQuotaReservation) == 0


@pytest.mark.asyncio
async def test_api_key_authentication_and_revocation(client, mock_process_lead):
    api_key = "test-api-key-secret"
    license_id = await create_license(key="api-key-license", quota=5)
    async with AsyncSessionLocal() as db:
        db.add(
            APIKey(
                license_id=license_id,
                api_key_hash=hashlib.sha256(api_key.encode()).hexdigest(),
                key_prefix=api_key[:8],
            )
        )
        await db.commit()

    first = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "api-shop.example"},
        headers={"X-API-Key": api_key},
    )
    assert first.status_code == 200

    async with AsyncSessionLocal() as db:
        api_key_row = (await db.execute(select(APIKey))).scalar_one()
        await db.delete(api_key_row)
        await db.commit()

    second = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "api-shop.example"},
        headers={"X-API-Key": api_key},
    )
    assert second.status_code == 403


@pytest.mark.asyncio
async def test_missing_domain_is_rejected(client):
    await create_license(key="domain-validation-license")
    response = await client.post(
        "/api/v1/audit-lead",
        headers={"X-License-Key": "domain-validation-license"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_report_history_is_scoped_to_authenticated_license(client):
    owner_id = await create_license(key="report-owner")
    other_id = await create_license(key="report-other")
    async with AsyncSessionLocal() as db:
        owned = AuditReport(
            license_id=owner_id,
            domain="owned.example",
            pdf_bytes=b"%PDF-owned",
            coverage_json='{"findings_total": 1}',
            finding_count=1,
        )
        private = AuditReport(
            license_id=other_id,
            domain="private.example",
            pdf_bytes=b"%PDF-private",
            coverage_json='{"findings_total": 2}',
            finding_count=2,
        )
        db.add_all([owned, private])
        await db.commit()
        await db.refresh(owned)
        await db.refresh(private)
        owned_id, private_id = owned.id, private.id

    headers = {"X-License-Key": "report-owner"}
    listing = await client.get("/api/v1/reports", headers=headers)
    assert listing.status_code == 200
    payload = listing.json()
    assert payload["total"] == 1
    assert listing.headers["cache-control"] == "no-store, private"
    assert [row["domain"] for row in payload["reports"]] == ["owned.example"]

    pdf = await client.get(f"/api/v1/reports/{owned_id}/pdf", headers=headers)
    assert pdf.status_code == 200
    assert pdf.content == b"%PDF-owned"
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.headers["cache-control"] == "no-store, private"
    assert pdf.headers["x-content-type-options"] == "nosniff"

    coverage = await client.get(f"/api/v1/reports/{owned_id}/coverage", headers=headers)
    assert coverage.status_code == 200
    assert coverage.json()["findings_total"] == 1
    assert coverage.headers["cache-control"] == "no-store, private"

    forbidden_pdf = await client.get(f"/api/v1/reports/{private_id}/pdf", headers=headers)
    forbidden_coverage = await client.get(f"/api/v1/reports/{private_id}/coverage", headers=headers)
    assert forbidden_pdf.status_code == 404
    assert forbidden_coverage.status_code == 404


@pytest.mark.asyncio
async def test_licensed_comprehensive_audit_saved_pdf_history_ownership_and_opt_in_email(client, monkeypatch):
    owner_key = "journey-owner-license"
    other_key = "journey-other-license"
    owner_id = await create_license(key=owner_key, quota=3)
    await create_license(key=other_key, quota=3)

    async def fake_run_audit(target_url):
        return SimpleNamespace(
            domain="shop.example",
            mobile_score=82,
            speed_index_sec=2.1,
            screenshot_data_uri=None,
        )

    async def fake_phase_one(target_url):
        return AuditCheckResult(
            target_url=target_url,
            checked_at_utc=datetime.now(timezone.utc).isoformat(),
            findings=[],
            pages_checked=[target_url],
            limitations=["Integration test uses mocked network checks."],
        )

    async def fake_crawl(target_url):
        return [], [target_url], ["Crawl mocked for isolated API journey test."]

    async def fake_conversion(target_url):
        return [], [target_url], ["Conversion checks mocked for isolated API journey test."]

    monkeypatch.setattr(main.agent, "run_audit", fake_run_audit)
    monkeypatch.setattr(main, "run_phase_one_checks", fake_phase_one)
    monkeypatch.setattr(main, "run_bounded_site_crawl", fake_crawl)
    monkeypatch.setattr(main, "run_conversion_paid_traffic_checks", fake_conversion)
    monkeypatch.setattr(main, "render_audit_pdf", lambda *args, **kwargs: b"%PDF-journey-test")

    owner_headers = {"X-License-Key": owner_key}
    audit = await client.post(
        "/api/v1/comprehensive-audit?domain=https%3A%2F%2Fshop.example",
        headers=owner_headers,
    )
    assert audit.status_code == 200, audit.text
    assert audit.headers["content-type"] == "application/pdf"
    assert audit.headers["cache-control"] == "no-store, private"
    assert audit.content == b"%PDF-journey-test"
    report_id = int(audit.headers["x-audit-report-id"])

    usage = await client.get("/api/v1/account/usage", headers=owner_headers)
    assert usage.status_code == 200
    assert usage.json()["used"] == 1
    assert usage.json()["remaining"] == 2

    history = await client.get("/api/v1/reports", headers=owner_headers)
    assert history.status_code == 200
    assert history.json()["total"] == 1
    assert history.json()["reports"][0]["id"] == report_id
    assert history.json()["reports"][0]["domain"] == "shop.example"

    stored_pdf = await client.get(f"/api/v1/reports/{report_id}/pdf", headers=owner_headers)
    assert stored_pdf.status_code == 200
    assert stored_pdf.content == b"%PDF-journey-test"

    coverage = await client.get(f"/api/v1/reports/{report_id}/coverage", headers=owner_headers)
    assert coverage.status_code == 200
    assert coverage.json()["target_url"] == "https://shop.example/"
    coverage_categories = {
        row["category"]: row
        for key in ("observed_categories", "checked_without_findings_categories", "not_proven_categories")
        for row in coverage.json()[key]
    }
    # The isolated journey mocks every checker to return no findings and therefore
    # must not claim granular security, ARIA, or trust checker groups ran clean.
    for category in ("aria", "trust", "security_transport", "security_cookies", "security_api_documentation"):
        assert coverage_categories[category]["status"] == "not_proven"
        assert coverage_categories[category]["checker_group_executed"] is False
    # The fake phase-one checker emitted no indexing finding in this isolated test.
    assert coverage_categories["indexing"]["status"] == "not_proven"
    assert coverage_categories["indexing"]["checker_group_executed"] is False

    other_headers = {"X-License-Key": other_key}
    for path in (
        "/api/v1/reports",
        f"/api/v1/reports/{report_id}/pdf",
        f"/api/v1/reports/{report_id}/coverage",
    ):
        response = await client.get(path, headers=other_headers)
        if path == "/api/v1/reports":
            assert response.status_code == 200
            assert response.json()["total"] == 0
            assert response.json()["reports"] == []
        else:
            assert response.status_code == 404

    sent = []
    monkeypatch.setattr(
        main, "_send_pdf_email",
        lambda recipient, domain, sent_report_id, pdf_bytes: sent.append(
            (recipient, domain, sent_report_id, pdf_bytes)
        ),
    )
    no_consent = await client.post(
        f"/api/v1/reports/{report_id}/email",
        headers=owner_headers,
        json={"recipient_email": "recipient@example.com", "recipient_confirmed": False},
    )
    assert no_consent.status_code == 422
    assert sent == []

    foreign_email = await client.post(
        f"/api/v1/reports/{report_id}/email",
        headers=other_headers,
        json={"recipient_email": "recipient@example.com", "recipient_confirmed": True},
    )
    assert foreign_email.status_code == 404
    assert sent == []

    opted_in = await client.post(
        f"/api/v1/reports/{report_id}/email",
        headers=owner_headers,
        json={"recipient_email": "recipient@example.com", "recipient_confirmed": True},
    )
    assert opted_in.status_code == 200, opted_in.text
    assert opted_in.json() == {"status": "sent", "report_id": report_id}
    assert sent == [("recipient@example.com", "shop.example", report_id, b"%PDF-journey-test")]

    async with AsyncSessionLocal() as db:
        saved = (await db.execute(
            select(AuditReport).where(AuditReport.id == report_id, AuditReport.license_id == owner_id)
        )).scalar_one()
        assert saved.pdf_bytes == b"%PDF-journey-test"
        assert await db.scalar(select(func.count(AuditQuotaReservation.id))) == 0


@pytest.mark.asyncio
async def test_report_history_supports_stable_offset_pagination(client):
    license_id = await create_license(key="report-pagination-owner")
    async with AsyncSessionLocal() as db:
        db.add_all([
            AuditReport(
                license_id=license_id,
                domain=f"shop-{index}.example",
                pdf_bytes=b"%PDF-test",
                coverage_json="{}",
                finding_count=index,
                created_at=datetime.now(timezone.utc) + timedelta(seconds=index),
            )
            for index in range(3)
        ])
        await db.commit()

    headers = {"X-License-Key": "report-pagination-owner"}
    first = await client.get("/api/v1/reports?limit=2&offset=0", headers=headers)
    second = await client.get("/api/v1/reports?limit=2&offset=2", headers=headers)
    assert first.status_code == second.status_code == 200
    first_data, second_data = first.json(), second.json()
    assert first_data["total"] == second_data["total"] == 3
    assert len(first_data["reports"]) == 2
    assert len(second_data["reports"]) == 1
    first_ids = {row["id"] for row in first_data["reports"]}
    second_ids = {row["id"] for row in second_data["reports"]}
    assert first_ids.isdisjoint(second_ids)


@pytest.mark.asyncio
async def test_report_history_requires_authentication(client):
    response = await client.get("/api/v1/reports")
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_admin_overview_aggregates_per_license_metrics(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-overview-key")
    license_id = await create_license(key="admin-overview-license", quota=5)
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        db.add(AuditLead(
            license_id=license_id, domain="overview.example", mobile_score=81,
            speed_index_sec=2.1, created_at=now,
        ))
        db.add(AuditReport(
            license_id=license_id, domain="overview.example", pdf_bytes=b"%PDF-test",
            coverage_json="{}", finding_count=2, created_at=now,
        ))
        db.add(AuditQuotaReservation(
            license_id=license_id, created_at=now,
            expires_at=now + timedelta(minutes=10),
        ))
        await db.commit()

    response = await client.get(
        "/api/v1/admin/overview",
        headers={"X-Admin-Key": "test-admin-overview-key"},
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    payload = response.json()
    row = next(item for item in payload["clients"] if item["id"] == license_id)
    assert row["monthly_used"] == 1
    assert row["monthly_remaining"] == 4
    assert row["total_audits"] == 1
    assert row["reports_saved"] == 1
    assert row["active_audit_reservations"] == 1
    assert row["last_audit_at"]


@pytest.mark.asyncio
async def test_admin_pdf_download_is_private_and_not_cacheable(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-pdf-key")
    license_id = await create_license(key="admin-pdf-license")
    async with AsyncSessionLocal() as db:
        report = AuditReport(
            license_id=license_id, domain="private.example",
            pdf_bytes=b"%PDF-admin-private", coverage_json="{}",
            finding_count=1,
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)
        report_id = report.id

    unauthorized = await client.get(f"/api/v1/admin/reports/{report_id}/pdf")
    assert unauthorized.status_code in (401, 403)
    response = await client.get(
        f"/api/v1/admin/reports/{report_id}/pdf",
        headers={"X-Admin-Key": "test-admin-pdf-key"},
    )
    assert response.status_code == 200
    assert response.content == b"%PDF-admin-private"
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_customer_portal_is_served(client):
    response = await client.get("/app")
    assert response.status_code == 200
    assert "E-commerce Audit Dashboard" in response.text
    assert 'id="auditForm"' in response.text


@pytest.mark.asyncio
async def test_report_email_requires_explicit_recipient_confirmation(client, monkeypatch):
    license_id = await create_license(key="email-report-license")
    async with AsyncSessionLocal() as db:
        report = AuditReport(
            license_id=license_id,
            domain="mail.example",
            pdf_bytes=b"%PDF-email",
            coverage_json="{}",
            finding_count=0,
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)
        report_id = report.id

    response = await client.post(
        f"/api/v1/reports/{report_id}/email",
        headers={"X-License-Key": "email-report-license"},
        json={"recipient_email": "customer@example.com", "recipient_confirmed": False},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_report_email_uses_configured_sender_only_for_owned_report(client, monkeypatch):
    license_id = await create_license(key="email-report-owner")
    async with AsyncSessionLocal() as db:
        report = AuditReport(
            license_id=license_id,
            domain="mail.example",
            pdf_bytes=b"%PDF-email",
            coverage_json="{}",
            finding_count=0,
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)
        report_id = report.id

    sent = {}
    def fake_send(recipient, domain, report_id_arg, pdf_bytes):
        sent.update({
            "recipient": recipient, "domain": domain,
            "report_id": report_id_arg, "pdf_bytes": pdf_bytes,
        })
    monkeypatch.setattr(main, "_send_pdf_email", fake_send)
    response = await client.post(
        f"/api/v1/reports/{report_id}/email",
        headers={"X-License-Key": "email-report-owner"},
        json={"recipient_email": "customer@example.com", "recipient_confirmed": True},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "sent", "report_id": report_id}
    assert sent == {
        "recipient": "customer@example.com",
        "domain": "mail.example",
        "report_id": report_id,
        "pdf_bytes": b"%PDF-email",
    }


@pytest.mark.asyncio
async def test_report_email_cannot_send_another_licenses_pdf(client, monkeypatch):
    owner_id = await create_license(key="email-report-private-owner")
    await create_license(key="email-report-private-requester")
    async with AsyncSessionLocal() as db:
        report = AuditReport(
            license_id=owner_id, domain="private.example",
            pdf_bytes=b"%PDF-private", coverage_json="{}", finding_count=1,
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)
        report_id = report.id

    sent = []
    monkeypatch.setattr(
        main, "_send_pdf_email",
        lambda recipient, domain, report_id_arg, pdf_bytes: sent.append(report_id_arg),
    )
    response = await client.post(
        f"/api/v1/reports/{report_id}/email",
        headers={"X-License-Key": "email-report-private-requester"},
        json={"recipient_email": "recipient@example.com", "recipient_confirmed": True},
    )
    assert response.status_code == 404
    assert sent == []


@pytest.mark.asyncio
async def test_paddle_webhook_verifies_transaction_provisions_license_and_is_idempotent(client, monkeypatch):
    secret = "paddle-test-webhook-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_01abc123")
    monkeypatch.setenv("LICENSE_MONTHLY_AUDITS_STARTER", "100")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    sent = []
    monkeypatch.setattr(main, "_send_license_email", lambda email, key, tier, quota: sent.append((email, key, tier, quota)))
    event = {"event_id": "evt_paddle_test_completed", "event_type": "transaction.completed",
        "data": {"id": "txn_01abc123", "status": "completed", "custom_data": {"license_tier": "starter"},
        "customer_id": "ctm_01abc123", "customer": {"email": "buyer@example.com", "name": "Test Buyer"},
        "items": [{"price": {"id": "pri_01abc123"}, "quantity": 1}]}}
    body = json.dumps(event, separators=(",", ":")).encode()
    timestamp = int(time.time())
    signature = hmac.new(secret.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256).hexdigest()
    headers = {"Paddle-Signature": f"ts={timestamp};h1={signature}"}
    first = await client.post("/api/v1/billing/paddle-webhook", content=body, headers=headers)
    assert first.status_code == 200 and first.json()["status"] == "provisioned"
    assert len(sent) == 1 and sent[0][0] == "buyer@example.com" and sent[0][2:] == ("starter", 100)
    duplicate = await client.post("/api/v1/billing/paddle-webhook", content=body, headers=headers)
    assert duplicate.status_code == 200 and duplicate.json()["status"] == "already_processed" and len(sent) == 1
    async with AsyncSessionLocal() as db:
        licenses = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.client_name == "Test Buyer"))).scalars().all()
        events = (await db.execute(select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == "evt_paddle_test_completed"))).scalars().all()
    assert len(licenses) == 1 and len(events) == 1 and events[0].status == "delivered"


@pytest.mark.asyncio
async def test_paddle_webhook_rejects_invalid_signature_without_provisioning(client, monkeypatch):
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", "paddle-test-webhook-secret")
    body = b'{"event_id":"evt_bad","event_type":"transaction.completed","data":{"status":"completed"}}'
    response = await client.post("/api/v1/billing/paddle-webhook", content=body,
        headers={"Paddle-Signature": f"ts={int(time.time())};h1=invalid"})
    assert response.status_code == 400
    async with AsyncSessionLocal() as db:
        assert (await db.execute(select(func.count(SoftwareLicense.id)))).scalar_one() == 0


@pytest.mark.asyncio
async def test_public_plans_only_show_configured_paddle_price_ids(client, monkeypatch):
    for key, value in {"PADDLE_API_KEY": "pdl_sandbox_test_key", "PADDLE_WEBHOOK_SECRET": "test-webhook-secret",
        "SMTP_HOST": "smtp.example.com", "SMTP_FROM": "reports@example.com", "PADDLE_PRICE_ID_STARTER": "pri_01abc123"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("PADDLE_PRICE_ID_PRO", raising=False)
    response = await client.get("/api/v1/billing/plans")
    payload = response.json()
    assert response.status_code == 200 and payload["configured"] is True
    assert payload["checkout_provider"] == "Paddle" and [plan["tier"] for plan in payload["plans"]] == ["starter"]
    assert "price_id" not in payload["plans"][0]


@pytest.mark.asyncio
async def test_paddle_checkout_uses_server_configured_price(client, monkeypatch):
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_01abc123")
    captured = {}
    def fake_request(path, method="GET", payload=None):
        captured.update({"path": path, "method": method, "payload": payload})
        return {"data": {"id": "txn_01abc123", "checkout": {"url": "https://pay.paddle.com/checkout/test"}}}
    monkeypatch.setattr(main, "_paddle_api_request", fake_request)
    response = await client.post("/api/v1/billing/checkout", json={"tier": "starter"})
    assert response.status_code == 200 and response.json()["checkout_url"] == "https://pay.paddle.com/checkout/test"
    assert captured["payload"]["items"] == [{"price_id": "pri_01abc123", "quantity": 1}]
    assert captured["payload"]["custom_data"]["license_tier"] == "starter"
    assert (await client.post("/api/v1/billing/checkout", json={"tier": "made-up"})).status_code == 422


@pytest.mark.asyncio
async def test_paddle_webhook_retries_pending_license_email_without_duplicate_license(client, monkeypatch):
    secret = "paddle-test-webhook-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_01retry123")
    monkeypatch.setenv("LICENSE_MONTHLY_AUDITS_STARTER", "100")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    attempts = []

    def flaky_email(email, key, tier, quota):
        attempts.append((email, key, tier, quota))
        if len(attempts) == 1:
            raise RuntimeError("simulated SMTP outage")

    monkeypatch.setattr(main, "_send_license_email", flaky_email)
    event = {
        "event_id": "evt_paddle_email_retry",
        "event_type": "transaction.completed",
        "data": {
            "id": "txn_01retry123",
            "status": "completed",
            "custom_data": {"license_tier": "starter"},
            "customer": {"email": "retry-buyer@example.com", "name": "Retry Buyer"},
            "items": [{"price": {"id": "pri_01retry123"}, "quantity": 1}],
        },
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    timestamp = int(time.time())
    signature = hmac.new(
        secret.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256
    ).hexdigest()
    headers = {"Paddle-Signature": f"ts={timestamp};h1={signature}"}

    first = await client.post("/api/v1/billing/paddle-webhook", content=body, headers=headers)
    assert first.status_code == 502
    assert "pending SMTP delivery retry" in first.json()["detail"]

    retry = await client.post("/api/v1/billing/paddle-webhook", content=body, headers=headers)
    assert retry.status_code == 200
    assert retry.json()["status"] == "provisioned"
    assert len(attempts) == 2
    assert attempts[0][1] == attempts[1][1]  # The same license key is retried.
    async with AsyncSessionLocal() as db:
        licenses = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.client_name == "Retry Buyer")
        )).scalars().all()
        events = (await db.execute(
            select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == "evt_paddle_email_retry")
        )).scalars().all()
    assert len(licenses) == 1
    assert len(events) == 1 and events[0].status == "delivered"
