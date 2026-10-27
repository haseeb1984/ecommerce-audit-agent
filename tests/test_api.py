import asyncio
import hashlib
import hmac
import json
import time
import threading
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
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


def test_smtp_configuration_status_reports_missing_settings_without_exposing_values(monkeypatch):
    for name in ("SMTP_HOST", "SMTP_FROM", "SMTP_PORT", "SMTP_TLS_MODE", "SMTP_USERNAME", "SMTP_PASSWORD"):
        monkeypatch.delenv(name, raising=False)

    status = main._smtp_configuration_status()
    assert status["configured"] is False
    assert "SMTP_HOST missing" in status["issues"]
    assert "SMTP_FROM missing" in status["issues"]
    assert all("secret" not in issue.lower() for issue in status["issues"])


def test_smtp_configuration_status_validates_port_tls_and_auth_pair(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "mail.example.test")
    monkeypatch.setenv("SMTP_FROM", "billing@example.test")
    monkeypatch.setenv("SMTP_PORT", "not-a-port")
    monkeypatch.setenv("SMTP_TLS_MODE", "plaintext")
    monkeypatch.setenv("SMTP_USERNAME", "mailer")
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)

    status = main._smtp_configuration_status()
    assert status["configured"] is False
    assert "SMTP_PORT must be an integer from 1 to 65535" in status["issues"]
    assert "SMTP_TLS_MODE must be starttls or ssl" in status["issues"]
    assert "SMTP_USERNAME and SMTP_PASSWORD must both be set or both be empty" in status["issues"]


def test_smtp_configuration_status_accepts_valid_unauthenticated_starttls(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "mail.example.test")
    monkeypatch.setenv("SMTP_FROM", "billing@example.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_TLS_MODE", "starttls")
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)

    assert main._smtp_configuration_status() == {"configured": True, "issues": []}

@pytest.mark.parametrize("target", [
    "http://127.0.0.1",
    "https://10.0.0.1",
    "http://[::1]/admin",
    "localhost",
    "service.internal",
    "https://user:password@shop.example",
    "https://shop.example:8443",
    "https://shop.example/?token=secret",
    "javascript:alert(1)",
    "not a valid hostname",
])
def test_audit_target_normalization_rejects_unsafe_or_ambiguous_targets(target):
    with pytest.raises(ValueError):
        main.agent._normalize_audit_target(target)


@pytest.mark.parametrize("target,expected", [
    ("shop.example", "https://shop.example/"),
    ("https://Shop.Example/products", "https://shop.example/products"),
    ("http://shop.example/", "https://shop.example/"),
    ("https://bücher.example/catalog", "https://xn--bcher-kva.example/catalog"),
])
def test_audit_target_normalization_canonicalizes_public_targets(target, expected):
    assert main.agent._normalize_audit_target(target) == expected


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
        if path == "/admin":
            assert "smtp_configuration_issues" in response.text


@pytest.mark.asyncio
async def test_root_and_database_health(client):
    root = await client.get("/")
    assert root.status_code == 200
    assert root.json()["status"] == "AI Agent Commercial Engine Operational"

    health = await client.get("/health-check")
    assert health.status_code == 200
    assert health.json() == {
        "status": "success",
        "db_connected": True,
        "schema_ready": True,
        "result": 1,
    }


@pytest.mark.asyncio
async def test_missing_authentication_returns_401(client):
    response = await client.post("/api/v1/audit-lead", params={"domain": "shop.example"})
    assert response.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("domain", [
    "http://127.0.0.1",
    "http://[::1]/admin",
    "http://localhost",
    "https://user:password@shop.example",
    "https://shop.example/?token=secret",
    "https://shop.example:8443",
])
async def test_audit_lead_rejects_unsafe_target_before_reserving_quota(client, domain):
    license_key = "invalid-target-license"
    await create_license(key=license_key, quota=2)
    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": domain},
        headers={"X-License-Key": license_key},
    )
    assert response.status_code == 422
    async with AsyncSessionLocal() as db:
        license_obj = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.license_key == license_key)
        )).scalar_one()
        reservations = (await db.execute(
            select(func.count(AuditQuotaReservation.id)).where(
                AuditQuotaReservation.license_id == license_obj.id
            )
        )).scalar_one()
        leads = (await db.execute(
            select(func.count(AuditLead.id)).where(AuditLead.license_id == license_obj.id)
        )).scalar_one()
    assert reservations == 0
    assert leads == 0


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
        raise TimeoutError("simulated optional crawl timeout")

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
    assert coverage.json()["evidence_storage_limits"]["max_findings"] == 150
    assert coverage.json()["evidence_storage_limits"]["query_strings_and_fragments_removed_from_evidence_urls"] is True
    assert coverage.json()["stored_findings_count"] >= 1
    findings_response = await client.get(
        f"/api/v1/reports/{report_id}/evidence?kind=findings&limit=20&offset=0",
        headers=owner_headers,
    )
    assert findings_response.status_code == 200
    assert findings_response.json()["total"] >= 1
    assert findings_response.json()["items"][0]["category"] == "performance"
    assert findings_response.json()["items"][0]["test_method"] == "Google PageSpeed Insights API mobile Lighthouse lab run"
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
    # An optional crawl timeout is retained as not-tested evidence and must not
    # discard the PDF, saved report, quota accounting, or completed conversion checker.
    assert coverage_categories["crawlability"]["status"] == "recorded"
    assert coverage_categories["crawlability"]["checker_group_executed"] is False
    assert coverage_categories["conversion_paid_traffic"]["status"] == "checked_no_findings"
    assert coverage_categories["conversion_paid_traffic"]["checker_group_executed"] is True

    other_headers = {"X-License-Key": other_key}
    for path in (
        "/api/v1/reports",
        f"/api/v1/reports/{report_id}/pdf",
        f"/api/v1/reports/{report_id}/coverage",
        f"/api/v1/reports/{report_id}/evidence",
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
async def test_paddle_subscription_renewal_reuses_existing_license_without_resending_key(client, monkeypatch):
    secret = "paddle-test-webhook-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_renewal123")
    monkeypatch.setenv("LICENSE_MONTHLY_AUDITS_STARTER", "100")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    sent = []
    monkeypatch.setattr(main, "_send_license_email", lambda *args: sent.append(args))

    async def send(event):
        body = json.dumps(event, separators=(",", ":")).encode()
        timestamp = int(time.time())
        signature = hmac.new(secret.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256).hexdigest()
        return await client.post(
            "/api/v1/billing/paddle-webhook",
            content=body,
            headers={"Paddle-Signature": f"ts={timestamp};h1={signature}"},
        )

    purchase = {"event_id": "evt_renewal_purchase", "event_type": "transaction.completed",
        "data": {"id": "txn_renewal_first", "subscription_id": "sub_renewal123",
        "status": "completed", "custom_data": {"license_tier": "starter"},
        "customer_id": "ctm_renewal123", "customer": {"email": "renewal@example.com", "name": "Renewal Buyer"},
        "items": [{"price": {"id": "pri_renewal123"}, "quantity": 1}]}}
    first = await send(purchase)
    assert first.status_code == 200 and first.json()["status"] == "provisioned"
    assert len(sent) == 1

    renewal = {"event_id": "evt_renewal_second", "event_type": "transaction.completed",
        "data": {"id": "txn_renewal_second", "subscription_id": "sub_renewal123",
        "status": "completed", "custom_data": {"license_tier": "starter"},
        "customer_id": "ctm_renewal123", "customer": {"email": "renewal@example.com", "name": "Renewal Buyer"},
        "items": [{"price": {"id": "pri_renewal123"}, "quantity": 1}]}}
    renewed = await send(renewal)
    assert renewed.status_code == 200
    assert renewed.json()["status"] == "subscription_renewed"
    assert len(sent) == 1

    duplicate = await send(renewal)
    assert duplicate.status_code == 200
    assert duplicate.json()["status"] == "already_processed"
    async with AsyncSessionLocal() as db:
        licenses = (await db.execute(select(SoftwareLicense).where(
            SoftwareLicense.client_name == "Renewal Buyer"))).scalars().all()
        events = (await db.execute(select(PaymentWebhookEvent).where(
            PaymentWebhookEvent.subscription_id == "sub_renewal123"))).scalars().all()
    assert len(licenses) == 1
    assert len(events) == 2
    assert {item.event_id for item in events} == {"evt_renewal_purchase", "evt_renewal_second"}


@pytest.mark.asyncio
async def test_paddle_subscription_cancellation_deactivates_linked_license_idempotently(client, monkeypatch):
    secret = "paddle-test-webhook-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_01cancel123")
    monkeypatch.setenv("LICENSE_MONTHLY_AUDITS_STARTER", "100")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    monkeypatch.setattr(main, "_send_license_email", lambda *args: None)
    purchase = {"event_id": "evt_purchase_for_cancel", "event_type": "transaction.completed",
        "data": {"id": "txn_01cancel123", "subscription_id": "sub_01cancel123", "status": "completed",
        "custom_data": {"license_tier": "starter"}, "customer_id": "ctm_01cancel123",
        "customer": {"email": "cancel-buyer@example.com", "name": "Cancel Buyer"},
        "items": [{"price": {"id": "pri_01cancel123"}, "quantity": 1}]}}
    async def send(event):
        body = json.dumps(event, separators=(",", ":")).encode()
        timestamp = int(time.time())
        signature = hmac.new(secret.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256).hexdigest()
        return await client.post("/api/v1/billing/paddle-webhook", content=body,
            headers={"Paddle-Signature": f"ts={timestamp};h1={signature}"})
    provision = await send(purchase)
    assert provision.status_code == 200
    async with AsyncSessionLocal() as db:
        license_obj = (await db.execute(select(SoftwareLicense).where(
            SoftwareLicense.client_name == "Cancel Buyer"))).scalar_one()
        license_id = license_obj.id
        assert license_obj.is_active is True
    cancellation = {"event_id": "evt_subscription_cancelled", "event_type": "subscription.canceled",
        "data": {"id": "sub_01cancel123"}}
    first = await send(cancellation)
    assert first.status_code == 200 and first.json()["status"] == "cancellation_applied"
    second = await send(cancellation)
    assert second.status_code == 200 and second.json()["status"] == "already_canceled"
    async with AsyncSessionLocal() as db:
        license_obj = (await db.execute(select(SoftwareLicense).where(
            SoftwareLicense.id == license_id))).scalar_one()
        assert license_obj.is_active is False


@pytest.mark.asyncio
async def test_paddle_late_renewal_does_not_reactivate_canceled_subscription(client, monkeypatch):
    secret = "paddle-test-webhook-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_late_renewal123")
    monkeypatch.setenv("LICENSE_MONTHLY_AUDITS_STARTER", "100")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    monkeypatch.setattr(main, "_send_license_email", lambda *args: None)

    async def send(event):
        body = json.dumps(event, separators=(",", ":")).encode()
        timestamp = int(time.time())
        signature = hmac.new(
            secret.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256
        ).hexdigest()
        return await client.post(
            "/api/v1/billing/paddle-webhook",
            content=body,
            headers={"Paddle-Signature": f"ts={timestamp};h1={signature}"},
        )

    purchase = {
        "event_id": "evt_late_renewal_purchase",
        "event_type": "transaction.completed",
        "data": {
            "id": "txn_late_renewal_purchase",
            "subscription_id": "sub_late_renewal123",
            "status": "completed",
            "custom_data": {"license_tier": "starter"},
            "customer_id": "ctm_late_renewal123",
            "customer": {"email": "late-renewal@example.com", "name": "Late Renewal"},
            "items": [{"price": {"id": "pri_late_renewal123"}, "quantity": 1}],
        },
    }
    assert (await send(purchase)).status_code == 200

    cancellation = {
        "event_id": "evt_late_renewal_cancel",
        "event_type": "subscription.canceled",
        "data": {"id": "sub_late_renewal123"},
    }
    canceled = await send(cancellation)
    assert canceled.status_code == 200
    assert canceled.json()["status"] == "cancellation_applied"

    late_renewal = {
        "event_id": "evt_late_renewal_paid_late",
        "event_type": "transaction.completed",
        "data": {
            "id": "txn_late_renewal_paid_late",
            "subscription_id": "sub_late_renewal123",
            "status": "completed",
            "custom_data": {"license_tier": "starter"},
            "customer_id": "ctm_late_renewal123",
            "customer": {"email": "late-renewal@example.com", "name": "Late Renewal"},
            "items": [{"price": {"id": "pri_late_renewal123"}, "quantity": 1}],
        },
    }
    response = await send(late_renewal)
    assert response.status_code == 200
    assert response.json()["status"] == "subscription_canceled"

    async with AsyncSessionLocal() as db:
        license_obj = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.client_name == "Late Renewal")
        )).scalar_one()
        assert license_obj.is_active is False
        events = (await db.execute(
            select(PaymentWebhookEvent).where(
                PaymentWebhookEvent.subscription_id == "sub_late_renewal123"
            )
        )).scalars().all()
    assert len(events) == 2
    statuses = {item.event_id: item.status for item in events}
    assert statuses["evt_late_renewal_purchase"] == "delivered"
    assert statuses["evt_late_renewal_cancel"] == "subscription_canceled"


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


@pytest.mark.asyncio
async def test_paddle_webhook_claims_license_email_delivery_once_for_concurrent_retries(client, monkeypatch):
    secret = "paddle-test-webhook-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_01concurrent123")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    entered_send = threading.Event()
    release_send = threading.Event()
    attempts = []

    def blocking_email(email, key, tier, quota):
        attempts.append(key)
        entered_send.set()
        if not release_send.wait(timeout=5):
            raise RuntimeError("test email send timed out")

    monkeypatch.setattr(main, "_send_license_email", blocking_email)
    event = {
        "event_id": "evt_paddle_concurrent_email",
        "event_type": "transaction.completed",
        "data": {
            "id": "txn_01concurrent123",
            "status": "completed",
            "custom_data": {"license_tier": "starter"},
            "customer": {"email": "concurrent-buyer@example.com", "name": "Concurrent Buyer"},
            "items": [{"price": {"id": "pri_01concurrent123"}, "quantity": 1}],
        },
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    timestamp = int(time.time())
    signature = hmac.new(
        secret.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256
    ).hexdigest()
    headers = {"Paddle-Signature": f"ts={timestamp};h1={signature}"}

    first_task = asyncio.create_task(client.post(
        "/api/v1/billing/paddle-webhook", content=body, headers=headers
    ))
    try:
        assert await asyncio.to_thread(entered_send.wait, 3), "first webhook did not start email delivery"
        second = await client.post("/api/v1/billing/paddle-webhook", content=body, headers=headers)
        assert second.status_code == 200
        assert second.json()["status"] == "delivery_in_progress"
    finally:
        release_send.set()
    first = await first_task
    assert first.status_code == 200 and first.json()["status"] == "provisioned"
    assert len(attempts) == 1



@pytest.mark.asyncio
async def test_paddle_webhook_different_event_ids_for_same_transaction_do_not_duplicate_license(client, monkeypatch):
    secret = "paddle-test-webhook-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_01dedupe123")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    monkeypatch.setattr(main, "_send_license_email", lambda email, key, tier, quota: None)

    async def deliver(event_id):
        event = {
            "event_id": event_id,
            "event_type": "transaction.completed",
            "data": {
                "id": "txn_01samepurchase123",
                "status": "completed",
                "custom_data": {"license_tier": "starter"},
                "customer": {"email": "same-purchase@example.com", "name": "Same Purchase"},
                "items": [{"price": {"id": "pri_01dedupe123"}, "quantity": 1}],
            },
        }
        body = json.dumps(event, separators=(",", ":")).encode()
        timestamp = int(time.time())
        signature = hmac.new(
            secret.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256
        ).hexdigest()
        return await client.post(
            "/api/v1/billing/paddle-webhook",
            content=body,
            headers={"Paddle-Signature": f"ts={timestamp};h1={signature}"},
        )

    # Simulate Paddle delivering two event IDs for one purchase at the same time.
    first, second = await asyncio.gather(
        deliver("evt_same_purchase_original"),
        deliver("evt_same_purchase_redelivered"),
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    # The duplicate may observe the committed event while the first request
    # is still sending the license email, or after delivery has completed.
    statuses = [first.json()["status"], second.json()["status"]]
    assert "provisioned" in statuses
    assert len(statuses) == 2
    assert all(status in {"provisioned", "already_processed", "delivery_in_progress"} for status in statuses)
    assert sum(status == "provisioned" for status in statuses) == 1

    async with AsyncSessionLocal() as db:
        licenses = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.client_name == "Same Purchase")
        )).scalars().all()
        events = (await db.execute(
            select(PaymentWebhookEvent).where(
                PaymentWebhookEvent.transaction_id == "txn_01samepurchase123"
            )
        )).scalars().all()
    assert len(licenses) == 1
    assert len(events) == 1 and events[0].status == "delivered"

@pytest.mark.asyncio
async def test_admin_package_lifecycle_create_update_and_soft_deactivate(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-packages-key")
    headers = {"X-Admin-Key": "test-admin-packages-key"}
    payload = {
        "tier": "qa-test-plan",
        "label": "QA Test Plan",
        "monthly_audit_allowance": 37,
        "max_concurrent_audits": 4,
        "paddle_price_id": "pri_QaTestPlan123",
        "is_active": True,
    }

    unauthorized = await client.get("/api/v1/admin/packages")
    assert unauthorized.status_code in (401, 403)

    created = await client.post("/api/v1/admin/packages", headers=headers, json=payload)
    assert created.status_code == 200, created.text
    assert created.json() == {"status": "created", "tier": "qa-test-plan"}

    listed = await client.get("/api/v1/admin/packages", headers=headers)
    assert listed.status_code == 200, listed.text
    package = next(item for item in listed.json()["packages"] if item["tier"] == "qa-test-plan")
    assert package["monthly_audit_allowance"] == 37
    assert package["max_concurrent_audits"] == 4
    assert package["price_id"] == "pri_QaTestPlan123"
    assert package["is_active"] is True

    updated_payload = {
        **payload,
        "label": "QA Test Plan Updated",
        "monthly_audit_allowance": 73,
        "max_concurrent_audits": 6,
        "paddle_price_id": None,
    }
    updated = await client.patch(
        "/api/v1/admin/packages/qa-test-plan", headers=headers, json=updated_payload
    )
    assert updated.status_code == 200, updated.text
    assert updated.json() == {"status": "updated", "tier": "qa-test-plan"}

    deactivated = await client.delete(
        "/api/v1/admin/packages/qa-test-plan", headers=headers
    )
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json() == {"status": "deactivated", "tier": "qa-test-plan"}

    final_list = await client.get("/api/v1/admin/packages", headers=headers)
    assert final_list.status_code == 200, final_list.text
    final_package = next(
        item for item in final_list.json()["packages"] if item["tier"] == "qa-test-plan"
    )
    assert final_package["label"] == "QA Test Plan Updated"
    assert final_package["monthly_audit_allowance"] == 73
    assert final_package["max_concurrent_audits"] == 6
    assert final_package["is_active"] is False



@pytest.mark.asyncio
async def test_pagespeed_provider_failure_still_saves_partial_audit_without_fake_metrics(client, monkeypatch):
    license_key = "partial-audit-pagespeed-failure"
    await create_license(key=license_key, quota=2)

    async def failed_pagespeed(target_url):
        raise RuntimeError("synthetic provider timeout")

    async def fake_phase_one(target_url):
        return AuditCheckResult(
            target_url=target_url,
            checked_at_utc=datetime.now(timezone.utc).isoformat(),
            findings=[],
            pages_checked=[target_url],
            limitations=[],
        )

    async def fake_crawl(target_url):
        return [], [target_url], []

    async def fake_conversion(target_url):
        return [], [target_url], []

    monkeypatch.setattr(main.agent, "run_audit", failed_pagespeed)
    monkeypatch.setattr(main, "run_phase_one_checks", fake_phase_one)
    monkeypatch.setattr(main, "run_bounded_site_crawl", fake_crawl)
    monkeypatch.setattr(main, "run_conversion_paid_traffic_checks", fake_conversion)
    monkeypatch.setattr(main, "render_audit_pdf", lambda *args, **kwargs: b"%PDF-partial-audit")

    headers = {"X-License-Key": license_key}
    response = await client.post(
        "/api/v1/comprehensive-audit?domain=https%3A%2F%2Fpartial.example",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    report_id = int(response.headers["x-audit-report-id"])

    coverage = await client.get(f"/api/v1/reports/{report_id}/coverage", headers=headers)
    assert coverage.status_code == 200
    assert coverage.json()["stored_findings_count"] >= 1
    evidence_response = await client.get(
        f"/api/v1/reports/{report_id}/evidence?kind=findings&limit=20&offset=0",
        headers=headers,
    )
    assert evidence_response.status_code == 200
    performance = next(
        row for row in evidence_response.json()["items"]
        if row["category"] == "performance"
    )
    assert performance["status"] == "not_tested"
    assert "no score" in performance["evidence"].lower()
    performance_category = next(
        row for key in ("observed_categories", "checked_without_findings_categories", "not_proven_categories")
        for row in coverage.json()[key]
        if row["category"] == "performance"
    )
    assert performance_category["checker_group_executed"] is False
    outcomes_response = await client.get(
        f"/api/v1/reports/{report_id}/evidence?kind=check_outcomes&limit=20&offset=0",
        headers=headers,
    )
    assert any(item["check_id"] == "performance.pagespeed_api" and item["outcome"] == "error"
               for item in outcomes_response.json()["items"])
    assert coverage.json()["category_execution_coverage_pct"] is not None

    usage = await client.get("/api/v1/account/usage", headers=headers)
    assert usage.status_code == 200
    assert usage.json()["used"] == 1


def test_persisted_audit_evidence_redacts_query_parameters_and_credentials():
    value = (
        "Fetched https://shop.example/products/item?access_token=private#section "
        "with api_key=synthetic-secret"
    )
    safe = main._redact_audit_metadata_text(value)
    assert "access_token=private" not in safe
    assert "synthetic-secret" not in safe
    assert "https://shop.example/products/item" in safe



@pytest.mark.asyncio
async def test_admin_report_evidence_is_authenticated_bounded_and_reads_saved_outcomes(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-evidence-key")
    license_id = await create_license(key="admin-evidence-license")
    coverage = {
        "check_outcomes": [
            {
                "check_id": "seo.title",
                "category": "technical_seo",
                "page_url": "https://shop.example/",
                "outcome": "pass",
                "evidence": "A non-empty title was present.",
                "internal_secret": "must-not-be-returned",
            },
            {
                "check_id": "mobile.viewport",
                "category": "mobile_ux",
                "page_url": "https://shop.example/product",
                "outcome": "warning",
                "evidence": "Viewport declaration needs review.",
            },
        ],
        "findings": [],
    }
    async with AsyncSessionLocal() as db:
        report = AuditReport(
            license_id=license_id,
            domain="shop.example",
            pdf_bytes=b"%PDF-test",
            coverage_json=json.dumps(coverage),
            finding_count=0,
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)
        report_id = report.id

    denied = await client.get(f"/api/v1/admin/reports/{report_id}/evidence")
    assert denied.status_code == 401

    response = await client.get(
        f"/api/v1/admin/reports/{report_id}/evidence?kind=check_outcomes&limit=1&offset=0",
        headers={"X-Admin-Key": "test-admin-evidence-key"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert payload["counts"]["pass"] == 1
    assert payload["counts"]["warning"] == 1
    assert len(payload["items"]) == 1
    assert payload["items"][0]["check_id"] == "seo.title"
    assert "internal_secret" not in json.dumps(payload)
    assert response.headers["cache-control"] == "no-store, private"

    missing = await client.get(
        "/api/v1/admin/reports/999999/evidence",
        headers={"X-Admin-Key": "test-admin-evidence-key"},
    )
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_malformed_saved_coverage_does_not_break_customer_or_admin_evidence(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-malformed-coverage")
    license_key = "malformed-saved-coverage-license"
    license_id = await create_license(key=license_key)
    async with AsyncSessionLocal() as db:
        report = AuditReport(
            license_id=license_id,
            domain="broken-coverage.example",
            pdf_bytes=b"%PDF-test",
            coverage_json="{malformed-json",
            finding_count=0,
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)
        report_id = report.id

    headers = {"X-License-Key": license_key}
    coverage = await client.get(f"/api/v1/reports/{report_id}/coverage", headers=headers)
    assert coverage.status_code == 200
    assert coverage.json()["stored_findings_count"] == 0
    assert coverage.json()["stored_check_outcomes_count"] == 0

    evidence = await client.get(
        f"/api/v1/reports/{report_id}/evidence?kind=check_outcomes",
        headers=headers,
    )
    assert evidence.status_code == 200
    assert evidence.json()["total"] == 0
    assert evidence.json()["items"] == []
    assert evidence.json()["outcome_summary"]["denominator"] == 0

    admin = await client.get(
        f"/api/v1/admin/reports/{report_id}/evidence",
        headers={"X-Admin-Key": "test-admin-malformed-coverage"},
    )
    assert admin.status_code == 200
    assert admin.json()["total"] == 0
    assert admin.json()["items"] == []


@pytest.mark.asyncio
async def test_saved_report_evidence_is_allowlisted_redacted_and_email_is_private(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-safe-evidence")
    license_key = "safe-evidence-license"
    license_id = await create_license(key=license_key)
    coverage = {
        "findings": [{
            "finding_id": "seo.meta.description",
            "category": "technical_seo",
            "title": "Meta description review",
            "page_url": "https://shop.example/products/one?access_token=private#details",
            "evidence": "Observed api_key=synthetic-secret in diagnostic output.",
            "recommendation": "Review the page metadata.",
            "internal_secret": "must-not-leak",
            "nested_internal": {"token": "must-not-leak"},
        }],
        "check_outcomes": [
            {"check_id": "seo.title", "outcome": "pass"},
            None,
            "malformed-record",
        ],
    }
    async with AsyncSessionLocal() as db:
        report = AuditReport(
            license_id=license_id,
            domain="shop.example",
            pdf_bytes=b"%PDF-test",
            coverage_json=json.dumps(coverage),
            finding_count=1,
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)
        report_id = report.id

    headers = {"X-License-Key": license_key}
    evidence = await client.get(
        f"/api/v1/reports/{report_id}/evidence?kind=findings",
        headers=headers,
    )
    assert evidence.status_code == 200, evidence.text
    payload = evidence.json()
    serialized = json.dumps(payload)
    assert "internal_secret" not in serialized
    assert "nested_internal" not in serialized
    assert "synthetic-secret" not in serialized
    assert "access_token=private" not in serialized
    assert payload["items"][0]["finding_id"] == "seo.meta.description"
    assert payload["items"][0]["page_url"] == "https://shop.example/products/one"

    outcomes = await client.get(
        f"/api/v1/reports/{report_id}/evidence?kind=check_outcomes",
        headers=headers,
    )
    assert outcomes.status_code == 200
    assert outcomes.json()["total"] == 1
    assert outcomes.json()["outcome_summary"]["denominator"] == 1

    async def fake_send(*args, **kwargs):
        return None

    monkeypatch.setattr(main, "_send_pdf_email", fake_send)
    emailed = await client.post(
        f"/api/v1/reports/{report_id}/email",
        headers=headers,
        json={"recipient_email": "owner@example.com", "recipient_confirmed": True},
    )
    assert emailed.status_code == 200, emailed.text
    assert emailed.headers["cache-control"] == "no-store, private"


@pytest.mark.asyncio
async def test_admin_overview_search_and_pagination_are_bounded_and_keep_global_summary(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-overview-page-key")
    first_id = await create_license(key="admin-page-alpha", quota=5)
    await create_license(key="admin-page-beta", quota=5)
    await create_license(key="admin-page-gamma", quota=5)
    headers = {"X-Admin-Key": "test-admin-overview-page-key"}

    page = await client.get("/api/v1/admin/overview?limit=1&offset=0", headers=headers)
    assert page.status_code == 200, page.text
    payload = page.json()
    assert len(payload["clients"]) == 1
    assert payload["client_page"]["limit"] == 1
    assert payload["client_page"]["offset"] == 0
    assert payload["client_page"]["total"] >= 3
    assert payload["summary"]["clients_total"] >= 3

    searched = await client.get(
        f"/api/v1/admin/overview?limit=10&offset=0&search={first_id}",
        headers=headers,
    )
    assert searched.status_code == 200, searched.text
    search_payload = searched.json()
    assert [row["id"] for row in search_payload["clients"]] == [first_id]
    assert search_payload["client_page"]["total"] == 1
    assert search_payload["summary"]["clients_total"] >= 3


@pytest.mark.asyncio
async def test_admin_overview_rejects_out_of_range_page_parameters(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-overview-validation-key")
    headers = {"X-Admin-Key": "test-admin-overview-validation-key"}
    too_large = await client.get("/api/v1/admin/overview?limit=201", headers=headers)
    negative_offset = await client.get("/api/v1/admin/overview?offset=-1", headers=headers)
    assert too_large.status_code == 422
    assert negative_offset.status_code == 422


@pytest.mark.asyncio
async def test_customer_portal_exposes_explicit_disconnect_and_clears_credentials(client):
    response = await client.get("/app")
    assert response.status_code == 200
    assert 'id="disconnectAccount"' in response.text
    assert "Disconnect &amp; clear account data" in response.text or "Disconnect & clear account data" in response.text
    assert 'credential = "";' in response.text
    assert 'setAccountControls(false)' in response.text
    assert "Credentials were cleared; reconnect to continue." in response.text
    assert "Promise.allSettled([loadReports(), loadUsage(), loadApiKeys()])" in response.text
    assert 'setStatus("auditStatus", auditAccess ?' in response.text
    assert '$("runAudit").disabled = !auditAccess;' in response.text
    assert "Connected for billing. Unavailable features:" in response.text


@pytest.mark.asyncio
async def test_health_check_returns_not_ready_when_required_schema_tables_are_missing():
    class IncompleteSchemaSession:
        async def execute(self, statement):
            sql = str(statement)
            if "SELECT 1" in sql:
                return SimpleNamespace(scalar=lambda: 1)
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: ["software_licenses"]))

    with pytest.raises(HTTPException) as raised:
        await main.health_check(IncompleteSchemaSession())

    assert raised.value.status_code == 503
    assert raised.value.detail["status"] == "not_ready"
    assert raised.value.detail["db_connected"] is True
    assert raised.value.detail["schema_ready"] is False
    assert "audit_reports" in raised.value.detail["missing_tables"]
    assert "payment_webhook_events" in raised.value.detail["missing_tables"]

@pytest.mark.asyncio
async def test_health_check_returns_not_ready_when_required_schema_columns_are_missing():
    required_tables = set(main.Base.metadata.tables)
    existing_columns = [
        (table_name, column.name)
        for table_name, table in main.Base.metadata.tables.items()
        for column in table.columns
        if not (table_name == "software_licenses" and column.name == "license_key")
    ]

    class IncompleteColumnSchemaSession:
        async def execute(self, statement):
            sql = str(statement)
            if "SELECT 1" in sql:
                return SimpleNamespace(scalar=lambda: 1)
            if "information_schema.tables" in sql:
                return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: sorted(required_tables)))
            return SimpleNamespace(all=lambda: existing_columns)

    with pytest.raises(HTTPException) as raised:
        await main.health_check(IncompleteColumnSchemaSession())

    assert raised.value.status_code == 503
    assert raised.value.detail["status"] == "not_ready"
    assert raised.value.detail["db_connected"] is True
    assert raised.value.detail["schema_ready"] is False
    assert raised.value.detail["missing_tables"] == []
    assert "license_key" in raised.value.detail["missing_columns"]["software_licenses"]

@pytest.mark.asyncio
async def test_health_check_returns_not_ready_when_required_database_indexes_are_missing():
    required_tables = set(main.Base.metadata.tables)
    existing_columns = [
        (table_name, column.name)
        for table_name, table in main.Base.metadata.tables.items()
        for column in table.columns
    ]
    required_indexes = sorted({
        index.name
        for table_name in required_tables
        for index in main.Base.metadata.tables[table_name].indexes
        if index.name
    })
    assert required_indexes, "test fixture requires at least one mapped index"
    existing_indexes = [name for name in required_indexes if name != required_indexes[0]]

    class IncompleteIndexSchemaSession:
        async def execute(self, statement):
            sql = str(statement)
            if "SELECT 1" in sql:
                return SimpleNamespace(scalar=lambda: 1)
            if "information_schema.tables" in sql:
                return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: sorted(required_tables)))
            if "information_schema.columns" in sql:
                return SimpleNamespace(all=lambda: existing_columns)
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: existing_indexes))

    with pytest.raises(HTTPException) as raised:
        await main.health_check(IncompleteIndexSchemaSession())

    assert raised.value.status_code == 503
    assert raised.value.detail["status"] == "not_ready"
    assert raised.value.detail["schema_ready"] is False
    assert raised.value.detail["missing_indexes"] == [required_indexes[0]]


@pytest.mark.asyncio
async def test_paddle_payment_failure_is_recorded_without_immediately_deactivating_license(client, monkeypatch):
    secret = "paddle-test-webhook-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_payment_failure123")
    monkeypatch.setenv("LICENSE_MONTHLY_AUDITS_STARTER", "100")
    monkeypatch.setattr(main, "_send_license_email", lambda *args: None)

    async def send(event):
        body = json.dumps(event, separators=(",", ":")).encode()
        timestamp = int(time.time())
        signature = hmac.new(secret.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256).hexdigest()
        return await client.post(
            "/api/v1/billing/paddle-webhook",
            content=body,
            headers={"Paddle-Signature": f"ts={timestamp};h1={signature}"},
        )

    purchase = {
        "event_id": "evt_payment_failure_purchase",
        "event_type": "transaction.completed",
        "data": {
            "id": "txn_payment_failure_purchase",
            "subscription_id": "sub_payment_failure123",
            "status": "completed",
            "custom_data": {"license_tier": "starter"},
            "customer_id": "ctm_payment_failure123",
            "customer": {"email": "payment-failure@example.com", "name": "Payment Failure"},
            "items": [{"price": {"id": "pri_payment_failure123"}, "quantity": 1}],
        },
    }
    provision = await send(purchase)
    assert provision.status_code == 200

    failed_payment = {
        "event_id": "evt_payment_failure_attempt",
        "event_type": "transaction.payment_failed",
        "data": {
            "id": "txn_payment_failure_attempt",
            "subscription_id": "sub_payment_failure123",
            "customer_id": "ctm_payment_failure123",
            "customer": {"email": "payment-failure@example.com"},
        },
    }
    first = await send(failed_payment)
    assert first.status_code == 200
    assert first.json()["status"] == "payment_failed"
    duplicate = await send(failed_payment)
    assert duplicate.status_code == 200
    assert duplicate.json()["status"] == "already_processed"

    async with AsyncSessionLocal() as db:
        license_obj = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.client_name == "Payment Failure")
        )).scalar_one()
        assert license_obj.is_active is True
        failure_event = (await db.execute(
            select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == "evt_payment_failure_attempt")
        )).scalar_one()
        assert failure_event.status == "payment_failed"
        assert failure_event.license_id == license_obj.id


@pytest.mark.asyncio
async def test_expired_account_can_list_and_revoke_api_keys_without_audit_access(client):
    raw_key = "expired-account-key-secret"
    license_id = await create_license(
        key="expired-key-owner",
        quota=5,
        active=False,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    async with AsyncSessionLocal() as db:
        db.add(APIKey(
            license_id=license_id,
            api_key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
            key_prefix=raw_key[:10],
        ))
        await db.commit()

    headers = {"X-License-Key": "expired-key-owner"}
    listing = await client.get("/api/v1/account/api-keys", headers=headers)
    assert listing.status_code == 200
    assert len(listing.json()["items"]) == 1
    key_id = listing.json()["items"][0]["id"]
    assert "key" not in listing.json()["items"][0]

    revoke = await client.delete(f"/api/v1/account/api-keys/{key_id}", headers=headers)
    assert revoke.status_code == 200
    assert revoke.json()["status"] == "revoked"

    listing_after_revoke = await client.get("/api/v1/account/api-keys", headers=headers)
    assert listing_after_revoke.status_code == 200
    assert listing_after_revoke.json()["items"] == []


@pytest.mark.asyncio
async def test_admin_payment_event_queue_is_bounded_filterable_and_secret_minimized(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-payment-event-queue-key")
    async with AsyncSessionLocal() as db:
        db.add_all([
            PaymentWebhookEvent(
                event_id="evt_admin_queue_pending",
                status="email_pending",
                recipient_email="pending@example.com",
                transaction_id="txn_admin_queue_pending",
            ),
            PaymentWebhookEvent(
                event_id="evt_admin_queue_failed",
                status="payment_failed",
                recipient_email="failed@example.com",
                transaction_id="txn_admin_queue_failed",
            ),
            PaymentWebhookEvent(
                event_id="evt_admin_queue_delivered",
                status="delivered",
                recipient_email="delivered@example.com",
                transaction_id="txn_admin_queue_delivered",
            ),
        ])
        await db.commit()

    headers = {"X-Admin-Key": "test-payment-event-queue-key"}
    page = await client.get("/api/v1/admin/payment-events?limit=1&offset=0", headers=headers)
    assert page.status_code == 200
    assert page.json()["page"]["limit"] == 1
    assert page.json()["page"]["total"] >= 3
    assert len(page.json()["items"]) == 1
    assert page.json()["page"]["has_more"] is True
    assert "recipient_email" not in page.json()["items"][0]
    assert "license_key" not in page.json()["items"][0]

    failed = await client.get(
        "/api/v1/admin/payment-events?status=payment_failed",
        headers=headers,
    )
    assert failed.status_code == 200
    assert all(item["status"] == "payment_failed" for item in failed.json()["items"])
    assert any(item["event_id"] == "evt_admin_queue_failed" for item in failed.json()["items"])

    invalid_limit = await client.get("/api/v1/admin/payment-events?limit=101", headers=headers)
    assert invalid_limit.status_code == 422
