import asyncio
import hashlib
import hmac
import json
import time
import threading
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

import main
from database import AsyncSessionLocal
from models import APIKey, AuditLead, AuditQuotaReservation, AuditReport, PaymentWebhookEvent, SaaSAdminActionLog, SoftwareLicense
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




def test_audit_target_normalization_strips_query_and_fragment_for_provider_privacy():
    assert main.agent._normalize_audit_target(
        "https://shop.example/products?token=secret#checkout"
    ) == "https://shop.example/products"


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
    for path in ("/app", "/admin", "/checkout?_ptxn=txn_123ABC"):
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
        if path.startswith("/checkout"):
            assert "Preparing your secure Paddle checkout" in response.text


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
@pytest.mark.parametrize("path", ["/api/v1/audit-lead", "/api/v1/comprehensive-audit"])
async def test_parameterized_audit_targets_are_rejected_before_quota_reservation(client, path):
    license_key = "query-rejected-" + path.rsplit("/", 1)[-1]
    await create_license(key=license_key, quota=2)
    response = await client.post(
        path,
        params={"domain": "https://shop.example/products?token=secret"},
        headers={"X-License-Key": license_key},
    )
    assert response.status_code == 422, response.text
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
    assert response.json()["audit"]["domain"] == "https://shop.example/"
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
async def test_report_history_is_scoped_to_authenticated_license(client, monkeypatch):
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
    forbidden_evidence = await client.get(f"/api/v1/reports/{private_id}/evidence", headers=headers)
    email_called = False

    def fake_send_pdf_email(recipient, domain, report_id, pdf_bytes):
        nonlocal email_called
        email_called = True

    monkeypatch.setattr(main, "_send_pdf_email", fake_send_pdf_email)
    forbidden_email = await client.post(
        f"/api/v1/reports/{private_id}/email",
        headers=headers,
        json={"recipient_email": "recipient@example.com", "recipient_confirmed": True},
    )
    assert forbidden_pdf.status_code == 404
    assert forbidden_coverage.status_code == 404
    assert forbidden_evidence.status_code == 404
    assert forbidden_email.status_code == 404
    assert email_called is False


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
    other_license_id = await create_license(key="report-pagination-other")
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
        db.add(AuditReport(
            license_id=other_license_id,
            domain="shop-1.example",
            pdf_bytes=b"%PDF-other",
            coverage_json="{}",
            finding_count=99,
            created_at=datetime.now(timezone.utc) + timedelta(days=1),
        ))
        await db.commit()

    headers = {"X-License-Key": "report-pagination-owner"}
    first = await client.get("/api/v1/reports?limit=2&offset=0", headers=headers)
    second = await client.get("/api/v1/reports?limit=2&offset=2", headers=headers)
    filtered = await client.get("/api/v1/reports?limit=10&offset=0&domain=SHOP-1.EXAMPLE", headers=headers)
    wildcard = await client.get("/api/v1/reports?domain=%25", headers=headers)
    assert first.status_code == second.status_code == filtered.status_code == wildcard.status_code == 200
    first_data, second_data = first.json(), second.json()
    assert first_data["total"] == second_data["total"] == 3
    assert len(first_data["reports"]) == 2
    assert len(second_data["reports"]) == 1
    first_ids = {row["id"] for row in first_data["reports"]}
    second_ids = {row["id"] for row in second_data["reports"]}
    assert first_ids.isdisjoint(second_ids)
    assert filtered.json()["total"] == 1
    assert filtered.json()["domain"] == "shop-1.example"
    assert filtered.json()["reports"][0]["domain"] == "shop-1.example"
    assert wildcard.json()["total"] == 3
    assert wildcard.json()["domain"] == ""
    assert all(row["finding_count"] != 99 for row in filtered.json()["reports"])
    assert (await client.get("/api/v1/reports?offset=10000001", headers=headers)).status_code == 422


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
@pytest.mark.parametrize("recipient", ["", "x", "a" * 255])
async def test_report_email_rejects_invalid_length_before_smtp(client, monkeypatch, recipient):
    license_id = await create_license(key="email-report-invalid-length")
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

    sent = []
    monkeypatch.setattr(
        main, "_send_pdf_email",
        lambda *args: sent.append(args),
    )
    response = await client.post(
        f"/api/v1/reports/{report_id}/email",
        headers={"X-License-Key": "email-report-invalid-length"},
        json={"recipient_email": recipient, "recipient_confirmed": True},
    )
    assert response.status_code == 422
    assert sent == []


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
async def test_paddle_webhook_rejects_valid_json_with_invalid_object_shapes(client, monkeypatch):
    secret = "paddle-test-webhook-shape-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)

    async def send(payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        timestamp = int(time.time())
        signature = hmac.new(secret.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256).hexdigest()
        return await client.post(
            "/api/v1/billing/paddle-webhook",
            content=body,
            headers={"Paddle-Signature": f"ts={timestamp};h1={signature}"},
        )

    top_level_list = await send(["not", "an", "event-object"])
    assert top_level_list.status_code == 400
    assert top_level_list.json()["detail"] == "Paddle event must be a JSON object."

    invalid_data = await send({
        "event_id": "evt_invalid_data_shape",
        "event_type": "transaction.completed",
        "data": ["not", "an", "object"],
    })
    assert invalid_data.status_code == 400
    assert invalid_data.json()["detail"] == "Paddle event data must be a JSON object."

    missing_type = await send({"event_id": "evt_missing_type", "data": {}})
    assert missing_type.status_code == 400
    assert missing_type.json()["detail"] == "Paddle event type is missing or invalid."

    oversized_id = await send({
        "event_id": "evt_" + ("x" * 252),
        "event_type": "transaction.completed",
        "data": {},
    })
    assert oversized_id.status_code == 400
    assert oversized_id.json()["detail"] == "Paddle event ID is missing or invalid."

    invalid_custom_data = await send({
        "event_id": "evt_invalid_custom_data_shape",
        "event_type": "transaction.completed",
        "data": {"status": "completed", "custom_data": ["not", "an", "object"]},
    })
    assert invalid_custom_data.status_code == 400
    assert invalid_custom_data.json()["detail"] == "Paddle transaction custom_data must be a JSON object."

    invalid_items = await send({
        "event_id": "evt_invalid_items_shape",
        "event_type": "transaction.completed",
        "data": {"status": "completed", "custom_data": {}, "items": {"not": "an array"}},
    })
    assert invalid_items.status_code == 400
    assert invalid_items.json()["detail"] == "Paddle transaction items must be a JSON array."

    invalid_customer = await send({
        "event_id": "evt_invalid_customer_shape",
        "event_type": "transaction.completed",
        "data": {
            "status": "completed",
            "custom_data": {},
            "customer": ["not", "an", "object"],
            "items": [],
        },
    })
    assert invalid_customer.status_code == 400
    assert invalid_customer.json()["detail"] == "Paddle transaction customer must be a JSON object."


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
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_laterenewal123")
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
            "items": [{"price": {"id": "pri_laterenewal123"}, "quantity": 1}],
        },
    }
    purchase_response = await send(purchase)
    assert purchase_response.status_code == 200, purchase_response.text

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
            "items": [{"price": {"id": "pri_laterenewal123"}, "quantity": 1}],
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
    assert len(events) == 3
    statuses = {item.event_id: item.status for item in events}
    assert statuses["evt_late_renewal_purchase"] == "delivered"
    assert statuses["evt_late_renewal_cancel"] == "subscription_canceled"
    assert statuses["evt_late_renewal_paid_late"] == "subscription_canceled"


@pytest.mark.asyncio
async def test_payment_failure_after_cancellation_cannot_hide_canceled_state(client, monkeypatch):
    secret = "paddle-test-webhook-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_cancel_failure123")
    monkeypatch.setenv("LICENSE_MONTHLY_AUDITS_STARTER", "100")
    # Keep this lifecycle test independent of package rows left by other billing tests.
    async def configured_test_plan(db, active_only=True):
        return [{
            "tier": "starter", "label": "Starter",
            "monthly_audit_allowance": 100, "max_concurrent_audits": 1,
            "price_id": "pri_cancel_failure123", "is_active": True,
        }]
    monkeypatch.setattr(main, "_db_payment_plans", configured_test_plan)
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
        "event_id": "evt_cancel_failure_purchase",
        "event_type": "transaction.completed",
        "data": {
            "id": "txn_cancel_failure_purchase",
            "subscription_id": "sub_cancel_failure123",
            "status": "completed",
            "custom_data": {"license_tier": "starter"},
            "customer_id": "ctm_cancel_failure123",
            "customer": {"email": "cancel-failure@example.com", "name": "Cancel Failure"},
            "items": [{"price": {"id": "pri_cancel_failure123"}, "quantity": 1}],
        },
    }
    purchase_response = await send(purchase)
    assert purchase_response.status_code == 200, purchase_response.text

    cancellation = {
        "event_id": "evt_cancel_failure_canceled",
        "event_type": "subscription.canceled",
        "data": {"id": "sub_cancel_failure123"},
    }
    assert (await send(cancellation)).json()["status"] == "cancellation_applied"

    # A later failure event is still recorded for billing history, but must not
    # erase the cancellation state used to guard subsequent completed transactions.
    failure = {
        "event_id": "evt_cancel_failure_payment_failed",
        "event_type": "transaction.payment_failed",
        "data": {
            "id": "txn_cancel_failure_attempt",
            "subscription_id": "sub_cancel_failure123",
            "customer_id": "ctm_cancel_failure123",
            "customer": {"email": "cancel-failure@example.com"},
        },
    }
    failed = await send(failure)
    assert failed.status_code == 200, failed.text
    assert failed.json()["status"] == "payment_failed"

    late_renewal = {
        "event_id": "evt_cancel_failure_late_renewal",
        "event_type": "transaction.completed",
        "data": {
            "id": "txn_cancel_failure_late_renewal",
            "subscription_id": "sub_cancel_failure123",
            "status": "completed",
            "custom_data": {"license_tier": "starter"},
            "customer_id": "ctm_cancel_failure123",
            "customer": {"email": "cancel-failure@example.com", "name": "Cancel Failure"},
            "items": [{"price": {"id": "pri_cancel_failure123"}, "quantity": 1}],
        },
    }
    response = await send(late_renewal)
    assert response.status_code == 200
    assert response.json()["status"] == "subscription_canceled"

    async with AsyncSessionLocal() as db:
        license_obj = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.client_name == "Cancel Failure")
        )).scalar_one()
        assert license_obj.is_active is False
        events = (await db.execute(
            select(PaymentWebhookEvent).where(
                PaymentWebhookEvent.subscription_id == "sub_cancel_failure123"
            )
        )).scalars().all()
    assert len(events) == 4
    statuses = {item.event_id: item.status for item in events}
    assert statuses["evt_cancel_failure_canceled"] == "subscription_canceled"
    assert statuses["evt_cancel_failure_payment_failed"] == "payment_failed"
    assert statuses["evt_cancel_failure_late_renewal"] == "subscription_canceled"
    # Re-delivery of the same late transaction is idempotent and does not add a
    # second history record or reactivate the canceled license.
    repeated = await send(late_renewal)
    assert repeated.status_code == 200
    assert repeated.json()["status"] == "already_processed"


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



@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://pay.paddle.com/checkout/test", True),
        ("https://paddle.com/portal", True),
        ("https://CUSTOMER.PADDLE.COM/portal", True),
        ("https://evil.example/portal", False),
        ("https://paddle.com.evil.example/portal", False),
        ("https://user:password@pay.paddle.com/portal", False),
        ("https://@pay.paddle.com/portal", False),
        ("http://pay.paddle.com/portal", False),
        ("javascript:alert(1)", False),
        ("https://pay.paddle.com:bad/portal", False),
        (" https://pay.paddle.com/portal", False),
        (None, False),
        ({"url": "https://pay.paddle.com"}, False),
    ],
)
def test_paddle_hosted_url_validator(url, expected):
    assert main._is_valid_paddle_hosted_url(url) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "configured_url",
    [
        "https://evil.example/checkout",
        "https://paddle.com.evil.example/checkout",
        "https://user:password@pay.paddle.com/checkout",
        "http://pay.paddle.com/checkout",
    ],
)
async def test_paddle_checkout_rejects_untrusted_configured_checkout_url(client, monkeypatch, configured_url):
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", "test-webhook-secret")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_01abc123")
    monkeypatch.setenv("PADDLE_CHECKOUT_URL", configured_url)
    called = False

    def fake_request(path, method="GET", payload=None):
        nonlocal called
        called = True
        return {"data": {"id": "txn_01abc123", "checkout": {"url": "https://pay.paddle.com/checkout/test"}}}

    monkeypatch.setattr(main, "_paddle_api_request", fake_request)
    response = await client.post("/api/v1/billing/checkout", json={"tier": "starter"})
    assert response.status_code == 503
    assert response.json()["detail"] == "Paddle checkout URL configuration is invalid."
    assert called is False


@pytest.mark.asyncio
async def test_paddle_checkout_uses_server_configured_price(client, monkeypatch):
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", "test-webhook-secret")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_01abc123")
    captured = {}
    def fake_request(path, method="GET", payload=None):
        captured.update({"path": path, "method": method, "payload": payload})
        return {"data": {"id": "txn_01abc123", "checkout": {"url": "https://pay.paddle.com/checkout/test"}}}
    monkeypatch.setattr(main, "_paddle_api_request", fake_request)
    response = await client.post("/api/v1/billing/checkout", json={"tier": "starter"})
    assert response.status_code == 200 and response.json()["checkout_url"] == "https://pay.paddle.com/checkout/test"
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
    assert captured["payload"]["items"] == [{"price_id": "pri_01abc123", "quantity": 1}]
    assert captured["payload"]["custom_data"]["license_tier"] == "starter"
    assert (await client.post("/api/v1/billing/checkout", json={"tier": "made-up"})).status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing_setting",
    ["PADDLE_WEBHOOK_SECRET", "SMTP_HOST", "SMTP_FROM"],
)
async def test_paddle_checkout_fails_closed_when_purchase_fulfillment_is_not_ready(
    client, monkeypatch, missing_setting
):
    async def configured_test_plan(db, active_only=True):
        return [{
            "tier": "starter", "label": "Starter",
            "monthly_audit_allowance": 100, "max_concurrent_audits": 1,
            "price_id": "pri_checkout_readiness123", "is_active": True,
        }]
    monkeypatch.setattr(main, "_db_payment_plans", configured_test_plan)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_checkout_readiness123")
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", "test-webhook-secret")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    monkeypatch.delenv(missing_setting, raising=False)
    called = False

    def fake_request(path, method="GET", payload=None):
        nonlocal called
        called = True
        return {"data": {"id": "txn_checkout_readiness123", "checkout": {
            "url": "https://pay.paddle.com/checkout/test"
        }}}

    monkeypatch.setattr(main, "_paddle_api_request", fake_request)
    response = await client.post("/api/v1/billing/checkout", json={"tier": "starter"})
    assert response.status_code == 503
    assert called is False


@pytest.mark.asyncio
async def test_paddle_checkout_accepts_trusted_configured_checkout_url(client, monkeypatch):
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", "test-webhook-secret")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_01abc123")
    monkeypatch.setenv("PADDLE_CHECKOUT_URL", "https://pay.paddle.com/checkout")
    captured = {}

    def fake_request(path, method="GET", payload=None):
        captured.update({"path": path, "method": method, "payload": payload})
        return {"data": {"id": "txn_01abc123", "checkout": {"url": "https://pay.paddle.com/checkout/test"}}}

    monkeypatch.setattr(main, "_paddle_api_request", fake_request)
    response = await client.post("/api/v1/billing/checkout", json={"tier": "starter"})
    assert response.status_code == 200
    assert captured["payload"]["checkout"] == {"url": "https://pay.paddle.com/checkout"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "checkout_url",
    [
        "https://evil.example/checkout",
        "https://paddle.com.evil.example/checkout",
        "https://user:password@pay.paddle.com/checkout",
        "http://pay.paddle.com/checkout",
        "javascript:alert(1)",
    ],
)
async def test_paddle_checkout_rejects_untrusted_checkout_destinations(client, monkeypatch, checkout_url):
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", "test-webhook-secret")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_01abc123")

    def fake_request(path, method="GET", payload=None):
        return {"data": {"id": "txn_01abc123", "checkout": {"url": checkout_url}}}

    monkeypatch.setattr(main, "_paddle_api_request", fake_request)
    response = await client.post("/api/v1/billing/checkout", json={"tier": "starter"})
    assert response.status_code == 502
    assert response.json()["detail"] == "Unable to start Paddle checkout; verify billing configuration."


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
    oversized_offset = await client.get(
        f"/api/v1/admin/reports/{report_id}/evidence?offset=10000001",
        headers={"X-Admin-Key": "test-admin-evidence-key"},
    )
    assert oversized_offset.status_code == 422

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
    oversized_customer_offset = await client.get(
        f"/api/v1/reports/{report_id}/evidence?offset=10000001",
        headers=headers,
    )
    assert oversized_customer_offset.status_code == 422

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
    assert "Promise.allSettled([loadReports(), loadUsage(), loadApiKeys(), loadActivity(), loadProfile()])" in response.text
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
async def test_paddle_past_due_retries_until_subscription_is_linked_and_deduplicates(client, monkeypatch):
    secret = "paddle-test-past-due-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_pastdue123")
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

    # A lifecycle event that arrives before purchase reconciliation must remain
    # retryable rather than being acknowledged and lost.
    early_past_due = {
        "event_id": "evt_past_due_before_purchase",
        "event_type": "subscription.past_due",
        "data": {"id": "sub_past_due_retry", "customer_id": "ctm_past_due"},
    }
    early = await send(early_past_due)
    assert early.status_code == 503
    assert early.json()["detail"] == "Payment-failure event is awaiting subscription reconciliation."

    purchase = {
        "event_id": "evt_past_due_purchase",
        "event_type": "transaction.completed",
        "data": {
            "id": "txn_past_due_purchase",
            "subscription_id": "sub_past_due_retry",
            "status": "completed",
            "custom_data": {"license_tier": "starter"},
            "customer_id": "ctm_past_due",
            "customer": {"email": "past-due@example.com", "name": "Past Due Customer"},
            "items": [{"price": {"id": "pri_pastdue123"}, "quantity": 1}],
        },
    }
    provision = await send(purchase)
    assert provision.status_code == 200

    first = await send(early_past_due)
    assert first.status_code == 200
    assert first.json()["status"] == "subscription_past_due"

    # Replaying the same provider event ID is idempotent. Distinct event IDs
    # are retained because a subscription can legitimately enter past-due state
    # more than once across separate billing cycles.
    duplicate = await send(early_past_due)
    assert duplicate.status_code == 200
    assert duplicate.json() == {
        "status": "already_processed",
        "event_id": "evt_past_due_before_purchase",
    }

    async with AsyncSessionLocal() as db:
        license_obj = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.client_name == "Past Due Customer")
        )).scalar_one()
        assert license_obj.is_active is True
        past_due_events = (await db.execute(
            select(PaymentWebhookEvent).where(
                PaymentWebhookEvent.subscription_id == "sub_past_due_retry",
                PaymentWebhookEvent.status == "subscription_past_due",
            )
        )).scalars().all()
        assert len(past_due_events) == 1

@pytest.mark.asyncio
async def test_paddle_payment_failure_is_recorded_without_immediately_deactivating_license(client, monkeypatch):
    secret = "paddle-test-webhook-secret"
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", secret)
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_test_key")
    monkeypatch.setenv("PADDLE_PRICE_ID_STARTER", "pri_paymentfailure123")
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
            "items": [{"price": {"id": "pri_paymentfailure123"}, "quantity": 1}],
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

    # Distinct Paddle event IDs for the same failed transaction must not create
    # duplicate lifecycle records or operation events.
    duplicate_delivery = {**failed_payment, "event_id": "evt_payment_failure_attempt_redelivered"}
    redelivered = await send(duplicate_delivery)
    assert redelivered.status_code == 200
    assert redelivered.json() == {
        "status": "already_processed",
        "event_id": "evt_payment_failure_attempt",
    }

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
    assert listing.json()["max_keys"] == 10
    assert listing.json()["key_count"] == 1
    assert listing.json()["keys_remaining"] == 9
    assert listing.json()["can_create"] is False
    key_id = listing.json()["items"][0]["id"]
    assert "key" not in listing.json()["items"][0]

    # The UI is not the security boundary: direct API requests must also be denied.
    creation = await client.post("/api/v1/account/api-keys", headers=headers)
    assert creation.status_code == 402
    async with AsyncSessionLocal() as db:
        remaining_keys = (await db.execute(
            select(APIKey).where(APIKey.license_id == license_id)
        )).scalars().all()
        assert len(remaining_keys) == 1

    revoke = await client.delete(f"/api/v1/account/api-keys/{key_id}", headers=headers)
    assert revoke.status_code == 200
    assert revoke.json()["status"] == "revoked"

    listing_after_revoke = await client.get("/api/v1/account/api-keys", headers=headers)
    assert listing_after_revoke.status_code == 200
    assert listing_after_revoke.json()["items"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_payload", [
    [],
    {"data": []},
    {"data": {"id": "txn_reconcile_shape", "details": []}},
    {"data": {"id": "txn_reconcile_shape", "details": {"totals": []}}},
])
async def test_admin_payment_reconciliation_rejects_malformed_provider_shapes(client, monkeypatch, provider_payload):
    monkeypatch.setenv("ADMIN_API_KEY", "test-reconcile-shape-key")
    monkeypatch.setenv("PADDLE_API_KEY", "pdl_test_key")
    async with AsyncSessionLocal() as db:
        db.add(PaymentWebhookEvent(
            event_id="evt_reconcile_shape",
            status="payment_failed",
            recipient_email="reconcile-shape@example.com",
            transaction_id="txn_reconcile_shape",
        ))
        await db.commit()

    monkeypatch.setattr(main, "_paddle_api_request", lambda *args, **kwargs: provider_payload)
    response = await client.post(
        "/api/v1/admin/payment-events/evt_reconcile_shape/reconcile",
        headers={"X-Admin-Key": "test-reconcile-shape-key"},
    )
    assert response.status_code == 502, response.text
    assert "Paddle returned" in response.json()["detail"]
    async with AsyncSessionLocal() as db:
        event = (await db.execute(
            select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == "evt_reconcile_shape")
        )).scalar_one()
        assert event.subscription_id is None
        assert event.paddle_customer_id is None


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


@pytest.mark.asyncio
async def test_admin_overview_filters_clients_by_status_and_package(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-filter-key")
    headers = {"X-Admin-Key": "test-admin-filter-key"}
    await create_license(key="filter-active", quota=5)
    await create_license(key="filter-expired", quota=5, expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    await create_license(key="filter-inactive", quota=20, active=False)
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        active = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.license_key == "filter-active"))).scalar_one()
        active.client_name = "Filter Active"
        active.tier = "starter"
        expired = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.license_key == "filter-expired"))).scalar_one()
        expired.client_name = "Filter Expired"
        expired.tier = "starter"
        inactive = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.license_key == "filter-inactive"))).scalar_one()
        inactive.client_name = "Filter Inactive"
        inactive.tier = "growth"
        await db.commit()

    active_page = await client.get("/api/v1/admin/overview?client_status=active&tier_filter=starter", headers=headers)
    assert active_page.status_code == 200, active_page.text
    assert {row["client_name"] for row in active_page.json()["clients"]} == {"Filter Active"}
    assert active_page.json()["client_page"]["status"] == "active"
    expired_page = await client.get("/api/v1/admin/overview?client_status=expired", headers=headers)
    assert expired_page.status_code == 200, expired_page.text
    assert {row["client_name"] for row in expired_page.json()["clients"]} == {"Filter Expired"}
    inactive_page = await client.get("/api/v1/admin/overview?client_status=inactive", headers=headers)
    assert inactive_page.status_code == 200, inactive_page.text
    assert {row["client_name"] for row in inactive_page.json()["clients"]} == {"Filter Inactive"}
    exact_tier = await client.get("/api/v1/admin/overview?tier_filter=STARTER", headers=headers)
    wildcard_tier = await client.get("/api/v1/admin/overview?tier_filter=%25", headers=headers)
    assert exact_tier.status_code == wildcard_tier.status_code == 200
    assert {row["client_name"] for row in exact_tier.json()["clients"]} == {"Filter Active", "Filter Expired"}
    assert wildcard_tier.json()["clients"] == []


@pytest.mark.asyncio
async def test_customer_audit_activity_is_paginated_scoped_and_minimizes_sensitive_fields(client):
    owner_id = await create_license(key="activity-owner")
    other_id = await create_license(key="activity-other")
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        db.add_all([
            AuditLead(license_id=owner_id, domain="first.example", mobile_score=80, speed_index_sec=2.2,
                      contact_email="private@example.com", revenue_leak_hypothesis="private pitch", email_body="secret body",
                      source_channel="customer_portal", created_at=now - timedelta(minutes=1)),
            AuditLead(license_id=owner_id, domain="second.example", mobile_score=60, speed_index_sec=4.5,
                      contact_email="other-private@example.com", revenue_leak_hypothesis="other pitch",
                      source_channel="api", created_at=now),
            AuditLead(license_id=other_id, domain="must-not-leak.example", mobile_score=99, speed_index_sec=1.0,
                      created_at=now),
        ])
        await db.commit()

    response = await client.get(
        "/api/v1/account/activity?limit=1&offset=0",
        headers={"X-License-Key": "activity-owner"},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["page"] == {"limit": 1, "offset": 0, "total": 2, "has_more": True, "domain": ""}
    assert len(data["items"]) == 1
    assert data["items"][0]["domain"] == "second.example"
    assert "contact_email" not in data["items"][0]
    assert "revenue_leak_hypothesis" not in data["items"][0]
    assert "email_body" not in data["items"][0]
    assert "must-not-leak.example" not in response.text
    assert response.headers["cache-control"] == "no-store, private"

    second_page = await client.get(
        "/api/v1/account/activity?limit=1&offset=1",
        headers={"X-License-Key": "activity-owner"},
    )
    assert second_page.status_code == 200
    assert second_page.json()["items"][0]["domain"] == "first.example"
    assert second_page.json()["page"]["has_more"] is False

    filtered = await client.get(
        "/api/v1/account/activity?domain=SECOND&limit=20&offset=0",
        headers={"X-License-Key": "activity-owner"},
    )
    assert filtered.status_code == 200
    assert filtered.json()["page"]["total"] == 1
    assert filtered.json()["page"]["domain"] == "second"
    assert [item["domain"] for item in filtered.json()["items"]] == ["second.example"]


@pytest.mark.asyncio
async def test_customer_audit_activity_requires_auth_and_bounds_pagination(client):
    unauthenticated = await client.get("/api/v1/account/activity")
    assert unauthenticated.status_code == 401
    license_id = await create_license(key="activity-bounds")
    del license_id
    headers = {"X-License-Key": "activity-bounds"}
    invalid_limit = await client.get("/api/v1/account/activity?limit=101", headers=headers)
    invalid_offset = await client.get("/api/v1/account/activity?offset=-1", headers=headers)
    assert invalid_limit.status_code == 422
    assert invalid_offset.status_code == 422


@pytest.mark.asyncio
async def test_customer_billing_history_is_paginated_scoped_and_validated(client):
    owner_id = await create_license(key="billing-history-owner")
    other_id = await create_license(key="billing-history-other")
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        db.add_all([
            PaymentWebhookEvent(event_id="evt_billing_owner_a", license_id=owner_id, status="delivered", recipient_email="owner@example.com",
                                transaction_id="txn-owner-a", created_at=now - timedelta(minutes=2)),
            PaymentWebhookEvent(event_id="evt_billing_owner_b", license_id=owner_id, status="payment_failed", recipient_email="owner@example.com",
                                transaction_id="txn-owner-b", created_at=now - timedelta(minutes=1)),
            PaymentWebhookEvent(event_id="evt_billing_owner_c", license_id=owner_id, status="delivered", recipient_email="owner@example.com",
                                transaction_id="txn-owner-c", created_at=now),
            PaymentWebhookEvent(event_id="evt_billing_other_private", license_id=other_id, status="delivered", recipient_email="other@example.com",
                                transaction_id="txn-other-secret", created_at=now),
        ])
        await db.commit()

    headers = {"X-License-Key": "billing-history-owner"}
    first = await client.get("/api/v1/account/billing-history?limit=2&offset=0", headers=headers)
    assert first.status_code == 200, first.text
    data = first.json()
    assert data["page"] == {"limit": 2, "offset": 0, "total": 3, "has_more": True}
    assert [item["event_id"] for item in data["items"]] == ["evt_billing_owner_c", "evt_billing_owner_b"]
    assert all("recipient_email" not in item and "paddle_customer_id" not in item for item in data["items"])
    assert "owner@example.com" not in first.text
    assert "evt_billing_other_private" not in first.text
    assert "txn-other-secret" not in first.text
    assert "other@example.com" not in first.text
    assert first.headers["cache-control"] == "no-store, private"

    second = await client.get("/api/v1/account/billing-history?limit=2&offset=2", headers=headers)
    assert second.status_code == 200
    assert [item["event_id"] for item in second.json()["items"]] == ["evt_billing_owner_a"]
    assert second.json()["page"]["has_more"] is False

    assert (await client.get("/api/v1/account/billing-history")).status_code == 401
    assert (await client.get("/api/v1/account/billing-history?limit=101", headers=headers)).status_code == 422
    assert (await client.get("/api/v1/account/billing-history?offset=-1", headers=headers)).status_code == 422


@pytest.mark.asyncio
async def test_admin_action_history_is_paginated_and_validated(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-actions-pagination")
    async with AsyncSessionLocal() as db:
        db.add_all([
            SaaSAdminActionLog(action="package_created", entity_type="package", entity_id="starter",
                               details_json='{"tier":"starter"}'),
            SaaSAdminActionLog(action="client_updated", entity_type="client", entity_id="12",
                               details_json='{"field":"is_active"}'),
            SaaSAdminActionLog(action="key_revoked", entity_type="api_key", entity_id="31",
                               details_json='{"reason":"rotation"}'),
        ])
        await db.commit()

    headers = {"X-Admin-Key": "test-admin-actions-pagination"}
    first = await client.get("/api/v1/admin/actions?limit=2&offset=0", headers=headers)
    assert first.status_code == 200, first.text
    assert first.headers["cache-control"] == "no-store, private"
    assert first.headers["pragma"] == "no-cache"
    payload = first.json()
    assert payload["page"]["limit"] == 2
    assert payload["page"]["offset"] == 0
    assert payload["page"]["total"] >= 3
    assert payload["page"]["has_more"] is True
    assert len(payload["actions"]) == 2
    assert payload["actions"][0]["id"] > payload["actions"][1]["id"]

    second = await client.get("/api/v1/admin/actions?limit=2&offset=2", headers=headers)
    assert second.status_code == 200
    second_data = second.json()
    assert len(second_data["actions"]) >= 1
    assert second_data["page"]["has_more"] == (second_data["page"]["offset"] + len(second_data["actions"]) < second_data["page"]["total"])

    assert (await client.get("/api/v1/admin/actions")).status_code == 401
    assert (await client.get("/api/v1/admin/actions?limit=201", headers=headers)).status_code == 422
    assert (await client.get("/api/v1/admin/actions?offset=-1", headers=headers)).status_code == 422


async def test_admin_action_history_tolerates_malformed_legacy_details_and_redacts_secrets(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-actions-legacy")
    async with AsyncSessionLocal() as db:
        db.add_all([
            SaaSAdminActionLog(
                action="legacy_malformed", entity_type="system", entity_id="legacy-malformed",
                details_json="{not valid json",
            ),
            SaaSAdminActionLog(
                action="legacy_sensitive", entity_type="system", entity_id="legacy-sensitive",
                details_json='{"api_key":"super-secret-value","note":"password=hunter2","nested":{"access_token":"abc123"}}',
            ),
        ])
        await db.commit()

    response = await client.get(
        "/api/v1/admin/actions?limit=200&offset=0",
        headers={"X-Admin-Key": "test-admin-actions-legacy"},
    )
    assert response.status_code == 200, response.text
    by_entity = {item["entity_id"]: item for item in response.json()["actions"]}
    malformed = by_entity["legacy-malformed"]["details"]
    assert "invalid" in malformed["_warning"].lower()
    sensitive = by_entity["legacy-sensitive"]["details"]
    assert sensitive["api_key"] == "[REDACTED]"
    assert sensitive["nested"]["access_token"] == "[REDACTED]"
    assert "hunter2" not in sensitive["note"]



@pytest.mark.parametrize("value", [
    "http://127.0.0.1/private",
    "http://10.0.0.4/internal",
    "http://[::1]/admin",
    "http://169.254.169.254/latest/meta-data",
    "https://localhost/private",
    "https://service.internal/debug",
    "https://store.local/account",
    "https://shop.example.test/private",
])
def test_audit_metadata_url_excludes_private_or_nonpublic_hosts(value):
    assert main._safe_audit_metadata_url(value) is None


@pytest.mark.parametrize("value,expected", [
    ("HTTPS://Shop.Example/products?token=private#details", "https://shop.example/products"),
    ("https://shop.example:8443/products?session=secret", "https://shop.example:8443/products"),
    ("https://[2606:4700:4700::1111]/?token=secret", "https://[2606:4700:4700::1111]/"),
])
def test_audit_metadata_url_preserves_public_targets_and_redacts_secrets(value, expected):
    assert main._safe_audit_metadata_url(value) == expected


def test_payment_webhook_migration_matches_current_model_columns_and_indexes():
    migration = Path(__file__).resolve().parents[1] / "migrations" / "2026-10-22-audit-reports.sql"
    sql = migration.read_text(encoding="utf-8").lower()

    for column in ("transaction_id", "subscription_id", "paddle_customer_id"):
        assert f"add column if not exists {column} varchar(100) null" in sql
        assert f"ix_payment_webhook_events_{column}" in sql




@pytest.mark.asyncio
async def test_admin_client_api_key_lifecycle_is_scoped_auditable_and_secret_minimized(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-client-key-lifecycle")
    first_client_id = await create_license(key="admin-key-owner-one")
    second_client_id = await create_license(key="admin-key-owner-two")
    headers = {"X-Admin-Key": "test-admin-client-key-lifecycle"}

    created = await client.post(
        f"/api/v1/admin/clients/{first_client_id}/api-keys",
        headers=headers,
        json={"client_id": first_client_id, "label": "integration key"},
    )
    assert created.status_code == 201
    secret = created.json()["key"]
    key_id = created.json()["id"]
    assert secret.startswith("eaa_")
    assert created.headers["cache-control"] == "no-store, private"

    listed = await client.get(
        f"/api/v1/admin/clients/{first_client_id}/api-keys",
        headers=headers,
    )
    assert listed.status_code == 200
    assert listed.headers["cache-control"] == "no-store, private"
    assert len(listed.json()["items"]) == 1
    assert listed.json()["items"][0]["id"] == key_id
    assert listed.json()["items"][0]["key_prefix"] == secret[:10]
    assert secret not in listed.text
    assert "api_key_hash" not in listed.text

    foreign_revoke = await client.request(
        "DELETE", f"/api/v1/admin/clients/{second_client_id}/api-keys/{key_id}",
        headers=headers, json={"reason": "must not cross client boundary"},
    )
    assert foreign_revoke.status_code == 404

    revoked = await client.request(
        "DELETE", f"/api/v1/admin/clients/{first_client_id}/api-keys/{key_id}",
        headers=headers, json={"reason": "rotation after integration test"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    after_revoke = await client.get(
        f"/api/v1/admin/clients/{first_client_id}/api-keys",
        headers=headers,
    )
    assert after_revoke.status_code == 200
    assert after_revoke.json()["items"] == []

    async with AsyncSessionLocal() as db:
        actions = (await db.execute(
            select(SaaSAdminActionLog).where(
                SaaSAdminActionLog.entity_id == str(first_client_id),
                SaaSAdminActionLog.action.in_([
                    "client.api_key_created",
                    "client.api_key_revoked",
                ]),
            ).order_by(SaaSAdminActionLog.id.asc())
        )).scalars().all()
        assert [item.action for item in actions] == [
            "client.api_key_created",
            "client.api_key_revoked",
        ]
        details = [json.loads(item.details_json) if isinstance(item.details_json, str) else item.details_json for item in actions]
        assert details[1]["reason"] == "rotation after integration test"
        assert all(secret not in json.dumps(item) for item in details)

@pytest.mark.asyncio
async def test_account_api_key_creation_enforces_ten_key_cap(client):
    license_id = await create_license(key="api-key-cap-license", quota=5)
    async with AsyncSessionLocal() as db:
        db.add_all([
            APIKey(
                license_id=license_id,
                api_key_hash=hashlib.sha256(f"existing-api-key-{i}".encode()).hexdigest(),
                key_prefix=f"eaa_{i:04d}",
            )
            for i in range(10)
        ])
        await db.commit()

    response = await client.post(
        "/api/v1/account/api-keys",
        headers={"X-License-Key": "api-key-cap-license"},
    )
    assert response.status_code == 409
    assert "10 API keys" in response.json()["detail"]
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(APIKey).where(APIKey.license_id == license_id)
        )).scalars().all()
        assert len(rows) == 10

@pytest.mark.asyncio
async def test_admin_api_key_creation_enforces_same_ten_key_cap(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-key-cap")
    license_id = await create_license(key="admin-api-key-cap-license", quota=5)
    async with AsyncSessionLocal() as db:
        db.add_all([
            APIKey(
                license_id=license_id,
                api_key_hash=hashlib.sha256(f"admin-existing-key-{i}".encode()).hexdigest(),
                key_prefix=f"eaa_a{i:03d}",
            )
            for i in range(10)
        ])
        await db.commit()

    response = await client.post(
        f"/api/v1/admin/clients/{license_id}/api-keys",
        headers={"X-Admin-Key": "test-admin-key-cap"},
        json={"client_id": license_id, "label": "cap regression"},
    )
    assert response.status_code == 409
    assert "10 API keys" in response.json()["detail"]
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(APIKey).where(APIKey.license_id == license_id)
        )).scalars().all()
        assert len(rows) == 10


@pytest.mark.asyncio
async def test_customer_profile_update_is_scoped_private_and_rejects_blank_names(client):
    owner_id = await create_license(key="profile-owner")
    other_id = await create_license(key="profile-other")
    async with AsyncSessionLocal() as db:
        owner = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.id == owner_id))).scalar_one()
        owner.client_name = "Original Customer"
        other = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.id == other_id))).scalar_one()
        other.client_name = "Other Customer"
        await db.commit()

    headers = {"X-License-Key": "profile-owner"}
    updated = await client.patch(
        "/api/v1/account/profile",
        headers=headers,
        json={"client_name": "  Updated Store  "},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json() == {"client_name": "Updated Store", "updated": True}
    assert updated.headers["cache-control"] == "no-store, private"
    assert updated.headers["pragma"] == "no-cache"

    profile = await client.get("/api/v1/account/profile", headers=headers)
    assert profile.status_code == 200, profile.text
    assert profile.json()["client_name"] == "Updated Store"
    assert "license_key" not in profile.json()
    assert "api_key" not in profile.json()
    assert profile.headers["cache-control"] == "no-store, private"

    blank = await client.patch(
        "/api/v1/account/profile",
        headers=headers,
        json={"client_name": "   "},
    )
    assert blank.status_code == 422

    too_long = await client.patch(
        "/api/v1/account/profile",
        headers=headers,
        json={"client_name": "x" * 256},
    )
    assert too_long.status_code == 422

    async with AsyncSessionLocal() as db:
        owner = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.id == owner_id))).scalar_one()
        other = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.id == other_id))).scalar_one()
        assert owner.client_name == "Updated Store"
        assert other.client_name == "Other Customer"

    assert (await client.get("/api/v1/account/profile")).status_code == 401


@pytest.mark.asyncio
async def test_expired_customer_can_open_only_a_valid_paddle_billing_portal(client, monkeypatch):
    from datetime import timedelta
    from database import AsyncSessionLocal
    from models import PaymentWebhookEvent, SoftwareLicense
    from sqlalchemy import select

    monkeypatch.setenv("PADDLE_API_KEY", "pdl_sandbox_portal_test")
    license_id = await create_license(key="expired-billing-portal")
    async with AsyncSessionLocal() as db:
        license_obj = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.id == license_id)
        )).scalar_one()
        license_obj.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        license_obj.is_active = False
        db.add(PaymentWebhookEvent(
            event_id="evt_expired_portal_link",
            status="delivered",
            license_id=license_id,
            transaction_id="txn_expired_portal",
            subscription_id="sub_expired_portal",
            paddle_customer_id="ctm_expiredportal",
            recipient_email="expired-portal@example.com",
        ))
        await db.commit()

    monkeypatch.setattr(
        main, "_paddle_api_request",
        lambda *args, **kwargs: {"data": {"urls": {"general": {
            "overview": "https://customer-portal.paddle.com/overview/session-test"
        }}}},
    )
    valid = await client.post(
        "/api/v1/account/billing-portal",
        headers={"X-License-Key": "expired-billing-portal"},
    )
    assert valid.status_code == 200, valid.text
    assert valid.json()["portal_url"] == "https://customer-portal.paddle.com/overview/session-test"
    assert valid.json()["expires_in_seconds"] == 900
    assert valid.headers["cache-control"] == "no-store, private"
    assert valid.headers["pragma"] == "no-cache"

    monkeypatch.setattr(
        main, "_paddle_api_request",
        lambda *args, **kwargs: {"data": {"url": "https://attacker.example/collect"}},
    )
    invalid = await client.post(
        "/api/v1/account/billing-portal",
        headers={"X-License-Key": "expired-billing-portal"},
    )
    assert invalid.status_code == 502
    assert invalid.json()["detail"] == "Unable to open self-service billing. Please retry later."
