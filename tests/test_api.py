import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

import main
from database import AsyncSessionLocal
from models import APIKey, AuditLead, AuditQuotaReservation, AuditReport, SoftwareLicense
from ecommerce_agent import ContactInfo, LeadDossier, PersonalizedPitch, StoreAuditMetrics


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
    assert [row["domain"] for row in payload["reports"]] == ["owned.example"]

    pdf = await client.get(f"/api/v1/reports/{owned_id}/pdf", headers=headers)
    assert pdf.status_code == 200
    assert pdf.content == b"%PDF-owned"
    assert pdf.headers["content-type"] == "application/pdf"

    coverage = await client.get(f"/api/v1/reports/{owned_id}/coverage", headers=headers)
    assert coverage.status_code == 200
    assert coverage.json()["findings_total"] == 1

    forbidden_pdf = await client.get(f"/api/v1/reports/{private_id}/pdf", headers=headers)
    forbidden_coverage = await client.get(f"/api/v1/reports/{private_id}/coverage", headers=headers)
    assert forbidden_pdf.status_code == 404
    assert forbidden_coverage.status_code == 404


@pytest.mark.asyncio
async def test_report_history_requires_authentication(client):
    response = await client.get("/api/v1/reports")
    assert response.status_code == 401


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
