"""Regression coverage for operator-managed plan limits in audit quota enforcement."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from database import AsyncSessionLocal
from models import AuditLead, AuditQuotaReservation, SaaSPlanPackage, SoftwareLicense


async def _create_license(*, key: str, tier: str, legacy_quota: int = 100) -> int:
    async with AsyncSessionLocal() as db:
        license_obj = SoftwareLicense(
            license_key=key,
            client_name="Quota Plan Test",
            tier=tier,
            max_monthly_audits=legacy_quota,
            is_active=True,
        )
        db.add(license_obj)
        await db.commit()
        await db.refresh(license_obj)
        return license_obj.id


async def _count(model) -> int:
    async with AsyncSessionLocal() as db:
        return int((await db.execute(select(func.count(model.id)))).scalar_one())


@pytest.mark.asyncio
async def test_operator_plan_allowance_overrides_legacy_license_quota(client, monkeypatch):
    tier = "agency"
    license_id = await _create_license(key="catalogue-quota-license", tier=tier, legacy_quota=100)
    async with AsyncSessionLocal() as db:
        db.add(SaaSPlanPackage(
            tier=tier,
            label="Quota Catalogue Test",
            monthly_audit_allowance=1,
            max_concurrent_audits=2,
            is_active=True,
        ))
        db.add(AuditLead(
            license_id=license_id,
            domain="already-audited.example",
            mobile_score=70,
            speed_index_sec=2.0,
            created_at=datetime.now(timezone.utc),
        ))
        await db.commit()

    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "another-shop.example"},
        headers={"X-License-Key": "catalogue-quota-license"},
    )

    assert response.status_code == 429, response.text
    assert "Monthly audit quota of 1" in response.json()["detail"]
    assert await _count(AuditLead) == 1
    assert await _count(AuditQuotaReservation) == 0


@pytest.mark.asyncio
async def test_operator_deactivated_plan_blocks_new_audit_reservations(client):
    tier = "agency"
    await _create_license(key="disabled-plan-license", tier=tier)
    async with AsyncSessionLocal() as db:
        db.add(SaaSPlanPackage(
            tier=tier,
            label="Disabled Plan Test",
            monthly_audit_allowance=50,
            max_concurrent_audits=3,
            is_active=False,
        ))
        await db.commit()

    response = await client.post(
        "/api/v1/audit-lead",
        params={"domain": "blocked-shop.example"},
        headers={"X-License-Key": "disabled-plan-license"},
    )

    assert response.status_code == 403, response.text
    assert "plan is currently unavailable" in response.json()["detail"]
    assert await _count(AuditLead) == 0
    assert await _count(AuditQuotaReservation) == 0
