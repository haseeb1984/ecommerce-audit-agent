"""Admin package uniqueness and conflict-response regression tests."""
import pytest

from database import AsyncSessionLocal
from models import SaaSPlanPackage


async def _seed_package(tier: str, price_id: str) -> None:
    async with AsyncSessionLocal() as db:
        db.add(SaaSPlanPackage(
            tier=tier,
            label=f"Plan {tier}",
            monthly_audit_allowance=25,
            max_concurrent_audits=2,
            paddle_price_id=price_id,
            is_active=True,
        ))
        await db.commit()


def _payload(tier: str, price_id: str | None) -> dict:
    return {
        "tier": tier,
        "label": f"Plan {tier}",
        "monthly_audit_allowance": 25,
        "max_concurrent_audits": 2,
        "paddle_price_id": price_id,
        "is_active": True,
    }


@pytest.mark.asyncio
async def test_admin_package_create_rejects_paddle_price_already_assigned(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "package-unique-test-key")
    await _seed_package("starter", "pri_SharedPackagePrice")

    response = await client.post(
        "/api/v1/admin/packages",
        headers={"X-Admin-Key": "package-unique-test-key"},
        json=_payload("agency", "pri_SharedPackagePrice"),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "That Paddle price is already assigned to another package."


@pytest.mark.asyncio
async def test_admin_package_update_rejects_another_plans_paddle_price(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "package-unique-update-key")
    await _seed_package("starter", "pri_FirstUniquePrice")
    await _seed_package("agency", "pri_SecondUniquePrice")

    response = await client.patch(
        "/api/v1/admin/packages/starter",
        headers={"X-Admin-Key": "package-unique-update-key"},
        json=_payload("starter", "pri_SecondUniquePrice"),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "That Paddle price is already assigned to another package."
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        first = (await db.execute(
            select(SaaSPlanPackage).where(SaaSPlanPackage.tier == "starter")
        )).scalar_one()
        assert first.paddle_price_id == "pri_FirstUniquePrice"
