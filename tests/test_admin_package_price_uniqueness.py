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
    await _seed_package("existing-price-plan", "pri_shared_package_price")

    response = await client.post(
        "/api/v1/admin/packages",
        headers={"X-Admin-Key": "package-unique-test-key"},
        json=_payload("new-price-plan", "pri_shared_package_price"),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "That Paddle price is already assigned to another package."


@pytest.mark.asyncio
async def test_admin_package_update_rejects_another_plans_paddle_price(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "package-unique-update-key")
    await _seed_package("first-price-plan", "pri_first_unique_price")
    await _seed_package("second-price-plan", "pri_second_unique_price")

    response = await client.patch(
        "/api/v1/admin/packages/first-price-plan",
        headers={"X-Admin-Key": "package-unique-update-key"},
        json=_payload("first-price-plan", "pri_second_unique_price"),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "That Paddle price is already assigned to another package."
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        first = (await db.execute(
            select(SaaSPlanPackage).where(SaaSPlanPackage.tier == "first-price-plan")
        )).scalar_one()
        assert first.paddle_price_id == "pri_first_unique_price"
