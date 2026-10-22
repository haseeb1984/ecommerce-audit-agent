import pytest


@pytest.mark.asyncio
async def test_admin_package_crud_and_action_audit(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-key-only")
    headers = {"X-Admin-Key": "test-admin-key-only"}

    unauthorized = await client.get("/api/v1/admin/packages")
    assert unauthorized.status_code == 403

    created = await client.post(
        "/api/v1/admin/packages",
        headers=headers,
        json={
            "tier": "qa-plan",
            "label": "QA Plan",
            "monthly_audit_allowance": 250,
            "max_concurrent_audits": 2,
            "paddle_price_id": None,
            "is_active": True,
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["status"] == "created"

    listed = await client.get("/api/v1/admin/packages", headers=headers)
    assert listed.status_code == 200
    package = next(item for item in listed.json()["packages"] if item["tier"] == "qa-plan")
    assert package["monthly_audit_allowance"] == 250
    assert package["max_concurrent_audits"] == 2
    assert package["is_active"] is True
    assert "price_id" in package

    updated = await client.patch(
        "/api/v1/admin/packages/qa-plan",
        headers=headers,
        json={
            "tier": "qa-plan",
            "label": "QA Plan Plus",
            "monthly_audit_allowance": 400,
            "max_concurrent_audits": 3,
            "paddle_price_id": None,
            "is_active": True,
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["status"] == "updated"

    deactivated = await client.delete("/api/v1/admin/packages/qa-plan", headers=headers)
    assert deactivated.status_code == 200
    packages = (await client.get("/api/v1/admin/packages", headers=headers)).json()["packages"]
    package = next(item for item in packages if item["tier"] == "qa-plan")
    assert package["is_active"] is False
    assert package["monthly_audit_allowance"] == 400

    actions = await client.get("/api/v1/admin/actions", headers=headers)
    assert actions.status_code == 200
    action_names = [item["action"] for item in actions.json()["actions"]]
    assert "package.created" in action_names
    assert "package.updated" in action_names
    assert "package.deactivated" in action_names
    assert "test-admin-key-only" not in actions.text

    operations = await client.get("/api/v1/admin/operations", headers=headers)
    assert operations.status_code == 200, operations.text
    assert "audit_and_operation_failures_24h" in operations.json()["counts"]
    assert "test-admin-key-only" not in operations.text


@pytest.mark.asyncio
async def test_admin_package_validation_rejects_invalid_limits(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-key-only")
    response = await client.post(
        "/api/v1/admin/packages",
        headers={"X-Admin-Key": "test-admin-key-only"},
        json={
            "tier": "invalid-plan",
            "label": "Invalid Plan",
            "monthly_audit_allowance": 0,
            "max_concurrent_audits": 1,
            "paddle_price_id": None,
            "is_active": True,
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_payment_reconciliation_requires_recorded_transaction_id(client, monkeypatch):
    from database import AsyncSessionLocal
    from models import PaymentWebhookEvent

    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-key-only")
    async with AsyncSessionLocal() as db:
        db.add(PaymentWebhookEvent(
            event_id="evt_reconcile_without_transaction",
            status="email_pending",
            license_id=None,
            recipient_email="qa@example.test",
            transaction_id=None,
            subscription_id=None,
        ))
        await db.commit()

    response = await client.post(
        "/api/v1/admin/payment-events/evt_reconcile_without_transaction/reconcile",
        headers={"X-Admin-Key": "test-admin-key-only"},
    )
    assert response.status_code == 409
    assert "transaction ID" in response.json()["detail"]
