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


@pytest.mark.asyncio
async def test_admin_client_update_syncs_package_limit_and_keeps_license_secret_private(client, monkeypatch):
    from database import AsyncSessionLocal
    from models import SoftwareLicense

    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-key-only")
    headers = {"X-Admin-Key": "test-admin-key-only"}

    package = await client.post(
        "/api/v1/admin/packages",
        headers=headers,
        json={
            "tier": "support-tier",
            "label": "Support Tier",
            "monthly_audit_allowance": 321,
            "max_concurrent_audits": 2,
            "paddle_price_id": None,
            "is_active": True,
        },
    )
    assert package.status_code == 200, package.text

    async with AsyncSessionLocal() as db:
        license_obj = SoftwareLicense(
            license_key="qa-license-marker",
            client_name="QA Client",
            tier="starter",
            max_monthly_audits=100,
            is_active=True,
        )
        db.add(license_obj)
        await db.commit()
        await db.refresh(license_obj)
        license_id = license_obj.id

    response = await client.patch(
        f"/api/v1/admin/clients/{license_id}",
        headers=headers,
        json={"client_name": "Updated QA Client", "tier": "support-tier", "is_active": False},
    )
    assert response.status_code == 200, response.text
    updated_client = response.json()["client"]
    assert updated_client["client_name"] == "Updated QA Client"
    assert updated_client["tier"] == "support-tier"
    assert updated_client["monthly_limit"] == 321
    assert updated_client["is_active"] is False
    assert "qa-license-marker" not in response.text

    history = await client.get(f"/api/v1/admin/clients/{license_id}/history", headers=headers)
    assert history.status_code == 200, history.text
    assert "qa-license-marker" not in history.text


@pytest.mark.asyncio
async def test_admin_routes_fail_closed_when_admin_key_is_unconfigured(client, monkeypatch):
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    response = await client.get("/api/v1/admin/packages")
    assert response.status_code == 503
    assert response.json()["detail"] == "Admin access is not configured."



@pytest.mark.asyncio
async def test_admin_packages_reject_duplicate_paddle_price_mapping(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-key-only")
    headers = {"X-Admin-Key": "test-admin-key-only"}
    first = await client.post(
        "/api/v1/admin/packages",
        headers=headers,
        json={
            "tier": "paddle-plan-a",
            "label": "Paddle Plan A",
            "monthly_audit_allowance": 100,
            "max_concurrent_audits": 1,
            "paddle_price_id": "pri_TestPrice123",
            "is_active": True,
        },
    )
    assert first.status_code == 200, first.text

    duplicate = await client.post(
        "/api/v1/admin/packages",
        headers=headers,
        json={
            "tier": "paddle-plan-b",
            "label": "Paddle Plan B",
            "monthly_audit_allowance": 500,
            "max_concurrent_audits": 2,
            "paddle_price_id": "pri_TestPrice123",
            "is_active": True,
        },
    )
    assert duplicate.status_code == 409, duplicate.text
    assert "already assigned" in duplicate.json()["detail"]


@pytest.mark.asyncio
async def test_admin_client_update_rejects_unknown_package(client, monkeypatch):
    from database import AsyncSessionLocal
    from models import SoftwareLicense

    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-key-only")
    async with AsyncSessionLocal() as db:
        license_obj = SoftwareLicense(
            license_key="qa-unknown-tier-marker",
            client_name="QA Client",
            tier="starter",
            max_monthly_audits=100,
            is_active=True,
        )
        db.add(license_obj)
        await db.commit()
        await db.refresh(license_obj)
        license_id = license_obj.id

    response = await client.patch(
        f"/api/v1/admin/clients/{license_id}",
        headers={"X-Admin-Key": "test-admin-key-only"},
        json={"tier": "does-not-exist"},
    )
    assert response.status_code == 422
    assert "package" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_plan_bootstrap_repairs_legacy_default_concurrency_limits(monkeypatch):
    """Existing default-1 plan rows should inherit explicitly configured higher limits."""
    from sqlalchemy import text
    from database import AsyncSessionLocal
    import main

    for tier in ("STARTER", "PRO", "BUSINESS"):
        monkeypatch.setenv(f"PADDLE_PRICE_ID_{tier}", f"pri_test{tier.lower()}")
    monkeypatch.setenv("LICENSE_MAX_CONCURRENT_AUDITS_STARTER", "1")
    monkeypatch.setenv("LICENSE_MAX_CONCURRENT_AUDITS_PRO", "3")
    monkeypatch.setenv("LICENSE_MAX_CONCURRENT_AUDITS_BUSINESS", "10")

    async with AsyncSessionLocal() as db:
        for tier, label, allowance, price_id in (
            ("starter", "Starter", 100, "pri_teststarter"),
            ("pro", "Pro", 500, "pri_testpro"),
            ("business", "Business", 2000, "pri_testbusiness"),
        ):
            await db.execute(text("""
                INSERT INTO saas_plan_packages
                    (tier, label, monthly_audit_allowance, max_concurrent_audits, paddle_price_id, is_active)
                VALUES (:tier, :label, :allowance, 1, :price_id, TRUE)
            """), {
                "tier": tier,
                "label": label,
                "allowance": allowance,
                "price_id": price_id,
            })

        await main._ensure_admin_tables(db)
        rows = (await db.execute(text("""
            SELECT tier, max_concurrent_audits
            FROM saas_plan_packages
            ORDER BY tier
        """))).all()

    assert dict(rows) == {"business": 10, "pro": 3, "starter": 1}


@pytest.mark.asyncio
async def test_plan_bootstrap_preserves_nondefault_admin_concurrency(monkeypatch):
    """Bootstrap must not overwrite a deliberate non-default limit from the admin UI."""
    from sqlalchemy import text
    from database import AsyncSessionLocal
    import main

    monkeypatch.setenv("PADDLE_PRICE_ID_PRO", "pri_testpro")
    monkeypatch.setenv("LICENSE_MAX_CONCURRENT_AUDITS_PRO", "3")

    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            INSERT INTO saas_plan_packages
                (tier, label, monthly_audit_allowance, max_concurrent_audits, paddle_price_id, is_active)
            VALUES ('pro', 'Pro', 500, 2, 'pri_testpro', TRUE)
        """))
        await main._ensure_admin_tables(db)
        concurrency = (await db.execute(text("""
            SELECT max_concurrent_audits FROM saas_plan_packages WHERE tier='pro'
        """))).scalar_one()

    assert concurrency == 2
