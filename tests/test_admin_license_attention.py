from datetime import datetime, timedelta, timezone

import pytest


@pytest.mark.asyncio
async def test_admin_operations_requires_admin_key(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "license-diagnostics-test-key")

    response = await client.get("/api/v1/admin/operations")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_admin_operations_reports_license_lifecycle_exceptions_without_secrets(
    client, monkeypatch
):
    from database import AsyncSessionLocal
    from models import SoftwareLicense

    monkeypatch.setenv("ADMIN_API_KEY", "license-diagnostics-test-key")
    headers = {"X-Admin-Key": "license-diagnostics-test-key"}
    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                SoftwareLicense(
                    license_key="diagnostic-expired-license",
                    client_name="Expired QA Customer",
                    tier="starter",
                    max_monthly_audits=25,
                    is_active=True,
                    expires_at=now - timedelta(days=1),
                ),
                SoftwareLicense(
                    license_key="diagnostic-inactive-license",
                    client_name="Inactive QA Customer",
                    tier=None,
                    max_monthly_audits=0,
                    is_active=False,
                    expires_at=now + timedelta(days=30),
                ),
                SoftwareLicense(
                    license_key="diagnostic-expiring-license",
                    client_name="Expiring QA Customer",
                    tier="pro",
                    max_monthly_audits=100,
                    is_active=True,
                    expires_at=now + timedelta(days=3),
                ),
            ]
        )
        await db.commit()

    response = await client.get("/api/v1/admin/operations", headers=headers)

    assert response.status_code == 200, response.text
    payload = response.json()
    counts = payload["counts"]
    assert counts["total_licenses"] == 3
    assert counts["expired_licenses"] == 1
    assert counts["active_but_expired_licenses"] == 1
    assert counts["inactive_licenses"] == 1
    assert counts["zero_or_negative_quota_licenses"] == 1
    assert counts["licenses_missing_tier"] == 1
    assert counts["expiring_within_7_days"] == 1

    attention_by_name = {
        item["client_name"]: set(item["flags"])
        for item in payload["license_attention"]
    }
    assert "active_but_expired" in attention_by_name["Expired QA Customer"]
    assert "inactive" in attention_by_name["Inactive QA Customer"]
    assert "invalid_monthly_quota" in attention_by_name["Inactive QA Customer"]
    assert "missing_tier" in attention_by_name["Inactive QA Customer"]
    assert "expiring_within_7_days" in attention_by_name["Expiring QA Customer"]

    # Operational diagnostics must not disclose license credentials or admin secrets.
    assert "diagnostic-expired-license" not in response.text
    assert "diagnostic-inactive-license" not in response.text
    assert "license-diagnostics-test-key" not in response.text
