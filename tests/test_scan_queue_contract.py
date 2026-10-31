"""Contract checks for the durable Hostinger scan worker schema."""

import pytest
from hostinger_models import (
    CustomerAccount,
    CustomerBillingEvent,
    CustomerEmailIdentitySyncOutbox,
    CustomerSession,
    ScanJob,
    WebsiteScanResult,
)
from scan_queue import (
    claim_next_scan_job,
    complete_scan_job,
    defer_scan_job,
    fail_or_retry_scan_job,
    renew_scan_job_lease,
)


def test_scan_job_model_has_lease_and_retry_state():
    columns = set(ScanJob.__table__.columns.keys())
    assert {
        "id", "license_key", "website_id", "target_url", "status",
        "attempts", "max_attempts", "available_at", "lease_owner",
        "lease_expires_at", "error_code", "result_reference",
        "quota_committed", "created_at", "updated_at", "completed_at",
    } <= columns


def test_worker_operational_models_cover_reconciliation_contract():
    assert {"license_key", "status", "updated_at"} <= set(CustomerAccount.__table__.columns.keys())
    assert {
        "event_id", "license_key", "recipient_email", "status",
        "transaction_id", "subscription_id", "paddle_customer_id",
    } <= set(CustomerBillingEvent.__table__.columns.keys())
    assert {"token_hash", "license_key", "expires_at", "revoked_at"} <= set(CustomerSession.__table__.columns.keys())
    assert {"old_email", "new_email", "status", "attempts", "next_attempt_at"} <= set(
        CustomerEmailIdentitySyncOutbox.__table__.columns.keys()
    )
    assert {"job_id", "findings_json", "check_outcomes_json", "coverage_json"} <= set(
        WebsiteScanResult.__table__.columns.keys()
    )


def test_queue_transition_functions_are_available():
    assert callable(claim_next_scan_job)
    assert callable(renew_scan_job_lease)
    assert callable(complete_scan_job)
    assert callable(fail_or_retry_scan_job)
    assert callable(defer_scan_job)


def test_scan_worker_module_imports_with_all_declared_dependencies():
    import scan_worker

    assert callable(scan_worker.process_scan_queue)
    assert callable(scan_worker.process_one_scan)
    assert callable(scan_worker.ensure_scan_worker_schema)


class _OutboxSession:
    def __init__(self):
        self.items = []
        self.existing = set()

    async def get(self, model, key):
        return object() if key in self.existing else None

    def add(self, item):
        self.items.append(item)


@pytest.mark.asyncio
async def test_billing_and_lifecycle_events_are_written_to_outboxes():
    import main

    db = _OutboxSession()
    await main._enqueue_billing_mirror_sync(db, "evt_contract_1")
    await main._enqueue_billing_mirror_sync(db, "evt_contract_1")
    await main._enqueue_customer_lifecycle_sync(db, "license-contract", "suspend")

    assert len(db.items) == 2
    assert db.items[0].event_id == "evt_contract_1"
    assert db.items[0].status == "pending"
    assert db.items[1].license_key == "license-contract"
    assert db.items[1].action == "suspend"


@pytest.mark.asyncio
async def test_internal_worker_endpoint_requires_authentication(client, monkeypatch):
    monkeypatch.delenv("SCAN_WORKER_SECRET", raising=False)
    monkeypatch.delenv("CRON_SECRET", raising=False)
    missing = await client.get("/api/v1/internal/scan-worker")
    assert missing.status_code == 503

    monkeypatch.setenv("CRON_SECRET", "test-value")
    unauthorized = await client.get(
        "/api/v1/internal/scan-worker",
        headers={"Authorization": "Bearer invalid"},
    )
    assert unauthorized.status_code == 401

    import scan_worker

    async def fake_process_scan_queue(*, max_jobs=1):
        return {"claimed_slots": 0, "processed": 0, "max_jobs": max_jobs}

    monkeypatch.setattr(scan_worker, "process_scan_queue", fake_process_scan_queue)
    accepted = await client.get(
        "/api/v1/internal/scan-worker",
        headers={"Authorization": "Bearer test-value"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["max_jobs"] == 1
