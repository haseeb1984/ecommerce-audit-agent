"""Regression tests for cross-database outbox processing in every worker cycle."""

import pytest


@pytest.mark.asyncio
async def test_idle_worker_cycle_still_reconciles_all_outboxes_and_auth_retention(monkeypatch):
    import scan_worker

    calls = []

    async def schema():
        calls.append("schema")

    async def lifecycle():
        calls.append("lifecycle")
        return {"processed": 2, "deferred": 0}

    async def identity():
        calls.append("identity")
        return {"processed": 1, "deferred": 0}

    async def billing():
        calls.append("billing")
        return {"processed": 3, "deferred": 1, "discarded": 0}

    async def cleanup():
        calls.append("cleanup")
        return {"sessions_deleted": 4}

    async def idle_scan(worker_id):
        calls.append("scan")
        return {"status": "idle"}

    monkeypatch.setattr(scan_worker, "ensure_scan_worker_schema", schema)
    monkeypatch.setattr(scan_worker, "reconcile_customer_lifecycle_outbox", lifecycle)
    monkeypatch.setattr(scan_worker, "reconcile_customer_email_identity_outbox", identity)
    monkeypatch.setattr(scan_worker, "reconcile_billing_mirror_outbox", billing)
    monkeypatch.setattr(scan_worker, "cleanup_expired_customer_auth_records", cleanup)
    monkeypatch.setattr(scan_worker, "process_one_scan", idle_scan)

    result = await scan_worker.process_scan_queue(max_jobs=1, worker_id="outbox-test")

    assert calls == [
        "schema", "lifecycle", "identity", "billing", "cleanup", "scan"
    ]
    assert result["claimed_slots"] == 0
    assert result["processed"] == 0
    assert result["customer_lifecycle_sync"]["processed"] == 2
    assert result["customer_email_identity_sync"]["processed"] == 1
    assert result["billing_mirror_sync"]["processed"] == 3
    assert result["billing_mirror_sync"]["deferred"] == 1
    assert result["authentication_cleanup"]["sessions_deleted"] == 4


@pytest.mark.asyncio
async def test_one_outbox_failure_does_not_block_other_reconciliation_or_scan_work(monkeypatch):
    import scan_worker

    calls = []

    async def schema():
        calls.append("schema")

    async def failed_lifecycle():
        calls.append("lifecycle")
        raise RuntimeError("temporary PostgreSQL outage")

    async def identity():
        calls.append("identity")
        return {"processed": 1, "deferred": 0}

    async def billing():
        calls.append("billing")
        return {"processed": 1, "deferred": 0, "discarded": 0}

    async def cleanup():
        calls.append("cleanup")
        return {}

    async def idle_scan(worker_id):
        calls.append("scan")
        return {"status": "idle"}

    monkeypatch.setattr(scan_worker, "ensure_scan_worker_schema", schema)
    monkeypatch.setattr(scan_worker, "reconcile_customer_lifecycle_outbox", failed_lifecycle)
    monkeypatch.setattr(scan_worker, "reconcile_customer_email_identity_outbox", identity)
    monkeypatch.setattr(scan_worker, "reconcile_billing_mirror_outbox", billing)
    monkeypatch.setattr(scan_worker, "cleanup_expired_customer_auth_records", cleanup)
    monkeypatch.setattr(scan_worker, "process_one_scan", idle_scan)

    result = await scan_worker.process_scan_queue(max_jobs=1, worker_id="outbox-failure-test")

    assert calls == [
        "schema", "lifecycle", "identity", "billing", "cleanup", "scan"
    ]
    assert result["customer_lifecycle_sync"]["status"] == "deferred"
    assert result["customer_lifecycle_sync"]["error_type"] == "RuntimeError"
    assert result["customer_email_identity_sync"]["processed"] == 1
    assert result["billing_mirror_sync"]["processed"] == 1
    assert result["authentication_cleanup"]["status"] == "completed"
    assert result["claimed_slots"] == 0



@pytest.mark.asyncio
async def test_one_scan_worker_slot_failure_does_not_hide_other_slot_results(monkeypatch):
    import scan_worker

    async def schema():
        return None

    async def no_work():
        return {"processed": 0, "deferred": 0}

    async def cleanup():
        return {}

    async def scan(worker_id):
        if worker_id.endswith("-0"):
            raise ConnectionError("temporary operational DB failure")
        return {"status": "completed", "job_id": "job-2"}

    monkeypatch.setattr(scan_worker, "ensure_scan_worker_schema", schema)
    monkeypatch.setattr(scan_worker, "reconcile_customer_lifecycle_outbox", no_work)
    monkeypatch.setattr(scan_worker, "reconcile_customer_email_identity_outbox", no_work)
    monkeypatch.setattr(scan_worker, "reconcile_billing_mirror_outbox", no_work)
    monkeypatch.setattr(scan_worker, "cleanup_expired_customer_auth_records", cleanup)
    monkeypatch.setattr(scan_worker, "process_one_scan", scan)

    result = await scan_worker.process_scan_queue(max_jobs=2, worker_id="partial")

    assert result["slot_errors"] == 1
    assert result["claimed_slots"] == 2
    assert result["processed"] == 1
    assert [item["status"] for item in result["outcomes"]] == [
        "worker_error", "completed",
    ]
    assert result["outcomes"][0]["error_code"] == "CONNECTIONERROR"


@pytest.mark.asyncio
async def test_all_scan_worker_slot_failures_fail_the_cycle_for_scheduler_retry(monkeypatch):
    import scan_worker

    async def schema():
        return None

    async def no_work():
        return {"processed": 0, "deferred": 0}

    async def cleanup():
        return {}

    async def scan(_worker_id):
        raise ConnectionError("temporary operational DB failure")

    monkeypatch.setattr(scan_worker, "ensure_scan_worker_schema", schema)
    monkeypatch.setattr(scan_worker, "reconcile_customer_lifecycle_outbox", no_work)
    monkeypatch.setattr(scan_worker, "reconcile_customer_email_identity_outbox", no_work)
    monkeypatch.setattr(scan_worker, "reconcile_billing_mirror_outbox", no_work)
    monkeypatch.setattr(scan_worker, "cleanup_expired_customer_auth_records", cleanup)
    monkeypatch.setattr(scan_worker, "process_one_scan", scan)

    with pytest.raises(RuntimeError, match="All scan worker slots failed"):
        await scan_worker.process_scan_queue(max_jobs=1, worker_id="all-failed")
