"""Configuration contract for the managed durable scan worker."""

import pytest

from worker_service import _bounded_int


def test_worker_configuration_uses_safe_defaults(monkeypatch):
    monkeypatch.delenv("SCAN_WORKER_MAX_JOBS", raising=False)
    monkeypatch.delenv("SCAN_WORKER_POLL_SECONDS", raising=False)

    assert _bounded_int("SCAN_WORKER_MAX_JOBS", 1, 1, 10) == 1
    assert _bounded_int("SCAN_WORKER_POLL_SECONDS", 5, 1, 300) == 5


@pytest.mark.parametrize(
    ("name", "raw", "minimum", "maximum"),
    [
        ("SCAN_WORKER_MAX_JOBS", "10", 1, 10),
        ("SCAN_WORKER_POLL_SECONDS", "300", 1, 300),
    ],
)
def test_worker_configuration_accepts_upper_bounds(monkeypatch, name, raw, minimum, maximum):
    monkeypatch.setenv(name, raw)
    assert _bounded_int(name, minimum, minimum, maximum) == maximum


@pytest.mark.parametrize(
    ("name", "raw", "minimum", "maximum"),
    [
        ("SCAN_WORKER_MAX_JOBS", "0", 1, 10),
        ("SCAN_WORKER_MAX_JOBS", "11", 1, 10),
        ("SCAN_WORKER_POLL_SECONDS", "0", 1, 300),
        ("SCAN_WORKER_POLL_SECONDS", "301", 1, 300),
        ("SCAN_WORKER_POLL_SECONDS", "fast", 1, 300),
    ],
)
def test_worker_configuration_rejects_invalid_values(monkeypatch, name, raw, minimum, maximum):
    monkeypatch.setenv(name, raw)
    with pytest.raises(RuntimeError):
        _bounded_int(name, 5, minimum, maximum)


def test_scan_worker_validates_operational_schema_before_processing():
    import inspect
    import scan_worker

    assert callable(scan_worker.ensure_scan_worker_schema)
    source = inspect.getsource(scan_worker.process_scan_queue)
    assert source.index("await ensure_scan_worker_schema()") < source.index(
        "reconcile_customer_lifecycle_outbox()"
    )



@pytest.mark.asyncio
async def test_scan_worker_schema_guard_fails_closed_without_hostinger_database(monkeypatch):
    import scan_worker

    monkeypatch.setattr(scan_worker, "_worker_schema_ready", False)
    monkeypatch.setattr(scan_worker, "HostingerAsyncSessionLocal", None)
    monkeypatch.setattr(scan_worker, "hostinger_engine", None)

    with pytest.raises(RuntimeError, match="Hostinger operational database"):
        await scan_worker.ensure_scan_worker_schema()


def test_scan_worker_schema_guard_covers_all_operational_reconciliation_models():
    import scan_worker

    required = {model.__name__ for model in scan_worker._WORKER_REQUIRED_MODELS}
    assert required == {
        "CustomerAccount",
        "CustomerLoginChallenge",
        "CustomerSession",
        "CustomerEmailChangeChallenge",
        "CustomerEmailIdentitySyncOutbox",
        "CustomerBillingEvent",
        "CustomerWebsite",
        "AgencyAccount",
        "AgencyClientWorkspace",
        "AgencyUsageEvent",
        "WebsiteScanResult",
        "ScanBatch",
        "WebsiteScanJob",
    }

def test_scan_worker_schema_guard_covers_postgres_execution_and_outbox_models():
    import scan_worker

    required = {model.__name__ for model in scan_worker._WORKER_REQUIRED_POSTGRES_MODELS}
    assert required == {
        "SoftwareLicense",
        "AuditLead",
        "AuditQuotaReservation",
        "SaaSPlanPackage",
        "CustomerLifecycleSyncOutbox",
        "PaymentWebhookEvent",
        "BillingMirrorSyncOutbox",
    }


def test_worker_schema_contract_reports_missing_tables_and_columns():
    from scan_worker import _missing_worker_schema
    from models import CustomerLifecycleSyncOutbox, SoftwareLicense

    result = _missing_worker_schema(
        (SoftwareLicense, CustomerLifecycleSyncOutbox),
        {"software_licenses", "customer_lifecycle_sync_outbox"},
        {
            "software_licenses": {"id", "license_key"},
            "customer_lifecycle_sync_outbox": {"id", "license_key"},
        },
    )

    assert result["tables"] == []
    assert "tier" in result["columns"]["software_licenses"]
    assert "action" in result["columns"]["customer_lifecycle_sync_outbox"]


def test_worker_schema_contract_reports_absent_outbox_table():
    from scan_worker import _missing_worker_schema
    from models import CustomerLifecycleSyncOutbox

    result = _missing_worker_schema(
        (CustomerLifecycleSyncOutbox,),
        set(),
        {},
    )

    assert result == {
        "tables": ["customer_lifecycle_sync_outbox"],
        "columns": {},
    }


@pytest.mark.asyncio
async def test_worker_startup_uses_shared_dual_database_schema_guard(monkeypatch):
    import scan_worker
    import worker_service

    calls = []

    async def validate_all_databases():
        calls.append("validated")

    monkeypatch.setattr(worker_service, "ensure_scan_worker_schema", validate_all_databases)

    await worker_service.validate_worker_schema()

    assert calls == ["validated"]
    assert callable(scan_worker.ensure_scan_worker_schema)


def test_worker_service_no_longer_maintains_a_separate_queue_only_schema_contract():
    import inspect
    import worker_service

    source = inspect.getsource(worker_service.validate_worker_schema)

    assert "ensure_scan_worker_schema" in source
    assert "WebsiteScanJob" not in source


def test_legacy_worker_route_remains_registered_and_processes_one_job():
    import inspect
    import scan_worker_api

    route = next(
        route for route in scan_worker_api.router.routes
        if route.path == "/api/v1/internal/scan-worker"
    )
    assert route.methods == {"GET"}
    source = inspect.getsource(route.endpoint)
    assert "SCAN_WORKER_SECRET" in source
    assert "process_scan_queue(max_jobs=1)" in source


@pytest.mark.asyncio
async def test_legacy_worker_route_accepts_existing_scheduler_secret(monkeypatch):
    import scan_worker_api

    monkeypatch.setenv("SCAN_WORKER_SECRET", "legacy-cron-secret")
    calls = []

    async def fake_process_scan_queue(*, max_jobs):
        calls.append(max_jobs)
        return {"processed": max_jobs}

    monkeypatch.setattr(scan_worker_api, "process_scan_queue", fake_process_scan_queue)
    result = await scan_worker_api.run_legacy_scan_worker("Bearer legacy-cron-secret")

    assert result == {"processed": 1}
    assert calls == [1]


@pytest.mark.asyncio
async def test_legacy_worker_route_rejects_invalid_scheduler_secret(monkeypatch):
    import scan_worker_api
    from fastapi import HTTPException

    monkeypatch.setenv("SCAN_WORKER_SECRET", "legacy-cron-secret")
    with pytest.raises(HTTPException) as raised:
        await scan_worker_api.run_legacy_scan_worker("Bearer wrong-secret")
    assert raised.value.status_code == 401


def test_worker_cycle_logs_outbox_reconciliation_counters(caplog):
    import logging

    from worker_service import _log_worker_cycle

    result = {
        "customer_lifecycle_sync": {"processed": 2, "deferred": 1},
        "customer_email_identity_sync": {"processed": 3, "deferred": 0},
        "billing_mirror_sync": {"processed": 4, "deferred": 2, "discarded": 1},
        "authentication_cleanup": {"status": "deferred"},
    }

    with caplog.at_level(logging.INFO, logger="worker_service"):
        _log_worker_cycle(result, claimed=0, processed=0)

    assert "lifecycle_deferred=1" in caplog.text
    assert "identity_processed=3" in caplog.text
    assert "billing_deferred=2" in caplog.text
    assert "billing_discarded=1" in caplog.text
    assert "auth_cleanup_status=deferred" in caplog.text


@pytest.mark.asyncio
async def test_current_scan_worker_route_accepts_cron_secret_and_requested_batch_size(monkeypatch):
    import scan_worker_api

    monkeypatch.setenv("CRON_SECRET", "configured-cron-secret")
    monkeypatch.delenv("SCAN_WORKER_TOKEN", raising=False)
    calls = []

    async def fake_process_scan_queue(*, max_jobs):
        calls.append(max_jobs)
        return {"claimed_slots": max_jobs, "processed": max_jobs}

    monkeypatch.setattr(scan_worker_api, "process_scan_queue", fake_process_scan_queue)
    result = await scan_worker_api.run_scan_worker(
        max_jobs=4,
        authorization="Bearer configured-cron-secret",
    )

    assert result == {"claimed_slots": 4, "processed": 4}
    assert calls == [4]


@pytest.mark.asyncio
async def test_current_scan_worker_route_accepts_scan_worker_token(monkeypatch):
    import scan_worker_api

    monkeypatch.delenv("CRON_SECRET", raising=False)
    monkeypatch.setenv("SCAN_WORKER_TOKEN", "worker-token")
    calls = []

    async def fake_process_scan_queue(*, max_jobs):
        calls.append(max_jobs)
        return {"claimed_slots": max_jobs}

    monkeypatch.setattr(scan_worker_api, "process_scan_queue", fake_process_scan_queue)
    result = await scan_worker_api.run_scan_worker(
        max_jobs=2,
        authorization="Bearer worker-token",
    )

    assert result == {"claimed_slots": 2}
    assert calls == [2]


@pytest.mark.asyncio
async def test_current_scan_worker_route_fails_closed_without_secret(monkeypatch):
    import scan_worker_api
    from fastapi import HTTPException

    monkeypatch.delenv("CRON_SECRET", raising=False)
    monkeypatch.delenv("SCAN_WORKER_TOKEN", raising=False)

    with pytest.raises(HTTPException) as raised:
        await scan_worker_api.run_scan_worker(
            max_jobs=1,
            authorization="Bearer anything",
        )
    assert raised.value.status_code == 503


@pytest.mark.asyncio
async def test_current_scan_worker_route_rejects_invalid_secret(monkeypatch):
    import scan_worker_api
    from fastapi import HTTPException

    monkeypatch.setenv("CRON_SECRET", "configured-cron-secret")
    monkeypatch.delenv("SCAN_WORKER_TOKEN", raising=False)

    with pytest.raises(HTTPException) as raised:
        await scan_worker_api.run_scan_worker(
            max_jobs=1,
            authorization="Bearer wrong-secret",
        )
    assert raised.value.status_code == 401


@pytest.mark.asyncio
async def test_audit_failure_cleans_up_lease_monitor_task(monkeypatch):
    import asyncio
    import scan_worker

    started = asyncio.Event()
    lease_unconfirmed = asyncio.Event()
    created_tasks = []
    real_create_task = asyncio.create_task

    def capture_task(coro):
        task = real_create_task(coro)
        created_tasks.append(task)
        return task

    async def failing_audit(_target):
        started.set()
        raise ValueError("audit failed")

    monkeypatch.setattr(asyncio, "create_task", capture_task)
    monkeypatch.setattr(scan_worker, "_execute_audit", failing_audit)
    with pytest.raises(ValueError, match="audit failed"):
        await scan_worker._run_audit_with_lease_guard(
            "https://shop.example", lease_unconfirmed
        )

    assert started.is_set()
    assert len(created_tasks) == 2
    assert all(task.done() for task in created_tasks)
    assert created_tasks[1].cancelled()


@pytest.mark.asyncio
async def test_lease_loss_cancels_running_audit_and_monitor(monkeypatch):
    import asyncio
    import scan_worker

    audit_started = asyncio.Event()
    audit_cancelled = asyncio.Event()
    lease_unconfirmed = asyncio.Event()

    async def waiting_audit(_target):
        audit_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            audit_cancelled.set()

    monkeypatch.setattr(scan_worker, "_execute_audit", waiting_audit)
    task = asyncio.create_task(
        scan_worker._run_audit_with_lease_guard("https://shop.example", lease_unconfirmed)
    )
    await audit_started.wait()
    lease_unconfirmed.set()

    with pytest.raises(RuntimeError, match="SCAN_JOB_LEASE_UNCONFIRMED"):
        await task

    assert audit_cancelled.is_set()


@pytest.mark.asyncio
async def test_cancelled_scan_releases_quota_reservation(monkeypatch):
    import scan_worker

    captured = []
    session = object()

    class SessionContext:
        async def __aenter__(self):
            return session
        async def __aexit__(self, *_args):
            return None

    async def release(db, reservation_id):
        captured.append((db, reservation_id))

    monkeypatch.setattr(scan_worker, "AsyncSessionLocal", SessionContext)
    monkeypatch.setattr(scan_worker, "release_audit_reservation", release)

    await scan_worker._release_scan_reservation(812)

    assert captured == [(session, 812)]


@pytest.mark.asyncio
async def test_missing_scan_reservation_does_not_open_database(monkeypatch):
    import scan_worker

    def unexpected_session():
        raise AssertionError("No reservation means no database work.")

    monkeypatch.setattr(scan_worker, "AsyncSessionLocal", unexpected_session)
    await scan_worker._release_scan_reservation(None)


def test_scan_worker_cancellation_releases_reservation_before_propagating():
    import inspect
    import scan_worker

    source = inspect.getsource(scan_worker.process_one_scan)
    cancellation = source.index("except asyncio.CancelledError:")
    release = source.index("_release_scan_reservation(reservation_id)", cancellation)
    propagate = source.index("raise", release)
    runtime_handler = source.index("except RuntimeError as exc:", cancellation)

    assert cancellation < release < propagate < runtime_handler


@pytest.mark.parametrize(
    ("failures", "poll_seconds", "expected"),
    [
        (1, 5, 10),
        (2, 5, 20),
        (3, 5, 40),
        (1, 1, 2),
        (9, 5, 300),
        (100, 300, 300),
        (0, 5, 10),
    ],
)
def test_worker_retry_delay_uses_capped_exponential_backoff(
    failures, poll_seconds, expected
):
    from worker_service import _worker_retry_delay

    assert _worker_retry_delay(failures, poll_seconds) == expected


def test_worker_loop_resets_consecutive_failures_after_success():
    import inspect
    import worker_service

    source = inspect.getsource(worker_service.run_worker)
    loop = source.index("while not stop.is_set()")
    success = source.index("result = await process_scan_queue", loop)
    reset_after_success = source.index("consecutive_failures = 0", success)

    assert success < reset_after_success
    assert "consecutive_failures += 1" in source
    assert "_worker_retry_delay(consecutive_failures, poll_seconds)" in source



@pytest.mark.asyncio
async def test_scan_worker_confirms_live_queue_lease_before_billable_commit(monkeypatch):
    from contextlib import asynccontextmanager
    import asyncio
    import scan_worker

    calls = []

    class OperationalSession:
        pass

    @asynccontextmanager
    async def session_factory():
        yield OperationalSession()

    async def renew(db, *, job_id, worker_id):
        calls.append((job_id, worker_id))
        return True

    monkeypatch.setattr(scan_worker, "HostingerAsyncSessionLocal", session_factory)
    monkeypatch.setattr(scan_worker, "renew_scan_job_lease", renew)

    confirmed = await scan_worker._confirm_scan_job_lease(
        "job-lease-check", "worker-1", asyncio.Event(),
    )

    assert confirmed is True
    assert calls == [("job-lease-check", "worker-1")]


@pytest.mark.asyncio
async def test_scan_worker_refuses_billable_commit_after_lease_reclaimed(monkeypatch):
    from contextlib import asynccontextmanager
    import asyncio
    import scan_worker

    @asynccontextmanager
    async def session_factory():
        yield object()

    async def renew(db, *, job_id, worker_id):
        return False

    monkeypatch.setattr(scan_worker, "HostingerAsyncSessionLocal", session_factory)
    monkeypatch.setattr(scan_worker, "renew_scan_job_lease", renew)

    confirmed = await scan_worker._confirm_scan_job_lease(
        "job-reclaimed", "old-worker", asyncio.Event(),
    )

    assert confirmed is False


@pytest.mark.asyncio
async def test_scan_worker_does_not_renew_lease_after_heartbeat_loss(monkeypatch):
    import asyncio
    import scan_worker

    lease_unconfirmed = asyncio.Event()
    lease_unconfirmed.set()

    async def should_not_run(*args, **kwargs):
        raise AssertionError("lost lease must be rejected before database access")

    monkeypatch.setattr(scan_worker, "renew_scan_job_lease", should_not_run)

    confirmed = await scan_worker._confirm_scan_job_lease(
        "job-lost", "worker-1", lease_unconfirmed,
    )

    assert confirmed is False



def test_scan_worker_rechecks_lease_loss_before_billable_quota_commit():
    import inspect
    import scan_worker

    source = inspect.getsource(scan_worker.process_one_scan)
    guard = source.index('if lease_unconfirmed.is_set():', source.index('current_license ='))
    commit = source.index('await licensing_db.commit()', guard)
    reservation_cleanup = source.index('delete(AuditQuotaReservation)', guard)

    assert reservation_cleanup < guard < commit
    assert 'raise RuntimeError("SCAN_JOB_LEASE_UNCONFIRMED")' in source[guard:commit]
