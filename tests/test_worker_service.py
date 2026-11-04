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
