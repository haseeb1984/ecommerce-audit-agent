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


def test_worker_schema_contract_reports_missing_columns():
    from worker_service import _missing_required_columns

    assert _missing_required_columns({"id", "status", "batch_id"}, {"id", "status"}) == ["batch_id"]


def test_worker_schema_contract_accepts_complete_table():
    from worker_service import _missing_required_columns

    assert _missing_required_columns({"id", "status"}, {"id", "status", "created_at"}) == []



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
        "WebsiteScanResult",
        "ScanBatch",
        "WebsiteScanJob",
    }
