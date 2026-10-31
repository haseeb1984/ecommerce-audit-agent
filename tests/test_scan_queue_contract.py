"""Contract checks for the durable Hostinger scan worker schema."""
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
