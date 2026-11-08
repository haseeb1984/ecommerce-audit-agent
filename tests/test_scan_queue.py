from types import SimpleNamespace

import pytest

from scan_queue import complete_scan_job, retry_failed_scan_job, _validate_standard_license_site_binding
from hostinger_models import AgencyUsageEvent


class FakeSession:
    def __init__(self, *rows):
        self.rows = list(rows)
        self.committed = False
        self.rolled_back = False
        self.added = []

    def add(self, value):
        self.added.append(value)

    async def scalar(self, _statement):
        return self.rows.pop(0)

    async def commit(self):
        self.committed = True

    async def rollback(self):
        self.rolled_back = True


@pytest.mark.asyncio
async def test_retry_failed_scan_job_requeues_job_and_reopens_failed_batch():
    job = SimpleNamespace(
        id="job-1",
        batch_id="batch-1",
        status="failed",
        attempt_count=3,
        next_attempt_at=None,
        locked_at="old-lock",
        locked_by="old-worker",
        last_error_code="UPSTREAM_TIMEOUT",
        result_reference="stale-result",
        completed_at="completed",
    )
    batch = SimpleNamespace(
        id="batch-1",
        status="failed",
        cancelled_count=0,
        failed_count=1,
        queued_count=0,
        completed_at="completed",
        available_at=None,
    )
    db = FakeSession(job, batch)

    result = await retry_failed_scan_job(
        db, job_id="job-1", license_key="license-1",
    )

    assert result["status"] == "retry_wait"
    assert result["job_id"] == "job-1"
    assert job.status == "retry_wait"
    assert job.attempt_count == 0
    assert job.locked_at is None and job.locked_by is None
    assert job.last_error_code is None and job.result_reference is None
    assert job.completed_at is None
    assert job.next_attempt_at is not None
    assert batch.status == "queued"
    assert batch.failed_count == 0 and batch.queued_count == 1
    assert batch.completed_at is None and batch.available_at is not None
    assert db.committed and not db.rolled_back


@pytest.mark.asyncio
async def test_retry_failed_scan_job_does_not_reopen_cancelled_batch():
    job = SimpleNamespace(id="job-2", batch_id="batch-2", status="failed")
    batch = SimpleNamespace(
        id="batch-2", status="cancelled", cancelled_count=1,
        failed_count=1, queued_count=0,
    )
    db = FakeSession(job, batch)

    result = await retry_failed_scan_job(
        db, job_id="job-2", license_key="license-1",
    )

    assert result == {"job_id": "job-2", "status": "not_retryable"}
    assert job.status == "failed"
    assert batch.status == "cancelled"
    assert db.rolled_back and not db.committed


@pytest.mark.asyncio
async def test_retry_failed_scan_job_rejects_non_failed_job():
    job = SimpleNamespace(id="job-3", status="completed")
    db = FakeSession(job)

    result = await retry_failed_scan_job(
        db, job_id="job-3", license_key="license-1",
    )

    assert result == {"job_id": "job-3", "status": "not_retryable"}
    assert db.rolled_back and not db.committed


@pytest.mark.asyncio
async def test_retry_failed_scan_job_does_not_disclose_other_license_jobs():
    db = FakeSession(None)

    result = await retry_failed_scan_job(
        db, job_id="private-job", license_key="other-license",
    )

    assert result is None
    assert db.rolled_back and not db.committed


def test_standard_license_can_scan_multiple_pages_on_one_site():
    _validate_standard_license_site_binding(
        registered_hosts=["shop.example"],
        submitted_urls=["https://shop.example/", "https://shop.example/products/item"],
    )


def test_standard_license_first_scan_binds_one_website():
    _validate_standard_license_site_binding(
        registered_hosts=[],
        submitted_urls=["https://shop.example/", "https://shop.example/about"],
    )


def test_standard_license_cannot_switch_to_a_second_website():
    with pytest.raises(ValueError, match="already bound"):
        _validate_standard_license_site_binding(
            registered_hosts=["shop.example"],
            submitted_urls=["https://other.example/"],
        )


def test_standard_license_rejects_multiple_websites_in_one_submission():
    with pytest.raises(ValueError, match="one ecommerce website"):
        _validate_standard_license_site_binding(
            registered_hosts=[],
            submitted_urls=["https://shop.example/", "https://other.example/"],
        )


def test_standard_license_fails_closed_on_conflicting_historical_site_bindings():
    with pytest.raises(ValueError, match="multiple historical"):
        _validate_standard_license_site_binding(
            registered_hosts=["shop.example", "other.example"],
            submitted_urls=["https://shop.example/"],
        )


@pytest.mark.asyncio
async def test_complete_scan_job_records_workspace_usage_once():
    job = SimpleNamespace(
        id="job-agency-1", batch_id="batch-agency-1", status="processing",
        locked_by="worker-1", locked_at="locked", license_key="business-license",
        result_reference=None, completed_at=None, quota_consumed=False,
    )
    batch = SimpleNamespace(
        id="batch-agency-1", workspace_id="client-workspace-1",
        status="processing", processing_count=1, completed_count=0,
        failed_count=0, cancelled_count=0, total_urls=1,
        completed_at=None, package_tier="business",
    )
    agency = SimpleNamespace(id="agency-1")
    db = FakeSession(job, batch, None, agency, None)

    completed = await complete_scan_job(
        db, job_id=job.id, worker_id="worker-1",
        result_reference="saved-result-1", quota_committed=True,
    )

    assert completed is True
    assert job.status == "completed" and job.quota_consumed is True
    assert batch.completed_count == 1 and batch.status == "completed"
    events = [item for item in db.added if isinstance(item, AgencyUsageEvent)]
    assert len(events) == 1
    assert events[0].agency_id == "agency-1"
    assert events[0].workspace_id == "client-workspace-1"
    assert events[0].event_type == "audit_completed"
    assert events[0].quantity == 1
    assert events[0].source_reference == "scan-complete:job-agency-1"
    assert db.committed


@pytest.mark.asyncio
async def test_complete_scan_job_does_not_create_duplicate_agency_usage_event():
    job = SimpleNamespace(
        id="job-agency-2", batch_id="batch-agency-2", status="processing",
        locked_by="worker-1", locked_at="locked", license_key="business-license",
        result_reference=None, completed_at=None, quota_consumed=False,
    )
    batch = SimpleNamespace(
        id="batch-agency-2", workspace_id="client-workspace-1",
        status="processing", processing_count=1, completed_count=0,
        failed_count=0, cancelled_count=0, total_urls=1,
        completed_at=None, package_tier="business",
    )
    agency = SimpleNamespace(id="agency-1")
    db = FakeSession(job, batch, None, agency, "existing-usage-event")

    completed = await complete_scan_job(
        db, job_id=job.id, worker_id="worker-1",
        result_reference="saved-result-2", quota_committed=True,
    )

    assert completed is True
    assert not any(isinstance(item, AgencyUsageEvent) for item in db.added)
    assert db.committed

@pytest.mark.asyncio
async def test_non_retryable_scan_failure_is_terminal_and_closes_batch():
    from scan_queue import fail_or_retry_scan_job

    job = SimpleNamespace(
        id="job-terminal-1",
        batch_id="batch-terminal-1",
        status="processing",
        locked_by="worker-1",
        locked_at="locked",
        attempt_count=1,
        max_attempts=5,
        last_error_code=None,
        completed_at=None,
    )
    batch = SimpleNamespace(
        id="batch-terminal-1",
        status="processing",
        processing_count=1,
        queued_count=0,
        failed_count=0,
        completed_count=0,
        cancelled_count=0,
        total_urls=1,
        completed_at=None,
    )
    db = FakeSession(job, batch)

    outcome = await fail_or_retry_scan_job(
        db,
        job_id=job.id,
        worker_id="worker-1",
        error_code="LICENSE_INACTIVE",
        retry_delay_seconds=300,
        retryable=False,
    )

    assert outcome == "failed"
    assert job.status == "failed"
    assert job.last_error_code == "LICENSE_INACTIVE"
    assert job.locked_at is None and job.locked_by is None
    assert job.completed_at is not None
    assert batch.processing_count == 0
    assert batch.failed_count == 1
    assert batch.status == "failed"
    assert batch.completed_at is not None
    assert db.committed and not db.rolled_back


class EnqueueResult:
    def __init__(self, *, value=None, rows=None):
        self.value = value
        self.rows = list(rows or [])

    def scalar_one(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.rows


class EnqueueSession:
    def __init__(self, website):
        self.website = website
        self.execute_results = [
            EnqueueResult(),                 # sequence row insert
            EnqueueResult(value=1),          # locked next sequence
            EnqueueResult(rows=[]),          # idempotency lookup
            EnqueueResult(rows=[]),          # historical customer website hosts
            EnqueueResult(rows=[]),          # active WordPress site hosts
            EnqueueResult(),                 # advance sequence
        ]
        self.scalar_statements = []
        self.execute_statements = []
        self.added = []
        self.committed = False

    async def execute(self, statement, *_args, **_kwargs):
        self.execute_statements.append(statement)
        return self.execute_results.pop(0)

    async def scalar(self, statement):
        self.scalar_statements.append(statement)
        return self.website

    def add(self, value):
        self.added.append(value)

    async def flush(self):
        return None

    async def commit(self):
        self.committed = True

    async def rollback(self):
        return None


@pytest.mark.asyncio
async def test_resubmitting_archived_website_locks_row_before_reactivation():
    from scan_queue import enqueue_scan_request
    from hostinger_models import CustomerWebsite

    archived = SimpleNamespace(
        id="website-archived", license_key="license-1",
        normalized_url="https://shop.example/", url="https://shop.example/",
        host="shop.example", status="archived", updated_at=None,
    )
    db = EnqueueSession(archived)

    result = await enqueue_scan_request(
        db,
        license_key="license-1",
        package_tier="starter",
        urls=["https://shop.example/"],
        request_id="archive-resubmit-lock-123",
    )

    assert result["new_jobs"] == 1
    assert archived.status == "active"
    assert archived.updated_at is not None
    assert db.scalar_statements[0]._for_update_arg is not None
    assert not any(isinstance(item, CustomerWebsite) for item in db.added)
    assert db.committed



def test_scan_lease_renewal_rejects_expired_owner_and_bounds_lease_window():
    import inspect
    import scan_queue

    renewal = inspect.getsource(scan_queue.renew_scan_job_lease)
    assert "lease_seconds: int = 900" in renewal
    assert "renewal_cutoff = _scan_lease_cutoff(now, lease_seconds)" in renewal
    assert "WebsiteScanJob.locked_at >= renewal_cutoff" in renewal
    cutoff = inspect.getsource(scan_queue._scan_lease_cutoff)
    assert "isinstance(lease_seconds, bool)" in cutoff
    assert "1 <= lease_seconds <= 3600" in cutoff


def test_scan_worker_heartbeat_runs_well_inside_lease_window():
    import inspect
    import scan_worker

    source = inspect.getsource(scan_worker.process_one_scan)
    heartbeat_interval = int(source.split("await asyncio.sleep(", 1)[1].split(")", 1)[0])
    assert heartbeat_interval < 900
    assert "if not owned:" in source
    assert "lease_unconfirmed.set()" in source



def test_stale_scan_lease_recovery_is_bounded_ordered_and_nonblocking():
    import inspect
    import scan_queue

    source = inspect.getsource(scan_queue.claim_next_scan_job)
    start = source.index("expired_jobs =")
    end = source.index(").scalars().all()", start)
    recovery_query = source[start:end]

    assert ".order_by(WebsiteScanJob.locked_at.asc(), WebsiteScanJob.id.asc())" in recovery_query
    assert ".limit(100)" in recovery_query
    assert ".with_for_update(skip_locked=True)" in recovery_query



def test_every_worker_owned_queue_mutation_rejects_expired_leases():
    import inspect
    import scan_queue

    for function in (
        scan_queue.complete_scan_job,
        scan_queue.fail_or_retry_scan_job,
        scan_queue.defer_scan_job,
        scan_queue.renew_scan_job_lease,
    ):
        source = inspect.getsource(function)
        assert "lease_seconds: int = 900" in source
        assert "WebsiteScanJob.locked_at >=" in source
        assert "_scan_lease_cutoff(now, lease_seconds)" in source


@pytest.mark.parametrize("lease_seconds", [0, -1, 3601, True, 900.0, "900"])
def test_scan_lease_cutoff_rejects_invalid_durations(lease_seconds):
    from datetime import datetime, timezone
    from scan_queue import _scan_lease_cutoff

    with pytest.raises(ValueError, match="between 1 and 3600"):
        _scan_lease_cutoff(datetime.now(timezone.utc), lease_seconds)


def test_scan_lease_cutoff_accepts_valid_integer_duration():
    from datetime import datetime, timedelta, timezone
    from scan_queue import _scan_lease_cutoff

    now = datetime.now(timezone.utc)
    assert _scan_lease_cutoff(now, 900) == now - timedelta(seconds=900)


@pytest.mark.parametrize("max_attempts", [0, -1, 11, True, 3.0, "3"])
def test_enqueue_rejects_invalid_attempt_limits(max_attempts):
    from scan_queue import enqueue_scan_request

    class NeverUsedSession:
        async def execute(self, *_args, **_kwargs):
            raise AssertionError("invalid input must be rejected before database access")

    async def run():
        await enqueue_scan_request(
            NeverUsedSession(),
            license_key="license-1",
            package_tier="starter",
            urls=["https://shop.example/"],
            request_id="invalid-attempt-limit",
            max_attempts=max_attempts,
        )

    with pytest.raises(ValueError, match="Maximum scan attempts"):
        import asyncio
        asyncio.run(run())


@pytest.mark.parametrize("request_id", ["", "x" * 129])
def test_enqueue_rejects_invalid_request_id_before_database_access(request_id):
    from scan_queue import enqueue_scan_request
    import asyncio

    class NeverUsedSession:
        async def execute(self, *_args, **_kwargs):
            raise AssertionError("invalid input must be rejected before database access")

    with pytest.raises(ValueError, match="Request ID"):
        asyncio.run(enqueue_scan_request(
            NeverUsedSession(),
            license_key="license-1",
            package_tier="starter",
            urls=["https://shop.example/"],
            request_id=request_id,
        ))


def test_site_binding_normalizes_existing_unicode_and_trailing_dot_hosts():
    _validate_standard_license_site_binding(
        registered_hosts=["BÜCHER.example."],
        submitted_urls=["https://xn--bcher-kva.example/products/1"],
    )


@pytest.mark.parametrize("host", ["shop.example:443", "user@shop.example", "shop.example/path"])
def test_site_binding_rejects_non_hostname_values_in_legacy_inventory(host):
    with pytest.raises(ValueError, match="valid website hostname"):
        _validate_standard_license_site_binding(
            registered_hosts=[host],
            submitted_urls=["https://shop.example/"],
        )


@pytest.mark.parametrize("batch_size", [True, False, 10.0, "10", 9, 12])
def test_enqueue_rejects_invalid_batch_sizes_before_database_access(batch_size):
    from scan_queue import enqueue_scan_request
    import asyncio

    class NeverUsedSession:
        async def execute(self, *_args, **_kwargs):
            raise AssertionError("invalid input must be rejected before database access")

    with pytest.raises(ValueError, match="Scan batch size"):
        asyncio.run(enqueue_scan_request(
            NeverUsedSession(),
            license_key="license-1",
            package_tier="starter",
            urls=["https://shop.example/"],
            request_id="invalid-batch-size",
            batch_size=batch_size,
        ))


def test_enqueue_rejects_whitespace_padded_request_id():
    from scan_queue import enqueue_scan_request
    import asyncio

    class NeverUsedSession:
        async def execute(self, *_args, **_kwargs):
            raise AssertionError("invalid input must be rejected before database access")

    with pytest.raises(ValueError, match="Request ID"):
        asyncio.run(enqueue_scan_request(
            NeverUsedSession(),
            license_key="license-1",
            package_tier="starter",
            urls=["https://shop.example/"],
            request_id=" request-1 ",
        ))


def test_site_binding_accepts_and_canonicalizes_public_ipv6_hosts():
    _validate_standard_license_site_binding(
        registered_hosts=["2606:4700:4700:0000:0000:0000:0000:1111"],
        submitted_urls=["https://[2606:4700:4700::1111]/products/1"],
    )


@pytest.mark.asyncio
async def test_enqueue_persists_ipv6_hostname_without_bracket_or_port_truncation():
    from scan_queue import enqueue_scan_request
    from hostinger_models import CustomerWebsite

    db = EnqueueSession(None)
    result = await enqueue_scan_request(
        db,
        license_key="license-ipv6",
        package_tier="starter",
        urls=["https://[2606:4700:4700::1111]/"],
        request_id="ipv6-site-binding-001",
    )

    website = next(item for item in db.added if isinstance(item, CustomerWebsite))
    assert website.host == "2606:4700:4700::1111"
    assert result["new_jobs"] == 1
