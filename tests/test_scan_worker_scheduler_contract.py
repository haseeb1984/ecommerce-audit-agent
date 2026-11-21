"""Contract tests for the scheduled durable scan worker invocation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "scan-worker.yml"


def test_scheduled_worker_has_visible_configuration_validation_and_bounded_retries():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert 'cron: "*/5 * * * *"' in workflow
    assert "timeout-minutes: 8" in workflow
    assert "vars.SCAN_WORKER_URL" in workflow
    assert "secrets.CRON_SECRET" in workflow
    assert "Repository variable SCAN_WORKER_URL is not configured." in workflow
    assert "Repository secret CRON_SECRET is not configured." in workflow
    assert "parsed.scheme == \"https\"" in workflow
    assert 'parsed.path.rstrip("/") == "/internal/scan-worker/run"' in workflow
    assert "parsed.username is None" in workflow
    assert "parsed.password is None" in workflow
    assert "not parsed.fragment" in workflow
    assert "parsed.port is None or 1 <= parsed.port <= 65535" in workflow
    assert "not any(character.isspace() for character in parsed.netloc)" in workflow
    assert "--max-time 150" in workflow
    assert "--retry 2 --retry-delay 5" in workflow
    assert "--retry-all-errors" not in workflow
    assert '--header "Authorization: Bearer $CRON_SECRET"' in workflow
    # The scheduler must not silently skip when its endpoint variable is absent.
    assert "if: ${{ vars.SCAN_WORKER_URL" not in workflow



def test_scan_worker_rechecks_license_under_lock_before_first_quota_commit():
    worker = (ROOT / "scan_worker.py").read_text(encoding="utf-8")

    audit_complete = worker.index("result = await _run_audit_with_lease_guard")
    revalidation = worker.index("select(SoftwareLicense)", audit_complete)
    row_lock = worker.index(".with_for_update()", revalidation)
    first_lead_insert = worker.index("lead = AuditLead(", row_lock)
    entitlement_check = worker.index("LICENSE_INACTIVE_OR_EXPIRED", row_lock)

    assert audit_complete < revalidation < row_lock < entitlement_check < first_lead_insert
    assert "if existing_lead is None:" in worker[row_lock:first_lead_insert]


def test_scan_worker_heartbeat_renews_quota_reservation_and_stops_on_loss():
    worker = (ROOT / "scan_worker.py").read_text(encoding="utf-8")
    quota = (ROOT / "quota.py").read_text(encoding="utf-8")

    heartbeat_start = worker.index("async def _heartbeat():")
    queue_renewal = worker.index("renew_scan_job_lease(", heartbeat_start)
    reservation_renewal = worker.index("renew_audit_reservation(", queue_renewal)
    stop_signal = worker.index("lease_unconfirmed.set()", reservation_renewal)

    assert heartbeat_start < queue_renewal < reservation_renewal < stop_signal
    assert "AuditQuotaReservation.expires_at > now" in quota
    assert ".values(expires_at=now + ttl)" in quota
