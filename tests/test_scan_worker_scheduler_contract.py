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
    assert 'https://*)' in workflow
    assert '--max-time 150' in workflow
    assert "--retry 2 --retry-delay 5" in workflow
    assert "--retry-all-errors" not in workflow
    assert '--header "Authorization: Bearer $CRON_SECRET"' in workflow
    # The scheduler must not silently skip when its endpoint variable is absent.
    assert "if: ${{ vars.SCAN_WORKER_URL" not in workflow
