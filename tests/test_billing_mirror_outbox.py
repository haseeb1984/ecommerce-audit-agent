from datetime import datetime, timezone
from types import SimpleNamespace

from scan_worker import _mark_billing_mirror_outbox_completed


def test_billing_mirror_outbox_delivery_is_marked_completed_and_retained():
    item = SimpleNamespace(
        status="pending",
        processed_at=None,
        last_error="PreviousTransientFailure",
    )
    processed_at = datetime(2026, 11, 1, 12, 30, tzinfo=timezone.utc)

    _mark_billing_mirror_outbox_completed(item, processed_at)

    assert item.status == "completed"
    assert item.processed_at == processed_at
    assert item.last_error is None
