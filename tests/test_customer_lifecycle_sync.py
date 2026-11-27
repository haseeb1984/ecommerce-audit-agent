from scan_worker import _lifecycle_action_applies


def test_stale_suspend_event_is_ignored_after_license_reactivation():
    assert not _lifecycle_action_applies("suspend", True)


def test_stale_reactivate_event_is_ignored_after_license_suspension():
    assert not _lifecycle_action_applies("reactivate", False)


def test_current_suspend_event_applies_only_to_inactive_license():
    assert _lifecycle_action_applies("suspend", False)
    assert not _lifecycle_action_applies("suspend", None)


def test_current_reactivate_event_applies_only_to_active_license():
    assert _lifecycle_action_applies("reactivate", True)
    assert not _lifecycle_action_applies("reactivate", None)


def test_explicit_session_revocation_is_independent_of_license_state():
    assert _lifecycle_action_applies("revoke_sessions", True)
    assert _lifecycle_action_applies("revoke_sessions", False)
    assert _lifecycle_action_applies("revoke_sessions", None)

def test_email_identity_update_is_scoped_to_license_and_normalizes_old_email():
    from scan_worker import _customer_email_identity_update_statement

    statement = _customer_email_identity_update_statement(
        42, "  Old.Customer@Example.com ", " New.Customer@Example.com "
    )
    compiled = statement.compile()
    sql = str(compiled).lower()

    assert "payment_webhook_events.license_id" in sql
    assert "lower(payment_webhook_events.recipient_email)" in sql
    assert 42 in compiled.params.values()
    assert "old.customer@example.com" in compiled.params.values()
    assert "New.Customer@Example.com" in compiled.params.values()

def test_delayed_explicit_session_revocation_is_bounded_to_sessions_existing_at_request_time():
    from pathlib import Path
    import inspect
    import main
    import scan_worker

    worker_source = inspect.getsource(scan_worker.reconcile_customer_lifecycle_outbox)
    admin_source = inspect.getsource(main.admin_customer_account_action)

    assert 'action == "revoke_sessions"' in worker_source
    revoke_branch = worker_source[worker_source.index('action == "revoke_sessions"'):]
    assert "CustomerSession.created_at <= event.created_at" in revoke_branch
    assert "CustomerSession.created_at <= now" in admin_source



def test_admin_customer_lifecycle_audit_is_attempted_before_operational_mutation():
    import inspect
    import main

    source = inspect.getsource(main.admin_customer_account_action)
    canonical_commit = source.index("await db.commit()")
    read_rollback = source.index("await operational_db.rollback()")
    audit_write = source.index('await _write_admin_log(db, "customer.account_"')
    operational_mutation = source.index("await operational_db.execute(update(CustomerAccount)")
    session_mutation = source.index("await operational_db.execute(update(CustomerSession)")
    helper_source = inspect.getsource(main._write_admin_log)
    assert canonical_commit < read_rollback < audit_write < operational_mutation
    assert operational_mutation < session_mutation
    # The audit helper owns a separate Hostinger transaction and commits it
    # before returning; committing the Supabase session here would be unrelated.
    assert "async with HostingerAsyncSessionLocal() as operational_db" in helper_source
    assert "await operational_db.commit()" in helper_source
    assert "except Exception as exc" in helper_source
    assert '"operational_sync": "queued"' in source
    audit_payload = source[audit_write:operational_mutation]
    assert '"changed_count": changed' not in audit_payload



def test_customer_lifecycle_outbox_claim_preserves_per_license_event_order():
    from datetime import datetime, timezone
    from sqlalchemy.dialects import postgresql
    from scan_worker import _customer_lifecycle_outbox_claim_statement

    statement = _customer_lifecycle_outbox_claim_statement(
        datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
    )
    sql = str(statement.compile(dialect=postgresql.dialect())).lower().replace('"', "")

    # A newer lifecycle event cannot overtake an older pending event for
    # the same license, even while the older event is deferred for retry.
    assert "not (exists (select" in sql
    assert "customer_lifecycle_sync_outbox_1.license_key = customer_lifecycle_sync_outbox.license_key" in sql
    assert "customer_lifecycle_sync_outbox_1.status =" in sql
    assert "customer_lifecycle_sync_outbox_1.created_at < customer_lifecycle_sync_outbox.created_at" in sql
    assert "customer_lifecycle_sync_outbox_1.id < customer_lifecycle_sync_outbox.id" in sql
    assert "customer_lifecycle_sync_outbox.next_attempt_at <= " in sql
    assert "order by customer_lifecycle_sync_outbox.created_at asc, customer_lifecycle_sync_outbox.id asc" in sql
    assert "for update skip locked" in sql


def test_customer_lifecycle_outbox_ordering_is_per_license():
    from datetime import datetime, timezone
    from scan_worker import _customer_lifecycle_outbox_claim_statement

    statement = _customer_lifecycle_outbox_claim_statement(
        datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
    )
    sql = str(statement.compile()).lower()

    assert "customer_lifecycle_sync_outbox_1.license_key = customer_lifecycle_sync_outbox.license_key" in sql
    assert "customer_lifecycle_sync_outbox_1.license_key !=" not in sql



def test_customer_lifecycle_worker_locks_canonical_license_before_operational_mirror():
    from sqlalchemy.dialects import postgresql
    from scan_worker import _customer_lifecycle_license_lock_query
    import inspect
    import scan_worker

    statement = _customer_lifecycle_license_lock_query("license-key")
    sql = str(statement.compile(dialect=postgresql.dialect())).lower().replace('"', "")

    assert "from software_licenses" in sql
    assert "software_licenses.license_key =" in sql
    assert "for update" in sql

    worker_source = inspect.getsource(scan_worker.reconcile_customer_lifecycle_outbox)
    lock_read = worker_source.index("_customer_lifecycle_license_lock_query(license_key)")
    operational_write = worker_source.index("async with HostingerAsyncSessionLocal() as operational_db:", lock_read)
    assert lock_read < operational_write


def test_admin_subscription_reconciliation_queues_customer_lifecycle_projection():
    import inspect
    import main

    source = inspect.getsource(main.admin_reconcile_subscription)
    previous_state = source.index("was_active = _license_is_current(license_obj, now)")
    period_update = source.index("billing_period_end = _apply_paddle_billing_period(", previous_state)
    current_state = source.index("current_active = _license_is_current(license_obj, now)", period_update)
    state_transition = source.index("if was_active != current_active:", current_state)
    outbox_insert = source.index("CustomerLifecycleSyncOutbox(", state_transition)
    canonical_commit = source.index("await db.commit()", outbox_insert)

    assert previous_state < period_update < current_state < state_transition < outbox_insert < canonical_commit
    assert 'action="reactivate" if current_active else "suspend"' in source
    assert "license_key=license_obj.license_key" in source
    assert 'status="pending"' in source


def test_paddle_lifecycle_transition_queues_customer_projection_only_when_state_changes():
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from main import _queue_customer_lifecycle_projection

    class FakeDB:
        def __init__(self):
            self.items = []

        def add(self, item):
            self.items.append(item)

    db = FakeDB()
    license_obj = SimpleNamespace(license_key="license-123", is_active=False, expires_at=None)
    now = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)

    assert _queue_customer_lifecycle_projection(db, license_obj, True, now)
    assert len(db.items) == 1
    assert db.items[0].action == "suspend"
    assert db.items[0].license_key == "license-123"
    assert db.items[0].status == "pending"
    assert db.items[0].attempts == 0
    assert db.items[0].next_attempt_at == now
    assert db.items[0].created_at == now

    assert not _queue_customer_lifecycle_projection(db, license_obj, False, now)
    assert len(db.items) == 1

    license_obj.is_active = True
    assert _queue_customer_lifecycle_projection(db, license_obj, False, now)
    assert db.items[-1].action == "reactivate"


def test_paddle_subscription_webhooks_queue_projection_before_canonical_commit():
    import inspect
    import main

    source = inspect.getsource(main.paddle_webhook)
    event_markers = (
        'if event_type in {"subscription.paused", "subscription.resumed", "subscription.activated"}:',
        'if event_type == "subscription.canceled":',
        'if event_type == "subscription.updated":',
    )
    for index, event_marker in enumerate(event_markers):
        start = source.index(event_marker)
        block_end = (
            source.index(event_markers[index + 1], start + len(event_marker))
            if index + 1 < len(event_markers)
            else len(source)
        )
        block = source[start:block_end]
        assert "_queue_customer_lifecycle_projection(" in block
        assert block.index("_queue_customer_lifecycle_projection(") < block.index("await db.commit()")


def test_license_projection_treats_expired_active_license_as_inactive():
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from scan_worker import _license_projection_is_active

    now = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
    expired = SimpleNamespace(is_active=True, expires_at=now - timedelta(seconds=1))
    current = SimpleNamespace(is_active=True, expires_at=now + timedelta(seconds=1))
    no_expiry = SimpleNamespace(is_active=True, expires_at=None)
    inactive = SimpleNamespace(is_active=False, expires_at=now + timedelta(days=1))

    assert _license_projection_is_active(expired, now) is False
    assert _license_projection_is_active(current, now) is True
    assert _license_projection_is_active(no_expiry, now) is True
    assert _license_projection_is_active(inactive, now) is False
    assert _license_projection_is_active(None, now) is None


def test_admin_expiry_change_queues_effective_access_lifecycle_projection():
    import inspect
    import main

    source = inspect.getsource(main.admin_update_client)
    assert "previous_active = _license_is_current(client, lifecycle_now)" in source
    assert "current_active = _license_is_current(client, lifecycle_now)" in source
    assert "if current_active != previous_active:" in source
    assert 'action="reactivate" if current_active else "suspend"' in source
    assert "if \"is_active\" in changes and" not in source


def test_paddle_lifecycle_projection_suspends_expired_but_raw_active_license():
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from main import _queue_customer_lifecycle_projection

    class FakeDB:
        def __init__(self):
            self.items = []

        def add(self, item):
            self.items.append(item)

    now = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
    db = FakeDB()
    license_obj = SimpleNamespace(
        license_key="license-expired",
        is_active=True,
        expires_at=now - timedelta(seconds=1),
    )

    assert _queue_customer_lifecycle_projection(db, license_obj, True, now)
    assert len(db.items) == 1
    assert db.items[0].action == "suspend"
