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
    audit_write = source.index('await _write_admin_log(db, "customer.account_"')
    operational_mutation = source.index("await operational_db.execute(update(CustomerAccount)")
    session_mutation = source.index("await operational_db.execute(update(CustomerSession)")
    assert canonical_commit < audit_write < operational_mutation
    assert audit_write < session_mutation
    assert '"operational_sync": "queued"' in source
    assert '"changed_count": changed' not in source
