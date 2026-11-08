def test_email_change_operational_updates_are_scoped_to_license():
    from datetime import datetime, timezone

    from main import _customer_email_change_operational_updates

    statements = _customer_email_change_operational_updates(
        license_key="license-customer-a",
        old_email="old@example.com",
        new_email="new@example.com",
        current_token_hash="current-session-hash",
        now=datetime.now(timezone.utc),
    )

    expected_tables = {
        "customer_accounts",
        "customer_billing_events",
        "wordpress_installations",
        "customer_login_challenges",
        "customer_sessions",
    }
    assert len(statements) == len(expected_tables)

    for statement in statements:
        sql = str(statement).lower()
        assert "license_key" in sql
        assert "license-customer-a" in statement.compile().params.values()
        assert "old@example.com" in statement.compile().params.values()

    assert {statement.table.name for statement in statements} == expected_tables


def test_email_change_does_not_revoke_current_session():
    from datetime import datetime, timezone

    from main import _customer_email_change_operational_updates

    statements = _customer_email_change_operational_updates(
        license_key="license-customer-a",
        old_email="old@example.com",
        new_email="new@example.com",
        current_token_hash="keep-this-session",
        now=datetime.now(timezone.utc),
    )
    session_update = next(
        statement for statement in statements
        if statement.table.name == "customer_sessions"
    )
    compiled = session_update.compile()
    assert "keep-this-session" in compiled.params.values()
    assert "revoked_at" in str(session_update).lower()



def test_email_change_request_and_verification_share_a_per_license_lock():
    import inspect
    import main

    request_source = inspect.getsource(main.request_customer_email_change)
    verify_source = inspect.getsource(main.verify_customer_email_change)

    for source in (request_source, verify_source):
        candidate_read = source.index("candidate = await operational_db.scalar")
        account_lock = source.index("_lock_customer_email_change_license")
        session_lock = source.index(".with_for_update()", account_lock)
        assert candidate_read < account_lock < session_lock
        assert "candidate.license_key" in source[account_lock:session_lock]

    request_lock = request_source.index("_lock_customer_email_change_license")
    rate_limit_read = request_source.index("select(func.count(CustomerEmailChangeChallenge.id))")
    assert request_lock < rate_limit_read

    verify_lock = verify_source.index("_lock_customer_email_change_license")
    challenge_lock = verify_source.index("CustomerEmailChangeChallenge.id == payload.challenge_id")
    assert verify_lock < challenge_lock


def test_email_change_throttle_model_schema_and_forward_migration_align():
    from pathlib import Path
    from hostinger_models import CustomerEmailChangeThrottle

    root = Path(__file__).resolve().parents[1]
    assert CustomerEmailChangeThrottle.__tablename__ == "customer_email_change_throttles"
    assert CustomerEmailChangeThrottle.__table__.primary_key.columns.keys() == ["license_key"]

    schema = (root / "migrations" / "hostinger_operational_schema.sql").read_text()
    migration = (root / "migrations" / "20261111_customer_email_change_throttle.sql").read_text()
    for source in (schema, migration):
        assert "CREATE TABLE IF NOT EXISTS customer_email_change_throttles" in source
        assert "license_key VARCHAR(100) NOT NULL PRIMARY KEY" in source

def test_email_change_revokes_only_sessions_existing_at_verification_time():
    from datetime import datetime, timezone
    from main import _customer_email_change_operational_updates

    cutoff = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
    statements = _customer_email_change_operational_updates(
        license_key="license-customer-a",
        old_email="old@example.com",
        new_email="new@example.com",
        current_token_hash="current-session",
        now=cutoff,
    )
    session_update = next(
        statement for statement in statements
        if statement.table.name == "customer_sessions"
    )
    compiled = session_update.compile()
    assert "customer_sessions.created_at" in str(session_update).lower()
    assert cutoff in compiled.params.values()


def test_email_change_verification_serializes_with_old_email_login_otp():
    import inspect
    import main

    source = inspect.getsource(main.verify_customer_email_change)
    account_lock = source.index("_lock_customer_email_change_license")
    login_email_lock = source.index("_lock_customer_login_email")
    session_lock = source.index(".with_for_update()", login_email_lock)
    challenge_lock = source.index("CustomerEmailChangeChallenge.id == payload.challenge_id")

    refreshed_identity = source.index("email_lock_candidate = await operational_db.scalar")
    assert account_lock < refreshed_identity < login_email_lock < session_lock < challenge_lock
    assert "locked_email = email_lock_candidate.email.strip().lower()" in source[refreshed_identity:login_email_lock]
    assert "_lock_customer_login_email(operational_db, locked_email)" in source[login_email_lock:session_lock]
    assert "if old_email != locked_email:" in source[session_lock:challenge_lock]
    assert "_customer_email_change_operational_updates" in source
