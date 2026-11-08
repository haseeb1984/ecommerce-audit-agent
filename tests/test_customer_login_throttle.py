"""Regression contract for race-safe customer passwordless login throttling."""

import inspect
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_customer_login_throttle_model_and_fresh_schema_are_aligned():
    from hostinger_models import CustomerLoginThrottle

    assert CustomerLoginThrottle.__tablename__ == "customer_login_throttles"
    assert CustomerLoginThrottle.__table__.primary_key.columns.keys() == ["email"]

    schema = (ROOT / "migrations" / "hostinger_operational_schema.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS customer_login_throttles" in schema
    assert "email VARCHAR(254) NOT NULL PRIMARY KEY" in schema


def test_customer_login_request_locks_stable_email_row_before_rate_limit_reads():
    import main

    endpoint = next(
        route.endpoint
        for route in main.app.routes
        if getattr(route, "path", None) == "/api/v1/account/auth/request-code"
    )
    source = inspect.getsource(endpoint)
    helper_source = inspect.getsource(main._lock_customer_login_email)
    lock_call = source.index("_lock_customer_login_email(operational_db, email)")
    count_read = source.index("select(func.count(CustomerLoginChallenge.id))")
    latest_read = source.index("select(CustomerLoginChallenge)")
    assert lock_call < count_read < latest_read
    lock_insert = helper_source.index("mysql_insert(CustomerLoginThrottle)")
    lock_read = helper_source.index(".with_for_update()", lock_insert)
    assert lock_insert < lock_read
    assert ".on_duplicate_key_update(" in helper_source


def test_existing_hostinger_databases_have_idempotent_throttle_table_migration():
    migration = (
        ROOT / "migrations" / "20261110_customer_login_email_throttle.sql"
    ).read_text()
    assert "CREATE TABLE IF NOT EXISTS customer_login_throttles" in migration
    assert "email VARCHAR(254) NOT NULL PRIMARY KEY" in migration
    assert "ENGINE=InnoDB" in migration


def test_customer_login_verification_and_logout_all_share_email_lock_order():
    import inspect
    import main

    request_source = inspect.getsource(main.request_account_login_code)
    verify_source = inspect.getsource(main.verify_account_login_code)
    logout_source = inspect.getsource(main.logout_all_account_sessions)

    assert "_lock_customer_login_email(operational_db, email)" in request_source
    assert "_lock_customer_login_email(operational_db, email)" in verify_source
    assert "_lock_customer_login_email(operational_db, email)" in logout_source

    assert verify_source.index("_lock_customer_login_email") < verify_source.index("CustomerLoginChallenge.email == email")
    account_lock = logout_source.index("_lock_customer_email_change_license")
    refreshed_identity = logout_source.index("refreshed = await operational_db.scalar")
    email_lock = logout_source.index("_lock_customer_login_email")
    session_lock = logout_source.index(".with_for_update()", email_lock)
    challenge_update = logout_source.index("CustomerLoginChallenge.consumed_at.is_(None)")
    session_update = logout_source.index("update(CustomerSession)")
    assert account_lock < refreshed_identity < email_lock < session_lock < challenge_update < session_update
    assert "email = refreshed.email.strip().lower()" in logout_source[refreshed_identity:email_lock]


def test_customer_login_email_lock_uses_persistent_mysql_throttle_row():
    import inspect
    import main

    source = inspect.getsource(main._lock_customer_login_email)
    assert "mysql_insert(CustomerLoginThrottle)" in source
    assert "on_duplicate_key_update" in source
    assert "CustomerLoginThrottle.email == email" in source
    assert ".with_for_update()" in source
