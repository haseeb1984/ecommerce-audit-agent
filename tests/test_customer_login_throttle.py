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
    lock_insert = source.index("mysql_insert(CustomerLoginThrottle)")
    lock_read = source.index(".with_for_update()", lock_insert)
    count_read = source.index("select(func.count(CustomerLoginChallenge.id))")
    latest_read = source.index("select(CustomerLoginChallenge)")
    assert lock_insert < lock_read < count_read < latest_read
    assert ".on_duplicate_key_update(" in source


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

    for source in (request_source, verify_source, logout_source):
        assert "_lock_customer_login_email(operational_db, email)" in source

    assert verify_source.index("_lock_customer_login_email") < verify_source.index("CustomerLoginChallenge.email == email")
    assert logout_source.index("_lock_customer_login_email") < logout_source.index("CustomerLoginChallenge.email == email")
    assert logout_source.index("CustomerLoginChallenge.consumed_at.is_(None)") < logout_source.index("update(CustomerSession)")
    assert ".with_for_update()" in logout_source


def test_customer_login_email_lock_uses_persistent_mysql_throttle_row():
    import inspect
    import main

    source = inspect.getsource(main._lock_customer_login_email)
    assert "mysql_insert(CustomerLoginThrottle)" in source
    assert "on_duplicate_key_update" in source
    assert "CustomerLoginThrottle.email == email" in source
    assert ".with_for_update()" in source
