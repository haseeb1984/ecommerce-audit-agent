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
