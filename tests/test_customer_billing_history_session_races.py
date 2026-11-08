from pathlib import Path


def test_customer_billing_history_new_session_supersedes_old_in_flight_load():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadBillingHistory")
    end = portal.index("async function loadApiKeys", start)
    source = portal[start:end]

    assert "const requestSessionVersion = accountSessionVersion;" in source
    assert "billingLoadingSessionVersion === requestSessionVersion" in source
    assert "const requestVersion = ++billingRequestVersion;" in source
    stale_guard = source.index(
        "if (requestVersion !== billingRequestVersion || requestSessionVersion !== accountSessionVersion) return;"
    )
    account_render = source.index('$("billingAccount").textContent')
    assert stale_guard < account_render
    assert "requestVersion === billingRequestVersion && requestSessionVersion === accountSessionVersion" in source
    assert "if (requestVersion === billingRequestVersion)" in source
    assert "billingLoadingSessionVersion = -1;" in source


def test_customer_billing_history_uses_request_generation_state():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    assert "let billingLoadingSessionVersion = -1;" in portal
    assert "let billingRequestVersion = 0;" in portal


def test_customer_billing_history_total_uses_distinct_union_count_in_sql():
    from main import _billing_history_event_count_query
    from sqlalchemy.dialects import postgresql

    statement = _billing_history_event_count_query(42, "license-example")
    compiled = statement.compile(dialect=postgresql.dialect())
    sql = str(compiled).lower()

    assert "count(*)" in sql
    assert "union" in sql
    assert "payment_webhook_events.event_id" in sql
    assert "customer_billing_events.event_id" in sql
    assert "payment_webhook_events.license_id" in sql
    assert "customer_billing_events.license_key" in sql
    assert 42 in compiled.params.values()
    assert "license-example" in compiled.params.values()
