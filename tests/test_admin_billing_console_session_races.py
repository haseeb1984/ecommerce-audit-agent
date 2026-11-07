from pathlib import Path


PORTAL = Path(__file__).resolve().parents[1] / "admin_portal.html"


def _function(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def test_payment_event_refresh_ignores_stale_filter_and_previous_admin_session():
    source = PORTAL.read_text(encoding="utf-8")
    loader = _function(source, "async function refreshPaymentEvents", "async function refreshAgencies")

    assert "paymentEventRequestVersion=0" in source
    assert "const requestSessionVersion=adminSessionVersion,requestVersion=++paymentEventRequestVersion;" in loader
    assert "requestVersion!==paymentEventRequestVersion" in loader
    assert 'selectedStatus!==$("paymentEventStatus").value' in loader
    assert loader.index("requestVersion!==paymentEventRequestVersion") < loader.index('const box=$("paymentEvents")')
    assert "requestSessionVersion===adminSessionVersion" in loader


def test_admin_activity_refresh_is_scoped_to_latest_session_and_request():
    source = PORTAL.read_text(encoding="utf-8")
    loader = _function(source, "async function refreshActions", "let billingMirrorNextOffset")

    assert "actionsRequestVersion=0" in source
    assert "actionsLoadingSessionVersion=-1" in source
    assert "const requestSessionVersion=adminSessionVersion;" in loader
    assert "const requestVersion=++actionsRequestVersion;" in loader
    assert "requestVersion!==actionsRequestVersion||requestSessionVersion!==adminSessionVersion" in loader
    assert "if(requestVersion===actionsRequestVersion)" in loader


def test_admin_logout_invalidates_payment_and_activity_requests():
    source = PORTAL.read_text(encoding="utf-8")
    clear = _function(source, "function clearAdminData", '$("createClientApiKey")')

    assert "paymentEventRequestVersion++" in clear
    assert "actionsRequestVersion++" in clear
    assert "actionsLoadingSessionVersion=-1" in clear


def test_payment_mutations_do_not_render_or_update_status_after_admin_session_changes():
    source = PORTAL.read_text(encoding="utf-8")
    retry = _function(source, "async function retryLicenseEmail", "async function reconcilePayment")
    reconcile = _function(source, "async function reconcilePayment", "let scanJobOffset")

    assert "const requestSessionVersion=adminSessionVersion" in retry
    assert "assertAdminSession(requestSessionVersion)" in retry
    assert "if(requestSessionVersion===adminSessionVersion)" in retry
    assert "const requestSessionVersion=adminSessionVersion" in reconcile
    assert "assertAdminSession(requestSessionVersion)" in reconcile
    assert "container.append(result)" in reconcile
    assert "if(requestSessionVersion===adminSessionVersion)" in reconcile
