"""Regression tests for customer device-session UI race protection."""

from pathlib import Path


PORTAL = Path(__file__).resolve().parents[1] / "customer_portal.html"


def _portal():
    return PORTAL.read_text(encoding="utf-8")


def _device_loader(source):
    start = source.index("  async function loadDeviceSessions() {")
    end = source.index("  async function loadWordPressSites()", start)
    return source[start:end]


def test_device_session_refreshes_only_render_the_latest_response():
    loader = _device_loader(_portal())
    assert "const requestId = ++deviceSessionsRequestId;" in loader
    assert "const requestSessionVersion = accountSessionVersion;" in loader
    assert "if (requestId !== deviceSessionsRequestId || requestSessionVersion !== accountSessionVersion) return;" in loader


def test_device_session_view_is_cleared_and_inflight_refreshes_invalidated_on_disconnect():
    source = _portal()
    start = source.index("  function clearAccountView() {")
    end = source.index('  $("requestLoginCode").addEventListener', start)
    clear = source[start:end]
    assert "deviceSessionsRequestId += 1;" in clear
    assert '$("deviceSessions").replaceChildren();' in clear
    assert "Connect with email sign-in to view active devices." in clear


def test_device_revocation_does_not_update_a_new_account_session():
    loader = _device_loader(_portal())
    assert "const actionSessionVersion = accountSessionVersion;" in loader
    assert "if (actionSessionVersion !== accountSessionVersion) return;" in loader
    assert "if (actionSessionVersion === accountSessionVersion)" in loader


def test_device_list_does_not_expose_old_session_when_email_signin_is_unavailable():
    loader = _device_loader(_portal())
    assert 'if (!sessionToken) {' in loader
    assert 'Email sign-in is required to manage devices.' in loader
