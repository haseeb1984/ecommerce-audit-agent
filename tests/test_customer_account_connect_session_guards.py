"""Regression tests for customer account connection session lifecycle guards."""

from pathlib import Path


PORTAL = Path(__file__).resolve().parents[1] / "customer_portal.html"


def _connect_handler():
    source = PORTAL.read_text(encoding="utf-8")
    start = source.index('  $("connect").addEventListener("click", async () => {')
    end = source.index('  $("logoutOtherSessions").addEventListener', start)
    return source[start:end]


def test_connection_checks_session_after_billing_history_load():
    handler = _connect_handler()
    assert "await loadBillingHistory();\n      if (attemptSessionVersion !== accountSessionVersion) return;" in handler


def test_connection_checks_session_after_parallel_account_loads():
    handler = _connect_handler()
    expected = "const results = await Promise.allSettled([loadReports(), loadUsage(), loadApiKeys(), loadActivity(), loadProfile(), loadWordPressSites(), loadScanBatches()]);\n      if (attemptSessionVersion !== accountSessionVersion) return;"
    assert expected in handler


def test_optional_branding_and_agency_loads_cannot_finish_obsolete_connection():
    handler = _connect_handler()
    assert "const brandingResult = await Promise.allSettled([loadBranding()]);\n        if (attemptSessionVersion !== accountSessionVersion) return;" in handler
    assert "const agencyResult = await Promise.allSettled([loadAgencyDashboard()]);\n        if (attemptSessionVersion !== accountSessionVersion) return;" in handler


def test_final_connection_ui_mutations_require_current_session():
    handler = _connect_handler()
    assert "if (attemptSessionVersion !== accountSessionVersion) return;\n      const unavailable =" in handler
    assert "if (attemptSessionVersion !== accountSessionVersion) return;\n      clearAccountView();" in handler
    assert 'if (attemptSessionVersion === accountSessionVersion) $("connect").disabled = false;' in handler
