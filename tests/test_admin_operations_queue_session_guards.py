from pathlib import Path


PORTAL = Path(__file__).resolve().parents[1] / "admin_portal.html"


def _section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def test_scan_operations_refresh_ignores_stale_session_and_older_page_requests():
    source = PORTAL.read_text(encoding="utf-8")
    loader = _section(source, "async function refreshScanOperations", "async function retrySyncOutbox")

    assert "scanOperationsRequestVersion=0" in source
    assert "const requestSessionVersion=adminSessionVersion,requestVersion=++scanOperationsRequestVersion;" in loader
    assert "requestSessionVersion!==adminSessionVersion||requestVersion!==scanOperationsRequestVersion" in loader
    assert loader.index("requestSessionVersion!==adminSessionVersion||requestVersion!==scanOperationsRequestVersion") < loader.index('const c=d.counts||{}')
    assert "if(requestSessionVersion!==adminSessionVersion||requestVersion!==scanOperationsRequestVersion)return;" in loader


def test_admin_logout_invalidates_inflight_scan_operations_refresh():
    source = PORTAL.read_text(encoding="utf-8")
    clear = _section(source, "function clearAdminData", '$("createClientApiKey")')

    assert "scanOperationsRequestVersion++" in clear


def test_sync_outbox_retry_uses_session_guarded_admin_post():
    source = PORTAL.read_text(encoding="utf-8")
    retry = _section(source, "async function retrySyncOutbox", '$("retryLifecycleOutbox")')

    assert "const requestSessionVersion=adminSessionVersion" in retry
    assert 'await adminPost("/api/v1/admin/sync-outboxes/retry?"+query.toString())' in retry
    assert "if(requestSessionVersion!==adminSessionVersion)return;" in retry
    assert "finally{if(requestSessionVersion===adminSessionVersion)button.disabled=!key}" in retry


def test_failed_scan_job_retry_cannot_update_or_alert_in_a_new_admin_session():
    source = PORTAL.read_text(encoding="utf-8")
    loader = _section(source, "async function refreshScanOperations", "async function retrySyncOutbox")

    assert "const actionSessionVersion=adminSessionVersion;" in loader
    assert "await adminPost(" in loader
    assert "if(actionSessionVersion!==adminSessionVersion)return;" in loader
    assert "if(actionSessionVersion===adminSessionVersion){alert(" in loader



def test_admin_operations_diagnostics_refresh_ignores_older_requests_and_sessions():
    source = PORTAL.read_text(encoding="utf-8")
    loader = _section(source, "async function refreshOps", "async function refreshScanOperations")

    assert "opsRequestVersion=0" in source
    assert "const requestSessionVersion=adminSessionVersion,requestVersion=++opsRequestVersion;" in loader
    assert "requestSessionVersion!==adminSessionVersion||requestVersion!==opsRequestVersion" in loader
    assert loader.index("requestVersion!==opsRequestVersion") < loader.index('const h=d.health')


def test_admin_logout_invalidates_operations_diagnostics_and_refresh_feedback_is_session_guarded():
    source = PORTAL.read_text(encoding="utf-8")
    clear = _section(source, "function clearAdminData", '$("createClientApiKey")')
    handler = _section(source, '$("opsRefresh").addEventListener', '$("search").addEventListener')

    assert "opsRequestVersion++" in clear
    assert "const version=adminSessionVersion" in handler
    assert "if(version===adminSessionVersion)" in handler



def test_admin_dashboard_refresh_stops_when_session_is_cleared_between_panels():
    source = PORTAL.read_text(encoding="utf-8")
    refresh = _section(source, "async function refresh(){", '$("scanJobsRefresh").addEventListener')

    assert "const requestSessionVersion=adminSessionVersion;" in refresh
    for awaited in [
        "await loadClientPage(0);",
        "await loadCustomerDirectory();",
        "await refreshOps();",
        "await refreshAgencies();",
        "await refreshPackages();",
        "await refreshActions();",
        "await refreshPaymentEvents(0);",
        "await refreshScanJobs(0);",
    ]:
        assert awaited in refresh
    assert refresh.count("if(requestSessionVersion!==adminSessionVersion)return;") >= 8
    assert refresh.index("if(requestSessionVersion!==adminSessionVersion)return;") < refresh.index('status("Connected.')


def test_manual_admin_dashboard_refresh_does_not_report_old_session_errors():
    source = PORTAL.read_text(encoding="utf-8")
    handler = _section(source, '$("refresh").addEventListener', '$("opsRefresh").addEventListener')

    assert "const version=adminSessionVersion" in handler
    assert "if(version===adminSessionVersion)" in handler
