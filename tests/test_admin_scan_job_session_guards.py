from pathlib import Path


PORTAL = Path(__file__).resolve().parents[1] / "admin_portal.html"


def test_admin_scan_job_refresh_ignores_stale_sessions_and_filter_requests():
    source = PORTAL.read_text(encoding="utf-8")
    start = source.index("async function refreshScanJobs")
    end = source.index("async function refreshOps", start)
    loader = source[start:end]

    assert "scanJobRequestVersion=0" in source
    assert "const requestSessionVersion=adminSessionVersion,requestVersion=++scanJobRequestVersion;" in loader
    assert "selectedStatus!==$(\"scanJobStatus\").value" in loader
    assert loader.index("requestVersion!==scanJobRequestVersion") < loader.index('const container=$(\"scanJobs\")')
    assert "requestVersion===scanJobRequestVersion" in loader


def test_admin_logout_invalidates_pending_scan_job_refreshes():
    source = PORTAL.read_text(encoding="utf-8")
    start = source.index("function clearAdminData")
    end = source.index('$("createClientApiKey")', start)
    clear = source[start:end]

    assert "scanJobRequestVersion++" in clear


def test_admin_scan_job_controls_do_not_report_errors_in_a_new_session():
    source = PORTAL.read_text(encoding="utf-8")
    start = source.index('$("scanJobsRefresh").addEventListener')
    end = source.index('$("failedScanJobsPrev").addEventListener', start)
    handlers = source[start:end]

    assert handlers.count("const version=adminSessionVersion") == 4
    assert handlers.count("if(version===adminSessionVersion)") == 4
