"""Regression coverage for admin operations and customer session race protection."""
import inspect
from pathlib import Path
import pytest
import main
from admin_scan_api import router



def test_scan_operations_outbox_diagnostics_include_retry_pressure_and_due_age():
    route = next(route for route in router.routes if route.path == "/api/v1/admin/scan-operations")
    source = inspect.getsource(route.endpoint)

    assert '"max_attempts"' in source
    assert '"oldest_pending_at"' in source
    assert '"oldest_due_at"' in source
    assert 'func.max(model.attempts)' in source
    assert 'model.next_attempt_at <= datetime.now(timezone.utc)' in source


def test_admin_portal_displays_outbox_retry_pressure_and_oldest_due_timestamp():
    from pathlib import Path

    portal = Path("admin_portal.html").read_text(encoding="utf-8")

    assert 'label+" max attempts"' in portal
    assert 'label+" oldest pending"' in portal
    assert 'label+" oldest due"' in portal
import inspect

import main


def test_admin_activity_endpoint_supports_bounded_sanitized_filters():
    signature = inspect.signature(main.admin_action_history)
    assert any(getattr(item, "max_length", None) == 100 for item in signature.parameters["action"].default.metadata)
    assert any(getattr(item, "max_length", None) == 80 for item in signature.parameters["entity_type"].default.metadata)
    assert any(getattr(item, "max_length", None) == 160 for item in signature.parameters["entity_id"].default.metadata)

    source = inspect.getsource(main.admin_action_history)
    assert "AdminActionLog.action.ilike" in source
    assert "AdminActionLog.entity_type.ilike" in source
    assert "AdminActionLog.entity_id.ilike" in source
    assert "total_query = total_query.where(*filters)" in source
    assert "rows_query = rows_query.where(*filters)" in source
    assert 'response.headers["Cache-Control"] = "no-store, private"' in source
    assert "_sanitize_admin_log_value(parsed_details)" in source


def test_admin_activity_portal_exposes_filters_and_preserves_them_for_pagination():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert 'id="activityActionFilter"' in source
    assert 'id="activityEntityFilter"' in source
    assert 'id="activityEntityIdFilter"' in source
    assert 'query.set("action",actionFilter)' in source
    assert 'query.set("entity_type",entityFilter)' in source
    assert 'query.set("entity_id",entityIdFilter)' in source
    assert 'id="actionsFilterApply"' in source
from pathlib import Path


def test_admin_customer_directory_ignores_stale_search_and_pagination_responses():
    source = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert "let customerDirectoryRequestVersion = 0;" in source
    assert "const requestVersion=++customerDirectoryRequestVersion;" in source
    assert 'if(requestVersion!==customerDirectoryRequestVersion||search!==$("customerAccountSearch").value.trim())return;' in source
    assert 'const search=$("customerAccountSearch").value.trim();' in source


def test_admin_customer_detail_ignores_stale_account_responses_and_signout_invalidates_requests():
    source = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert "let customerDetailRequestVersion = 0;" in source
    assert "const requestVersion=++customerDetailRequestVersion;" in source
    assert "if(requestVersion!==customerDetailRequestVersion" in source
    assert "customerDirectoryRequestVersion++;customerDetailRequestVersion++;" in source
    assert 'selectedCustomerEmail="";' in source
from pathlib import Path


def test_agency_team_revocation_uses_agency_first_lock_order():
    source = Path("main.py").read_text(encoding="utf-8")
    start = source.index('@app.delete("/api/v1/account/agency/team/{member_id}")')
    end = source.index('@app.get("/api/v1/account/agency/clients")', start)
    route = source[start:end]

    assert "AgencyAccount.owner_license_key == license_obj.license_key" in route
    assert ").with_for_update())" in route
    assert "AgencyTeamMember.id == member_id" in route
    assert "AgencyTeamSession.team_member_id == member.id" in route
    assert "member.status = \"revoked\"" in route
    assert "delete(AgencyWorkspaceAccess)" in route


def test_customer_portal_confirms_and_reports_team_member_revocation():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadAgencyTeam(")
    end = portal.index("async function inviteAgencyTeam(", start)
    section = portal[start:end]

    assert "window.confirm(\"Revoke access for \" + item.email" in section
    assert 'method:"DELETE"' in section
    assert 'setStatus("agencyStatus", "Access revoked for " + item.email, "success")' in section
    assert "revoke.disabled = true" in section
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
    account_render = source.index('$(\"billingAccount\").textContent')
    assert stale_guard < account_render
    assert "requestVersion === billingRequestVersion && requestSessionVersion === accountSessionVersion" in source
    assert "if (requestVersion === billingRequestVersion)" in source
    assert "billingLoadingSessionVersion = -1;" in source


def test_customer_billing_history_uses_request_generation_state():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    assert "let billingLoadingSessionVersion = -1;" in portal
    assert "let billingRequestVersion = 0;" in portal
from pathlib import Path


ADMIN_PORTAL = Path(__file__).resolve().parents[1] / "admin_portal.html"


def _admin_section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def test_scan_operations_refresh_ignores_stale_session_and_older_page_requests():
    source = ADMIN_PORTAL.read_text(encoding="utf-8")
    loader = _admin_section(source, "async function refreshScanOperations", "async function retrySyncOutbox")

    assert "scanOperationsRequestVersion=0" in source
    assert "const requestSessionVersion=adminSessionVersion,requestVersion=++scanOperationsRequestVersion;" in loader
    assert "requestSessionVersion!==adminSessionVersion||requestVersion!==scanOperationsRequestVersion" in loader
    assert loader.index("requestSessionVersion!==adminSessionVersion||requestVersion!==scanOperationsRequestVersion") < loader.index('const c=d.counts||{}')
    assert "if(requestSessionVersion!==adminSessionVersion||requestVersion!==scanOperationsRequestVersion)return;" in loader


def test_admin_logout_invalidates_inflight_scan_operations_refresh():
    source = ADMIN_PORTAL.read_text(encoding="utf-8")
    clear = _admin_section(source, "function clearAdminData", '$("createClientApiKey")')

    assert "scanOperationsRequestVersion++" in clear


def test_sync_outbox_retry_uses_session_guarded_admin_post():
    source = ADMIN_PORTAL.read_text(encoding="utf-8")
    retry = _admin_section(source, "async function retrySyncOutbox", '$("retryLifecycleOutbox")')

    assert "const requestSessionVersion=adminSessionVersion" in retry
    assert 'await adminPost("/api/v1/admin/sync-outboxes/retry?"+query.toString())' in retry
    assert "if(requestSessionVersion!==adminSessionVersion)return;" in retry
    assert "finally{if(requestSessionVersion===adminSessionVersion)button.disabled=!key}" in retry


def test_failed_scan_job_retry_cannot_update_or_alert_in_a_new_admin_session():
    source = ADMIN_PORTAL.read_text(encoding="utf-8")
    loader = _admin_section(source, "async function refreshScanOperations", "async function retrySyncOutbox")

    assert "const actionSessionVersion=adminSessionVersion;" in loader
    assert "await adminPost(" in loader
    assert "if(actionSessionVersion!==adminSessionVersion)return;" in loader
    assert "if(actionSessionVersion===adminSessionVersion){alert(" in loader


def test_admin_sync_outbox_retry_uses_the_database_that_owns_each_queue():
    from main import admin_retry_sync_outbox

    source = inspect.getsource(admin_retry_sync_outbox)
    params = inspect.signature(admin_retry_sync_outbox).parameters

    assert params["db"].default.dependency.__name__ == "get_async_db"
    assert params["operational_db"].default.dependency.__name__ == "get_hostinger_db"
    assert '"customer_lifecycle": (CustomerLifecycleSyncOutbox, db)' in source
    assert '"customer_email_identity": (CustomerEmailIdentitySyncOutbox, operational_db)' in source
    assert '"billing_mirror": (BillingMirrorSyncOutbox, db)' in source
    assert "model, queue_db = selected" in source
    assert "await queue_db.execute(" in source
    assert "await queue_db.commit()" in source
    assert 'await _write_admin_log(\n        db,' in source


def test_admin_sync_outbox_retry_rejects_unknown_queue_before_database_access():
    from main import admin_retry_sync_outbox

    source = inspect.getsource(admin_retry_sync_outbox)
    assert "if selected is None:" in source
    assert source.index("if selected is None:") < source.index("await queue_db.execute(")


def test_admin_portal_exposes_retry_controls_for_all_sync_outboxes():
    from pathlib import Path

    portal = Path("admin_portal.html").read_text(encoding="utf-8")

    assert 'id="retryLifecycleOutbox"' in portal
    assert 'id="retryEmailIdentityOutbox"' in portal
    assert 'id="retryBillingMirrorOutbox"' in portal
    assert 'retrySyncOutbox("billing_mirror",$("retryBillingMirrorOutbox"))' in portal
    assert 'billing_mirror:"billing mirror"' in portal
    assert '$("retryBillingMirrorOutbox").disabled=false' in portal
    assert "if(button.disabled||!key)return;" in portal
    assert "const requestSessionVersion=adminSessionVersion;" in portal
    assert 'adminPost("/api/v1/admin/sync-outboxes/retry?"' in portal
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
"""Regression tests for customer device-session UI race protection."""

from pathlib import Path


PORTAL = Path(__file__).resolve().parents[1] / "customer_portal.html"


def _portal():
    return PORTAL.read_text(encoding="utf-8")


def _device_loader(source):
    start = source.index("  async function loadDeviceSessions() {")
    end = source.index("  async function loadWordPressSites(", start)
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


def _handler(source, start_marker, end_marker):
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


def test_revoke_other_sessions_guards_refresh_status_and_button_state():
    source = _portal()
    handler = _handler(source, '  $("logoutOtherSessions").addEventListener', '  $("logoutAllSessions").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert handler.count("if (operationSessionVersion !== accountSessionVersion) return;") == 2
    assert "if (operationSessionVersion === accountSessionVersion) setStatus" in handler
    assert "if (operationSessionVersion === accountSessionVersion) button.disabled" in handler


def test_logout_all_sessions_only_clears_the_account_that_authorized_the_request():
    source = _portal()
    handler = _handler(source, '  $("logoutAllSessions").addEventListener', '  $("disconnectAccount").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert "if (operationSessionVersion !== accountSessionVersion) return;" in handler
    assert "accountSessionVersion += 1;" in handler
    assert "if (operationSessionVersion === accountSessionVersion) setStatus" in handler


def test_email_change_request_does_not_publish_old_challenge_after_account_switch():
    source = _portal()
    handler = _handler(source, '  $("requestEmailChange").addEventListener', '  $("verifyEmailChange").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert "if (operationSessionVersion !== accountSessionVersion) return;" in handler
    assert "if (operationSessionVersion === accountSessionVersion)" in handler


def test_email_change_verification_guards_the_post_change_refresh_and_status():
    source = _portal()
    handler = _handler(source, '  $("verifyEmailChange").addEventListener', '  $("generateWordPressLinkCode").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert "const updatedSessionVersion = accountSessionVersion;" in handler
    assert "if (updatedSessionVersion !== accountSessionVersion) return;" in handler
    assert "if (operationSessionVersion === accountSessionVersion)" in handler


def test_wordpress_one_time_code_is_never_rendered_into_a_different_account_view():
    source = _portal()
    handler = _handler(source, '  $("generateWordPressLinkCode").addEventListener', '  $("copyWordPressLinkCode").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert "if (operationSessionVersion !== accountSessionVersion) return;" in handler
    assert "if (operationSessionVersion === accountSessionVersion) setStatus" in handler


def test_copy_wordpress_code_does_not_update_status_after_account_switch():
    source = _portal()
    handler = _handler(source, '  $("copyWordPressLinkCode").addEventListener', '  $("hideWordPressLinkCode").addEventListener')
    assert "const operationSessionVersion = accountSessionVersion;" in handler
    assert handler.count("if (operationSessionVersion === accountSessionVersion) setStatus") == 2