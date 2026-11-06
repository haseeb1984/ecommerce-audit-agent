import inspect

import main


def test_admin_activity_endpoint_supports_bounded_sanitized_filters():
    signature = inspect.signature(main.admin_action_history)
    assert signature.parameters["action"].default.max_length == 100
    assert signature.parameters["entity_type"].default.max_length == 80
    assert signature.parameters["entity_id"].default.max_length == 160

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
