import inspect
from pathlib import Path

import main


def test_admin_client_sessions_endpoint_has_bounded_offset_pagination():
    source = inspect.getsource(main.admin_list_client_sessions)

    assert "limit: int = Query(default=50, ge=1, le=100)" in source
    assert "offset: int = Query(default=0, ge=0, le=1000000)" in source
    assert "select(func.count()).select_from(session_base.subquery())" in source
    assert "session_base.order_by(CustomerSession.created_at.desc(), CustomerSession.token_hash.desc())" in source
    assert '"has_more": offset + len(items) < total' in source


def test_admin_client_sessions_panel_exposes_load_more_and_stale_response_guard():
    portal = Path("admin_portal.html").read_text()

    assert '"Load more sessions"' in portal
    assert '/sessions?limit=50&offset=0' in portal
    assert '"/sessions?limit="+data.limit+"&offset="+(data.offset+data.limit)' in portal
    assert "expectedDetailVersion!==clientDetailVersion||currentHistoryId!==id" in portal
