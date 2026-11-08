import inspect
from pathlib import Path

import main


def test_admin_client_wordpress_endpoint_has_bounded_offset_pagination():
    source = inspect.getsource(main.admin_list_client_wordpress_links)

    assert "limit: int = Query(default=50, ge=1, le=100)" in source
    assert "offset: int = Query(default=0, ge=0, le=1000000)" in source
    assert "select(func.count()).select_from(wordpress_base.subquery())" in source
    assert "wordpress_base.order_by(" in source
    assert ").offset(offset).limit(limit)" in source
    assert '"has_more": offset + len(rows) < total' in source


def test_admin_client_wordpress_panel_load_more_is_selection_guarded():
    portal = Path("admin_portal.html").read_text()

    assert '"Load more WordPress sites"' in portal
    assert '/wordpress-links?limit=50&offset=0' in portal
    assert '"/wordpress-links?limit="+data.limit+"&offset="+(data.offset+data.limit)' in portal
    assert "expectedDetailVersion!==clientDetailVersion||currentHistoryId!==id" in portal
