from pathlib import Path

import main


def test_admin_agency_inventory_is_searchable_and_bounded():
    import inspect

    source = inspect.getsource(main.admin_list_business_agencies)
    assert 'search: str = Query(default="", max_length=254)' in source
    assert 'status: str = Query(default="all", max_length=16)' in source
    assert 'limit: int = Query(default=50, ge=1, le=100)' in source
    assert 'offset: int = Query(default=0, ge=0, le=1000000)' in source
    assert 'func.lower(AgencyAccount.owner_email).like' in source
    assert 'status not in {"all", "active", "suspended"}' in source
    assert '"has_more": offset + len(agencies) < total' in source
    assert 'Cache-Control' in source and 'no-store, private' in source


def test_admin_agency_inventory_portal_has_filters_pagination_and_stale_guards():
    portal = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert 'id="agencySearch"' in portal
    assert 'id="agencyStatusFilter"' in portal
    assert 'id="agencyPrev"' in portal
    assert 'id="agencyNext"' in portal
    assert 'id="agencyPageInfo"' in portal
    assert 'agencyRequestVersion' in portal
    assert 'requestVersion!==agencyRequestVersion' in portal
    assert 'sessionVersion!==adminSessionVersion' in portal
    assert 'agencyRequestVersion+=1' in portal
