from pathlib import Path
import inspect

import main


def test_agency_team_branding_endpoint_inherits_owner_branding():
    assert "/api/v1/agency/team/branding" in main.app.openapi()["paths"]
    source = inspect.getsource(main.get_agency_team_branding)

    assert "Depends(require_agency_team_session)" in source
    assert 'identity["agency"].owner_license_key' in source
    assert "CustomerBranding.license_key" in source
    assert '"brand_name"' in source
    assert '"logo_url"' in source
    assert '"primary_color"' in source
    assert 'response.headers["Cache-Control"] = "no-store, private"' in source


def test_agency_team_portal_applies_and_resets_inherited_branding():
    portal = (Path(__file__).resolve().parents[1] / "agency_portal.html").read_text(encoding="utf-8")

    assert 'id="agencyBrandName"' in portal
    assert 'id="agencyBrandLogo"' in portal
    assert "function applyAgencyBranding(branding)" in portal
    assert "--agency-brand-primary" in portal
    assert 'api("/api/v1/agency/team/branding"' in portal
    assert "applyAgencyBranding(branding);" in portal
    assert "applyAgencyBranding(null);" in portal
