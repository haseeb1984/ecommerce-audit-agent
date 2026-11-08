from pathlib import Path


def test_customer_white_label_settings_apply_to_the_portal_theme():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text(encoding="utf-8")

    assert 'id="portalBrandName"' in portal
    assert 'id="brandLogo"' in portal
    assert "--brand-primary" in portal
    assert "background:var(--brand-primary)" in portal
    assert "function applyBranding(branding)" in portal
    assert 'document.documentElement.style.setProperty("--brand-primary", color)' in portal
    assert "applyBranding(branding);" in portal
    assert "applyBranding(saved);" in portal
    assert 'applyBranding(null);' in portal


def test_customer_white_label_save_supports_passwordless_bearer_sessions():
    portal = (Path(__file__).resolve().parents[1] / "customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function saveBranding()")
    end = portal.index("async function loadAgencyUsage", start)
    handler = portal[start:end]

    assert 'if (!credential && !sessionToken)' in handler
    assert 'api("/api/v1/account/branding"' in handler
    assert "applyBranding(saved);" in handler
    assert 'finally { button.disabled = !credential && !sessionToken; }' in handler
