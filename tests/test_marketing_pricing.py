from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_public_marketing_pricing_uses_live_operator_catalogue_values():
    html = (ROOT / "marketing.html").read_text(encoding="utf-8")
    assert 'fetch("/api/v1/billing/plans"' in html
    assert "formatPrice(plan)" in html
    assert "plan.monthly_audit_allowance" in html
    assert "plan.max_concurrent_audits" in html
    assert "plan.features[featureKey]===true" in html
    assert "/api/v1/billing/checkout" in html


def test_public_plan_comparison_does_not_hardcode_package_limits_or_entitlements():
    html = (ROOT / "marketing.html").read_text(encoding="utf-8")
    assert "<td>100</td>" not in html
    assert "<td>500</td>" not in html
    assert "<td>2,000</td>" not in html
    assert 'id="planComparisonBody"' in html
    assert "featureDefinitions.map" in html



def test_public_pricing_filters_only_supported_tiers_without_undefined_feature_map():
    html = (ROOT / "marketing.html").read_text(encoding="utf-8")
    assert 'const supportedTiers=new Set(order)' in html
    assert 'if(!supportedTiers.has(tier))continue;' in html
    assert 'if(!features[tier])continue;' not in html



def test_public_pricing_checkout_uses_defined_dom_lookup():
    html = (ROOT / "marketing.html").read_text(encoding="utf-8")
    assert 'const byId=id=>document.getElementById(id);' in html
    assert 'byId("checkoutEmail").value.trim()' in html
    assert '$("checkoutEmail")' not in html



def test_public_pricing_comparison_uses_only_supported_package_tiers():
    html = (ROOT / "marketing.html").read_text(encoding="utf-8")
    assert 'data.plans.filter(plan=>supportedTiers.has(String(plan.tier||"").toLowerCase()))' in html
    assert 'for(const plan of plans)header.append(el("th",plan.label))' in html
