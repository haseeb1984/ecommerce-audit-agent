"""Canonical SaaS package entitlements. Unknown tiers fail closed."""
from typing import Any


def plan_features(tier: Any) -> dict[str, bool]:
    """Return the single canonical feature contract for Starter, Pro, and Business."""
    normalized = "starter" if tier is None else str(tier).strip().lower().replace("-", "_").replace(" ", "_")
    known = normalized in {"starter", "pro", "business"}
    pro_or_business = normalized in {"pro", "business"}
    business = normalized == "business"
    return {
        "standard_audits": known,
        "conversion_dossier": pro_or_business,
        "white_label_branding": pro_or_business,
        "agency_management": business,
        "direct_api_access": business,
    }
