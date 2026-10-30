"""Canonical SaaS plan entitlements. Unknown tiers fail closed."""
from typing import Any


def plan_features(tier: Any) -> dict[str, bool]:
    normalized = "starter" if tier is None else str(tier).strip().lower().replace("-", "_").replace(" ", "_")
    standard = normalized in {"starter", "agency", "pro", "agency_pro", "business", "whitelabel", "white_label", "enterprise"}
    dossier = normalized in {"agency", "pro", "agency_pro", "business", "whitelabel", "white_label", "enterprise"}
    white_label = normalized in {"business", "whitelabel", "white_label", "enterprise"}
    return {
        "standard_audits": standard,
        "conversion_dossier": dossier,
        "white_label_branding": white_label,
        "direct_api_access": white_label,
    }
