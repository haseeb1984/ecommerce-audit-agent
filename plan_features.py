"""Canonical, display-safe plan feature metadata for customer interfaces.

This is a feature catalogue, not an authorization boundary. Protected backend
routes must enforce access independently before implementing premium actions.
"""
from typing import Any


def plan_features(tier: Any) -> dict[str, bool]:
    """Return feature availability for known SaaS tiers; unknown tiers fail closed."""
    normalized = str(tier or "starter").strip().lower().replace("-", "_").replace(" ", "_")
    is_agency = normalized in {"agency", "pro", "agency_pro"}
    is_whitelabel = normalized in {"whitelabel", "white_label", "enterprise"}

    return {
        "standard_audits": normalized in {
            "starter", "agency", "pro", "agency_pro",
            "whitelabel", "white_label", "enterprise",
        },
        "conversion_dossier": is_agency or is_whitelabel,
        "white_label_branding": is_whitelabel,
        "direct_api_access": is_whitelabel,
    }
