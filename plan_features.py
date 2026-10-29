"""Canonical, display-safe plan feature metadata for customer interfaces.

This is a feature catalogue, not an authorization boundary. Protected backend
routes must enforce access independently before implementing premium actions.
"""
from typing import Any


def plan_features(tier: Any) -> dict[str, bool]:
    """Return feature availability for known SaaS tiers; unknown tiers fail closed."""
    # Preserve the legacy Starter default only for a missing database value;
    # an explicitly blank or unknown tier must not inherit plan entitlements.
    normalized = (
        "starter" if tier is None
        else str(tier).strip().lower().replace("-", "_").replace(" ", "_")
    )
    is_agency = normalized in {"agency", "pro", "agency_pro"}
    # "business" is the existing highest paid tier in the live billing catalogue.
    # Preserve its existing access while supporting the documented tier names.
    is_whitelabel = normalized in {"whitelabel", "white_label", "enterprise", "business"}

    return {
        "standard_audits": normalized in {
            "starter", "agency", "pro", "agency_pro",
            "whitelabel", "white_label", "enterprise", "business",
        },
        "conversion_dossier": is_agency or is_whitelabel,
        "white_label_branding": is_whitelabel,
        "direct_api_access": is_whitelabel,
    }
