"""Canonical SaaS plan entitlements. Unknown tiers fail closed."""
from typing import Any


def plan_features(tier: Any) -> dict[str, bool]:
    normalized = "starter" if tier is None else str(tier).strip().lower().replace("-", "_").replace(" ", "_")
    standard = normalized in {"starter", "pro", "business"}
    dossier = normalized in {"pro", "business"}
    white_label = normalized == "business"
    return {
        "standard_audits": standard,
        "conversion_dossier": dossier,
        "white_label_branding": white_label,
        "direct_api_access": white_label,
    }
