"""Explicitly record high-value audit checks that this deployment does not perform.

These records prevent a public HTML crawl from being mistaken for rendered-browser,
owner-authorized, or external-dataset verification. They are check outcomes, not findings.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from audit_checks import CheckOutcome


UNAVAILABLE_CHECKS: tuple[tuple[str, str, str], ...] = (
    (
        "crawl.javascript_rendered_dom",
        "crawlability",
        "A controlled browser did not complete a rendered DOM inspection for this run.",
    ),
    (
        "mobile_ux.rendered_orientation",
        "mobile_ux",
        "A controlled browser did not compare rendered horizontal overflow in portrait and landscape viewports for this run.",
    ),
    (
        "mobile_ux.rendered_viewport_matrix",
        "mobile_ux",
        "A controlled browser did not complete the agreed rendered viewport matrix for this run.",
    ),
    (
        "performance.browser_navigation_timing",
        "performance",
        "A controlled browser did not collect Navigation Timing and Resource Timing diagnostics for this run.",
    ),
    (
        "performance.browser_console_errors",
        "performance",
        "Browser console errors and uncaught page exceptions were not collected for this run.",
    ),
    (
        "performance.browser_network_failures",
        "performance",
        "Rendered-page network failures were not collected for this run.",
    ),
    (
        "accessibility.rendered_images_alt",
        "accessibility",
        "A controlled browser did not inspect image alt-attribute presence in the rendered DOM for this run.",
    ),
    (
        "accessibility.rendered_controls_name",
        "accessibility",
        "A controlled browser did not inspect rendered interactive-control naming heuristics for this run.",
    ),
    (
        "ecommerce.product_page_rendered_signals",
        "ecommerce",
        "A controlled browser did not inspect rendered product-page identity, price, and purchase-control signals for this run.",
    ),
    (
        "accessibility.manual_wcag_review",
        "accessibility",
        "Keyboard, screen-reader, zoom/reflow, and other manual WCAG review steps are not performed by this public automated scan.",
    ),
    (
        "indexing.google_search_console",
        "indexing",
        "No owner-authorized Google Search Console connection or export is available in this audit request; public crawl signals do not establish exact Google index status.",
    ),
    (
        "backlink_competitor.external_dataset",
        "backlink_competitor",
        "No backlink or competitor dataset/API result is supplied to this run, so external link metrics and competitor rankings are not assessed.",
    ),
    (
        "conversion.checkout_authorized_test",
        "conversion_paid_traffic",
        "No owner-authorized checkout test environment is used; this audit does not submit orders, payments, emails, or customer data.",
    ),
    (
        "pixel_analytics.consent_event_verification",
        "pixel_analytics",
        "Detected tags do not prove event firing or attribution; consent-dependent behavior and authenticated event flows are not verified in this public scan.",
    ),
    (
        "security.authenticated_active_testing",
        "security_baseline",
        "Authenticated or active penetration testing is outside this passive public scan and requires separate explicit authorization and scope.",
    ),
    (
        "trust.badge_authenticity_review",
        "trust",
        "Visible trust marks can be detected, but their authenticity, business legitimacy, and legal sufficiency are not established by presence checks.",
    ),
)


def append_unavailable_check_outcomes(result: Any, *, browser_audit_completed: bool = False) -> int:
    """Append one honest not-assessed outcome per unsupported verification method."""
    existing = {
        str(getattr(item, "check_id", "") or "")
        for item in getattr(result, "check_outcomes", [])
    }
    now = datetime.now(timezone.utc).isoformat()
    added = 0
    browser_checks = {"crawl.javascript_rendered_dom", "mobile_ux.rendered_viewport_matrix", "mobile_ux.rendered_orientation", "performance.browser_console_errors", "performance.browser_network_failures", "performance.browser_navigation_timing", "accessibility.rendered_images_alt", "accessibility.rendered_controls_name", "ecommerce.product_page_rendered_signals"}
    for check_id, category, evidence in UNAVAILABLE_CHECKS:
        if browser_audit_completed and check_id in browser_checks:
            continue
        if check_id in existing:
            continue
        result.check_outcomes.append(CheckOutcome(
            check_id=check_id,
            category=category,
            page_url=result.target_url,
            outcome="not_assessed",
            observed_at_utc=now,
            method="audit capability/authorization boundary",
            evidence=evidence,
            evidence_ref=check_id,
        ))
        added += 1
    if added:
        result.limitations.append(
            "Several verification methods are explicitly not assessed in this deployment: rendered-browser diagnostics, manual WCAG review, owner-authorized Google Search Console data, external backlink/competitor datasets, authorized checkout testing, consent-dependent event verification, and active security testing. See the per-check outcome records for exact boundaries."
        )
    return added
