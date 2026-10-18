"""Generate a synthetic PDF fixture for CI layout review; never used for client audits."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Executing a file under scripts/ sets sys.path[0] to that directory, not the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_checks import AuditCheckResult, AuditFinding
from report_generator import render_audit_pdf


def build_sample() -> AuditCheckResult:
    """Return clearly synthetic findings that exercise long and multi-page layouts."""
    return AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc="2026-10-18T00:00:00+00:00",
        pages_checked=[
            "https://shop.example/",
            "https://shop.example/products/sample-item",
            "https://shop.example/collections/sample",
        ],
        limitations=[
            "SYNTHETIC FIXTURE FOR PDF LAYOUT QA ONLY — this is not a real website audit.",
            "The example domain and all observations below are fabricated test data.",
            "Only three example URLs are listed to exercise evidence-reference layout.",
            "No authenticated pages, forms, checkout actions, or JavaScript-rendered states were tested.",
        ],
        findings=[
            AuditFinding(
                category="accessibility",
                title="Form controls may lack programmatic labels",
                status="manual_review_required",
                severity="high",
                evidence="Synthetic fixture: an input control on the sample contact page had no detectable associated label.",
                explanation=(
                    "A visitor using assistive technology may not be told what information the field expects. "
                    "This source-level signal needs review in the rendered page because labels can also be supplied "
                    "through accessible-name mechanisms not visible to this basic check."
                ),
                recommendation=(
                    "Review each affected control in the browser and provide a visible label or a correctly associated "
                    "accessible name. Keep the label specific to the information requested and do not rely on placeholder "
                    "text as the only label."
                ),
                verification_steps=[
                    "Inspect the control's computed accessible name in browser developer tools.",
                    "Navigate to the control with a keyboard and confirm its purpose is clear.",
                    "Repeat with a screen reader and confirm the label is announced.",
                ],
                source_url="https://shop.example/contact",
            ),
            AuditFinding(
                category="performance",
                title="Images may be missing explicit dimensions",
                status="manual_review_required",
                severity="medium",
                evidence="Synthetic fixture: several image elements omitted width and height attributes in the initial HTML.",
                explanation=(
                    "When the browser cannot reserve space for an image before it loads, nearby content may shift. "
                    "This observation does not measure layout shift or prove that a user experienced a problem."
                ),
                recommendation=(
                    "Inspect the affected image templates. Where practical, provide intrinsic width and height or a stable "
                    "aspect ratio, and confirm that responsive styling preserves the intended image proportions."
                ),
                verification_steps=[
                    "Inspect the rendered image dimensions at mobile and desktop widths.",
                    "Run Lighthouse or PageSpeed Insights and review layout-shift diagnostics.",
                    "Compare the page before and after the change using the same test conditions.",
                ],
                source_url="https://shop.example/products/sample-item",
            ),
            AuditFinding(
                category="technical_seo",
                title="Product structured-data properties need review",
                status="manual_review_required",
                severity="medium",
                evidence=(
                    "Synthetic fixture: the sample product JSON-LD includes a Product object but the static response "
                    "does not expose every commonly checked property."
                ),
                explanation=(
                    "Some product details may not be represented in the structured data returned in the initial HTML. "
                    "This source-level check cannot establish eligibility for search rich results or determine whether "
                    "JavaScript adds further properties after load."
                ),
                recommendation=(
                    "Compare the structured data against the visible product details and the current search-engine "
                    "documentation. Add only accurate values that are also supported by the page content."
                ),
                verification_steps=[
                    "Inspect the complete JSON-LD in the rendered page.",
                    "Run the official Rich Results Test where supported.",
                    "Confirm price, currency, availability, and product details match the visible offer.",
                ],
                source_url="https://shop.example/products/sample-item",
            ),
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="audit-report-sample.pdf")
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    pdf = render_audit_pdf(build_sample())
    if not pdf.startswith(b"%PDF-") or len(pdf) < 1000:
        raise SystemExit("Sample PDF generation failed validation.")
    output.write_bytes(pdf)
    print(f"Generated synthetic PDF layout fixture: {output} ({len(pdf)} bytes)")


if __name__ == "__main__":
    main()
