"""Conservative viewport checks from returned HTML; not rendered mobile testing."""
from __future__ import annotations

from html.parser import HTMLParser

from audit_checks import AuditFinding


class _ViewportParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.declarations: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "meta":
            return
        values = {key.lower(): value or "" for key, value in attrs}
        if values.get("name", "").strip().lower() == "viewport":
            self.declarations.append(values.get("content", "").strip())


def inspect_mobile_viewport(html: str, page_url: str) -> list[AuditFinding]:
    """Flag missing/incomplete viewport declarations and source directives that disable zoom."""
    parser = _ViewportParser()
    try:
        parser.feed(html)
    except Exception:
        return []

    findings: list[AuditFinding] = []
    if not parser.declarations:
        findings.append(AuditFinding(
            category="mobile_ux",
            title="Viewport declaration not detected",
            status="manual_review_required",
            severity="medium",
            evidence=f'No meta name="viewport" declaration was found in returned HTML for {page_url}.',
            explanation="Without a viewport declaration, mobile browsers may lay out the page at a wider virtual width. This source check cannot establish actual rendering, and JavaScript may change the DOM.",
            recommendation='Inspect the rendered page; if the declaration is genuinely missing, use a responsive viewport such as width=device-width, initial-scale=1. Do not disable user zoom.',
            verification_steps=[
                'Inspect the rendered DOM and source for meta name="viewport".',
                "Test reflow at 320 CSS px and common mobile widths, including zoom and text enlargement.",
            ],
            source_url=page_url,
        ))
        return findings

    contents = [value.lower() for value in parser.declarations]
    combined = ",".join(contents)
    if not any("width=device-width" in value.replace(" ", "") for value in contents):
        findings.append(AuditFinding(
            category="mobile_ux",
            title="Viewport width setting needs mobile review",
            status="manual_review_required",
            severity="low",
            evidence=f"Found {len(parser.declarations)} viewport declaration(s), but none explicitly set width=device-width in returned HTML for {page_url}.",
            explanation="A non-device viewport width can make responsive layouts behave unexpectedly on narrow screens. This source-level signal does not prove a layout defect.",
            recommendation="Review the rendered mobile layout and use an appropriate device-width viewport if the current configuration is unintended.",
            verification_steps=[
                "Inspect the computed viewport and rendered layout in a mobile browser.",
                "Test reflow at 320 CSS px and common mobile widths.",
            ],
            source_url=page_url,
        ))

    if "user-scalable=no" in combined.replace(" ", "") or "maximum-scale=1" in combined.replace(" ", ""):
        findings.append(AuditFinding(
            category="mobile_ux",
            title="Viewport may restrict user zoom",
            status="manual_review_required",
            severity="medium",
            evidence=f"Viewport content includes a user-scalable=no or maximum-scale=1 directive in returned HTML for {page_url}.",
            explanation="Restricting zoom can prevent some users from enlarging content. Browser behavior varies, so the rendered experience still needs confirmation.",
            recommendation="Remove unnecessary zoom restrictions and confirm users can zoom or enlarge text without losing content or functionality.",
            verification_steps=[
                "Test pinch zoom and text enlargement on a mobile device or emulator.",
                "Check reflow and keyboard access after zooming.",
            ],
            source_url=page_url,
        ))
    return findings
