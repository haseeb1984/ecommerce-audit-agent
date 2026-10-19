"""Conservative static HTML performance signals; not Core Web Vitals measurements."""
from __future__ import annotations

from html.parser import HTMLParser

from audit_checks import AuditFinding


MAX_EXTERNAL_SCRIPTS_REVIEW = 10
MAX_STYLESHEETS_REVIEW = 5
LARGE_INLINE_BYTES_REVIEW = 50_000


class _ResourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.images = 0
        self.images_without_dimensions = 0
        self.external_scripts = 0
        self.stylesheets = 0
        self.inline_script_bytes = 0
        self.inline_style_bytes = 0
        self._script_inline = False
        self._style_inline = False

    def handle_starttag(self, tag, attrs):
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "img":
            self.images += 1
            if not values.get("width") or not values.get("height"):
                self.images_without_dimensions += 1
        elif tag == "script":
            if values.get("src"):
                self.external_scripts += 1
                self._script_inline = False
            else:
                self._script_inline = True
        elif tag == "style":
            self._style_inline = True
        elif tag == "link":
            rel = set(values.get("rel", "").lower().split())
            if "stylesheet" in rel and values.get("href"):
                self.stylesheets += 1

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            self._script_inline = False
        elif tag.lower() == "style":
            self._style_inline = False

    def handle_data(self, data):
        size = len(data.encode("utf-8"))
        if self._script_inline:
            self.inline_script_bytes += size
        if self._style_inline:
            self.inline_style_bytes += size


def inspect_static_performance_signals(html: str, page_url: str) -> list[AuditFinding]:
    """Return review signals from HTML only; do not infer speed scores or CWV."""
    parser = _ResourceParser()
    try:
        parser.feed(html)
    except Exception:
        return []

    findings: list[AuditFinding] = []
    if parser.images_without_dimensions:
        findings.append(AuditFinding(
            category="performance",
            title="Images lack explicit width or height attributes",
            status="manual_review_required",
            severity="low",
            evidence=(
                f"{parser.images_without_dimensions} of {parser.images} inspected img element(s) "
                f"on {page_url} lack an explicit width or height attribute in returned HTML."
            ),
            explanation=(
                "Browsers can reserve space for images more reliably when dimensions or an equivalent "
                "aspect ratio are known. Missing dimensions can contribute to layout shifts, but CSS "
                "or other page behavior may already reserve the space."
            ),
            recommendation=(
                "Check the rendered layout and set accurate intrinsic width/height attributes or an "
                "appropriate CSS aspect-ratio for images, preserving responsive sizing."
            ),
            verification_steps=[
                "Inspect the image element and its computed layout in browser developer tools.",
                "Retest layout shifts with Lighthouse or PageSpeed Insights after changes.",
            ],
            source_url=page_url,
        ))

    if parser.external_scripts > MAX_EXTERNAL_SCRIPTS_REVIEW:
        findings.append(AuditFinding(
            category="performance",
            title="Many external script elements need review",
            status="manual_review_required",
            severity="low",
            evidence=(
                f"The returned HTML contains {parser.external_scripts} external script element(s) "
                f"on {page_url}; the review threshold is more than {MAX_EXTERNAL_SCRIPTS_REVIEW}."
            ),
            explanation=(
                "Scripts can add network requests and main-thread work, but the count alone does not "
                "measure bytes, execution time, caching, or whether scripts are necessary."
            ),
            recommendation=(
                "Use a browser network trace and performance profile to identify expensive or duplicate "
                "scripts. Remove unused tags and defer non-critical work only after checking functionality."
            ),
            verification_steps=[
                "Inspect the Network and Performance panels on a cold mobile-style load.",
                "Confirm important analytics and storefront interactions still work after changes.",
            ],
            source_url=page_url,
        ))

    if parser.stylesheets > MAX_STYLESHEETS_REVIEW:
        findings.append(AuditFinding(
            category="performance",
            title="Many stylesheet links need review",
            status="manual_review_required",
            severity="info",
            evidence=(
                f"The returned HTML contains {parser.stylesheets} linked stylesheet element(s) "
                f"on {page_url}; the review threshold is more than {MAX_STYLESHEETS_REVIEW}."
            ),
            explanation=(
                "Stylesheets may delay first rendering, but count alone does not reveal file size, "
                "caching, critical CSS, or browser behavior."
            ),
            recommendation=(
                "Use a browser network trace to identify render-blocking CSS and duplicate or unused "
                "stylesheets. Consolidate or defer only where it is safe for the storefront."
            ),
            verification_steps=[
                "Check the exact URL in PageSpeed Insights or Lighthouse for render-blocking resources.",
                "Retest visual layout and interactions after any CSS changes.",
            ],
            source_url=page_url,
        ))

    for label, size in (
        ("inline JavaScript", parser.inline_script_bytes),
        ("inline CSS", parser.inline_style_bytes),
    ):
        if size > LARGE_INLINE_BYTES_REVIEW:
            findings.append(AuditFinding(
                category="performance",
                title=f"Large {label} block needs review",
                status="manual_review_required",
                severity="info",
                evidence=(
                    f"Approximately {size} UTF-8 bytes of {label} were found in the returned HTML "
                    f"for {page_url}; the review threshold is {LARGE_INLINE_BYTES_REVIEW} bytes."
                ),
                explanation=(
                    "Large inline blocks can increase HTML transfer and parsing work. This static "
                    "estimate does not measure compression, execution cost, or cache effectiveness."
                ),
                recommendation=(
                    "Profile the page before changing assets. Consider external, cacheable files or "
                    "removing unused code when measurements show a benefit."
                ),
                verification_steps=[
                    "Measure transferred compressed bytes and main-thread work in browser developer tools.",
                    "Compare lab performance before and after the change.",
                ],
                source_url=page_url,
            ))
    return findings
