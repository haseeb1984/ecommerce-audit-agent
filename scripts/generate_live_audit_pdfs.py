"""Generate evidence-based PDFs from real public websites in CI.

This is a non-production QA helper. It does not call the authenticated API, consume
license quota, store audit leads, or deploy anything. PageSpeed metrics are explicitly
marked as not run in this live-site smoke test.
"""
from __future__ import annotations

import asyncio
import argparse
import base64
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_checks import AuditCheckResult, AuditFinding, normalize_target, run_phase_one_checks
from crawl_checks import run_bounded_site_crawl
from report_generator import render_audit_pdf


async def capture_real_website_screenshot(url: str) -> str | None:
    """Capture a real browser viewport screenshot; return a JPEG data URI or None."""
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            page = await browser.new_page(viewport={"width": 1440, "height": 1000}, device_scale_factor=1)
            await page.goto(url, wait_until="domcontentloaded", timeout=25000)
            await page.wait_for_timeout(1200)
            image_bytes = await page.screenshot(type="jpeg", quality=72, full_page=False)
            await browser.close()
        if not image_bytes or len(image_bytes) > 900_000:
            return None
        return "data:image/jpeg;base64," + base64.b64encode(image_bytes).decode("ascii")
    except Exception as exc:
        # Never log raw browser errors; they may contain target URLs or request details.
        print(f"browser_screenshot=unavailable failure_class={type(exc).__name__}")
        return None


def _mobile_render_findings(page_url: str, metrics: dict) -> list[AuditFinding]:
    """Turn browser-observed mobile layout signals into conservative findings."""
    findings: list[AuditFinding] = []
    viewport_width = metrics.get("viewport_width")
    document_width = metrics.get("document_width")
    viewport_meta = metrics.get("viewport_meta", "")
    hidden_focusables = metrics.get("aria_hidden_focusables")
    if isinstance(viewport_width, (int, float)) and isinstance(document_width, (int, float)):
        overflow = max(0, int(document_width - viewport_width))
        if overflow > 2:
            findings.append(AuditFinding(category="mobile_ux", title="Rendered page overflows the mobile viewport",
                status="manual_review_required", severity="medium",
                evidence=f"At a {int(viewport_width)} CSS-pixel viewport, rendered document width was {int(document_width)}px (about {overflow}px wider).",
                explanation="Horizontal overflow can make storefront content and controls difficult to use on small screens. Intentional scrollable components need visual review.",
                recommendation="Inspect overflowing elements at mobile widths; fix page-level layout, media, and fixed-width components without removing intentional local scrolling.",
                verification_steps=["Recheck product, cart, and checkout flows at 320px, 375px, and 390px widths.", "Confirm important content and purchase controls are not clipped."], source_url=page_url))
    if not isinstance(viewport_meta, str) or not re.search(r"width\s*=\s*device-width", viewport_meta, re.I):
        findings.append(AuditFinding(category="mobile_ux", title="Rendered page lacks a device-width viewport declaration",
            status="manual_review_required", severity="medium",
            evidence="Browser did not find a viewport meta declaration containing width=device-width.",
            explanation="Without a suitable viewport declaration, mobile browsers may scale a wider virtual layout down, making text and controls harder to use.",
            recommendation="Add a suitable viewport meta declaration and validate zoom and responsive behavior on real devices.",
            verification_steps=["Inspect the page head for a responsive viewport declaration.", "Check text scaling and checkout usability on a mobile browser."], source_url=page_url))
    if isinstance(hidden_focusables, int) and hidden_focusables > 0:
        findings.append(AuditFinding(category="accessibility", title="Rendered focusable controls are hidden from assistive technology",
            status="manual_review_required", severity="medium",
            evidence=f"Browser found {hidden_focusables} focusable element(s) inside an aria-hidden subtree.",
            explanation="Keyboard users may focus controls that assistive technology is instructed to ignore; this signal requires contextual keyboard and accessibility-tree review.",
            recommendation="Remove aria-hidden from interactive ancestors or make the hidden subtree genuinely non-interactive while hidden.",
            verification_steps=["Tab through the page and verify focus never enters hidden content.", "Inspect the browser accessibility tree and test representative screen readers."], source_url=page_url))
    return findings


async def inspect_mobile_rendered_signals(url: str) -> tuple[list[AuditFinding], str | None]:
    """Inspect one real 390px browser viewport; do not infer Core Web Vitals."""
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            page = await browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=1)
            await page.goto(url, wait_until="domcontentloaded", timeout=25000)
            await page.wait_for_timeout(500)
            metrics = await page.evaluate("""() => ({
              viewport_width: window.innerWidth,
              document_width: document.documentElement.scrollWidth,
              viewport_meta: document.querySelector('meta[name=\"viewport\"]')?.getAttribute('content') || '',
              aria_hidden_focusables: Array.from(document.querySelectorAll('[aria-hidden=\"true\"]'))
                .flatMap(root => [root, ...root.querySelectorAll('*')])
                .filter((el, index, all) => all.indexOf(el) === index)
                .filter(el => {
                  const tag = el.tagName.toLowerCase();
                  const tabindex = el.getAttribute('tabindex');
                  const natural = (tag === 'a' && el.hasAttribute('href')) || ['button','input','select','textarea'].includes(tag);
                  return (natural || (tabindex !== null && Number(tabindex) >= 0)) && !el.hasAttribute('disabled');
                }).length
            })""")
            screenshot = await page.screenshot(type="jpeg", quality=68, full_page=False)
            await browser.close()
        screenshot_uri = "data:image/jpeg;base64," + base64.b64encode(screenshot).decode("ascii") if screenshot and len(screenshot) <= 900_000 else None
        return _mobile_render_findings(url, metrics), screenshot_uri
    except Exception as exc:
        print(f"mobile_render_inspection=unavailable failure_class={type(exc).__name__}")
        return [AuditFinding(category="mobile_ux", title="Rendered mobile checks could not be completed",
            status="not_tested", severity="info", evidence=f"Browser inspection unavailable ({type(exc).__name__}); no mobile layout conclusion was drawn.",
            explanation="Static HTML checks cannot establish rendered mobile layout or the browser accessibility tree.",
            recommendation="Rerun browser-based inspection in an environment with Chromium and Playwright installed.",
            verification_steps=["Run the manual browser QA workflow and review the generated live-site PDF."], source_url=url)], None

DEFAULT_TARGETS = [
    "https://juncsys.com",
    "https://junctiontools.com",
    "https://www.google.com",
    "https://www.facebook.com",
]


async def audit_one(target: str, output_dir: Path) -> tuple[str, bool]:
    normalized = normalize_target(target)
    ok = True
    try:
        result = await run_phase_one_checks(normalized)
        crawl_findings, crawl_pages, crawl_limitations = await run_bounded_site_crawl(normalized)
        result.findings.extend(crawl_findings)
        result.pages_checked = list(dict.fromkeys([*result.pages_checked, *crawl_pages]))
        result.limitations.extend(crawl_limitations)
    except Exception as exc:
        ok = False
        result = AuditCheckResult(
            target_url=normalized,
            checked_at_utc=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            findings=[],
            pages_checked=[],
            limitations=[
                "Live website check failed before sufficient evidence could be collected.",
                f"Failure class: {type(exc).__name__}. Sensitive exception details are intentionally omitted.",
            ],
        )

    result.limitations.append(
        "Google PageSpeed Insights API metrics were not run by this live-site smoke test; "
        "no mobile score or Speed Index is claimed."
    )
    mobile_findings, mobile_screenshot = await inspect_mobile_rendered_signals(normalized)
    result.findings.extend(mobile_findings)
    screenshot_data_uri = mobile_screenshot or await capture_real_website_screenshot(normalized)
    print(f"target={normalized} browser_screenshot={'captured' if screenshot_data_uri else 'unavailable'} mobile_findings={len(mobile_findings)}")
    pdf_bytes = render_audit_pdf(result, screenshot_data_uri=screenshot_data_uri)
    hostname = urlsplit(normalized).hostname or "website"
    safe_hostname = re.sub(r"[^a-zA-Z0-9.-]", "-", hostname)[:100]
    output = output_dir / f"live-audit-{safe_hostname}.pdf"
    output.write_bytes(pdf_bytes)
    print(
        f"target={normalized} pdf={output.name} pages_checked={len(result.pages_checked)} "
        f"findings={len(result.findings)} limitations={len(result.limitations)} "
        f"network_or_audit_ok={ok}"
    )
    return normalized, ok


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="live-audit-pdfs")
    parser.add_argument("--targets", nargs="*", default=DEFAULT_TARGETS)
    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = await asyncio.gather(
        *(audit_one(target, output_dir) for target in args.targets),
        return_exceptions=True,
    )
    failures = 0
    for target, result in zip(args.targets, results):
        if isinstance(result, BaseException):
            failures += 1
            # Never print raw exception messages; they may contain URLs or request details.
            print(f"target={target} live_audit_failed={type(result).__name__}")
        elif not result[1]:
            failures += 1

    print(f"live_targets={len(args.targets)} failures={failures} output_dir={output_dir}")
    # Artifacts remain useful even if a target blocks automated requests; make that explicit
    # without failing the entire unit-test suite solely due to external-site availability.
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
