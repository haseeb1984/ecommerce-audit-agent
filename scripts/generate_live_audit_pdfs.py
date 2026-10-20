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

from audit_checks import AuditCheckResult, normalize_target, run_phase_one_checks
from crawl_checks import run_bounded_site_crawl
from report_generator import render_audit_pdf


async def capture_real_website_screenshot(url: str) -> str | None:
    """Capture a real browser viewport screenshot; return a PNG data URI or None."""
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
    screenshot_data_uri = await capture_real_website_screenshot(normalized)
    print(f"target={normalized} browser_screenshot={'captured' if screenshot_data_uri else 'unavailable'}")
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
