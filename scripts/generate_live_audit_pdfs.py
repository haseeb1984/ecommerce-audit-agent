"""Generate evidence-based PDFs from real public websites in CI.

This is a non-production QA helper. It does not call the authenticated API, consume
license quota, store audit leads, or deploy anything. PageSpeed metrics are explicitly
marked as not run in this live-site smoke test.
"""
from __future__ import annotations

import asyncio
import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_checks import AuditCheckResult, normalize_target, run_phase_one_checks
from crawl_checks import run_bounded_site_crawl
from report_generator import render_audit_pdf

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
    pdf_bytes = render_audit_pdf(result)
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
