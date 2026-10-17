"""Conservative public-surface security signals.

Only confirm likely exposed artifacts from strong response-body signatures. A 200
status by itself is not treated as a vulnerability (many SPAs return the same HTML
for every path). These low-impact GET checks do not exploit or modify the target.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from audit_checks import AuditFinding, _finding, _safe_get

EXPOSURE_PATHS = (
    "/.env",
    "/.git/HEAD",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/phpinfo.php",
)
ENV_KEY_PATTERN = re.compile(
    r"(?im)^\s*(?:APP_KEY|APP_SECRET|API_KEY|API_SECRET|DB_PASSWORD|DATABASE_URL|"
    r"AWS_SECRET_ACCESS_KEY|SECRET_KEY|STRIPE_SECRET_KEY)\s*="
)


def inspect_exposure_response(path: str, status: int, body: str,
                              headers: dict[str, str], source_url: str) -> list[AuditFinding]:
    """Return a finding only when the response body strongly resembles exposed content."""
    if status < 200 or status >= 300:
        return []
    normalized_path = urlsplit(path).path.lower()
    matched = None
    safe_evidence = ""

    if normalized_path == "/.env":
        keys = sorted({match.group(0).split("=", 1)[0].strip() for match in ENV_KEY_PATTERN.finditer(body)})
        if len(keys) >= 2:
            matched = "Environment configuration appears publicly readable"
            safe_evidence = f"The response resembles an environment file and contains {len(keys)} recognizable secret/configuration key name(s); values are intentionally not included in this report."
    elif normalized_path == "/.git/head":
        if re.match(r"^\s*ref:\s+refs/(?:heads|tags)/[A-Za-z0-9._/-]+\s*$", body.strip()):
            matched = "Git repository metadata appears publicly readable"
            safe_evidence = "The response body matches the expected format of a Git HEAD reference."
    elif normalized_path in {"/config.php.bak", "/wp-config.php.bak"}:
        if "<?php" in body.lower() and re.search(r"(?i)(?:password|secret|database|api[_-]?key)\s*[=\s]", body):
            matched = "A PHP configuration backup may be publicly readable"
            safe_evidence = "The response resembles PHP configuration source. Potential secret values are not copied into this report."
    elif normalized_path == "/phpinfo.php":
        if "phpinfo()" in body.lower() and ("php version" in body.lower() or "phpinfo" in body.lower()):
            matched = "A public PHP information page was detected"
            safe_evidence = "The response contains recognizable phpinfo output markers."

    if not matched:
        return []
    return [_finding(
        "security_exposure", matched, "verified", "high", safe_evidence,
        "Publicly accessible configuration, source-control metadata, or diagnostic output can disclose implementation details or secrets that attackers may reuse. The response was checked for recognizable content, not just an HTTP 200 status.",
        "Restrict the affected path at the web server/CDN, remove backup or repository artifacts from the public document root, and rotate any credentials that may have been exposed. Review access logs and deployment packaging.",
        ["Open the exact URL without being logged in and confirm the sensitive content is no longer returned.",
         "Check server/CDN rules and deployment artifacts; do not paste secret values into tickets or reports.",
         "If credentials may have been exposed, rotate them and review access logs."],
        source_url,
    )]


async def probe_common_exposure_paths(client, base_url: str) -> tuple[list[AuditFinding], list[str]]:
    """Probe a tiny fixed list of common exposure paths using the safe public fetcher."""
    findings: list[AuditFinding] = []
    limitations: list[str] = [
        f"Passive exposure probes checked only {len(EXPOSURE_PATHS)} common paths; this is not a penetration test or proof that other files are safe."
    ]
    origin = f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}"
    for path in EXPOSURE_PATHS:
        url = urljoin(origin + "/", path.lstrip("/"))
        try:
            status, body, headers, final_url = await _safe_get(client, url)
        except Exception as exc:
            # A failed probe is not evidence that the path is secure or vulnerable.
            continue
        final_parts = urlsplit(final_url)
        base_parts = urlsplit(origin)
        # Do not attribute a redirect to a different origin/path to the requested artifact.
        if (final_parts.scheme.lower(), final_parts.netloc.lower(), final_parts.path.lower()) != (
            base_parts.scheme.lower(), base_parts.netloc.lower(), path.lower()
        ):
            continue
        findings.extend(inspect_exposure_response(path, status, body, headers, final_url))
    return findings, limitations
