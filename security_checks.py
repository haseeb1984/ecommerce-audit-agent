"""Conservative public-surface security signals.

Only confirm likely exposed artifacts from strong response-body signatures. A 200
status by itself is not treated as a vulnerability (many SPAs return the same HTML
for every path). These low-impact GET checks do not exploit or modify the target.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import re
import socket
import ssl
from urllib.parse import urljoin, urlsplit, urlunsplit

from audit_checks import AuditFinding, _finding, _safe_get

EXPOSURE_PATHS = (
    "/.env",
    "/.git/HEAD",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/phpinfo.php",
    "/.DS_Store",
    "/debug.log",
    "/backup.sql",
    "/server-status",
    "/actuator/env",
    "/actuator/configprops",
    "/debug/vars",
    "/swagger-ui/index.html",
    "/openapi.json",
    "/wp-json/wp/v2/users",
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
    finding_category = "security_exposure"
    finding_status = "verified"
    finding_severity = "high"

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
    elif normalized_path == "/.ds_store":
        if body.startswith("Bud1") or body.startswith("\x00\x00\x00\x01Bud1"):
            matched = "A macOS directory metadata file appears publicly readable"
            safe_evidence = "The response begins with a recognizable .DS_Store file signature."
    elif normalized_path == "/debug.log":
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        if len(lines) >= 3 and any(token in body.lower() for token in ("fatal error", "stack trace", "traceback", "exception")):
            matched = "A debug log appears publicly readable"
            safe_evidence = f"The response resembles a diagnostic log ({len(lines)} non-empty lines) and contains error/trace markers; log contents are not copied into the report."
    elif normalized_path == "/backup.sql":
        lower = body.lower()
        if len(body) >= 200 and ("create table" in lower or "insert into" in lower) and ("-- mysql dump" in lower or "postgresql database dump" in lower or "copy " in lower):
            matched = "A database dump may be publicly readable"
            safe_evidence = "The response contains recognizable database-dump structure; table rows and data values are intentionally excluded from the report."

    elif normalized_path == "/server-status":
        lower = body.lower()
        if "server version:" in lower and "server uptime:" in lower and ("scoreboard:" in lower or "total accesses:" in lower):
            matched = "Apache server-status diagnostics appear publicly accessible"
            safe_evidence = "The response contains multiple Apache server-status diagnostic markers; raw status output is not copied into this report."
    elif normalized_path == "/actuator/env":
        lower = body.lower()
        if ('"propertysources"' in lower or '"propertySources"' in body) and ('"activeprofiles"' in lower or '"activeProfiles"' in body):
            matched = "Application environment diagnostics may be publicly accessible"
            safe_evidence = "The response resembles Spring Actuator environment output; property values are not copied into this report."
    elif normalized_path == "/actuator/configprops":
        lower = body.lower()
        if ('"contexts"' in lower and '"beans"' in lower) or ('"prefix"' in lower and '"properties"' in lower and '"inputs"' in lower):
            matched = "Application configuration diagnostics may be publicly accessible"
            safe_evidence = "The response contains recognizable configuration-properties structure; configuration values are not copied into this report."
    elif normalized_path == "/debug/vars":
        lower = body.lower()
        if '"cmdline"' in lower and '"memstats"' in lower and ('"goroutines"' in lower or '"numgoroutine"' in lower):
            matched = "Go runtime diagnostic variables appear publicly accessible"
            safe_evidence = "The response resembles Go expvar runtime diagnostics; variable values are not copied into this report."
    elif normalized_path == "/swagger-ui/index.html":
        lower = body.lower()
        if "swagger-ui" in lower and ("swaggerinitializerbundle" in lower or "swagger-ui-bundle" in lower):
            matched = "Interactive API documentation is publicly accessible"
            finding_category = "security_api_documentation"
            finding_status = "manual_review_required"
            finding_severity = "low"
            safe_evidence = "The response contains Swagger UI assets. Public API documentation may be intentional; confirm the documented API is meant to be public and does not expose sensitive operations."
    elif normalized_path == "/openapi.json":
        lower = body.lower()
        if '"openapi"' in lower and ('"paths"' in lower or '"components"' in lower):
            matched = "An OpenAPI schema is publicly accessible"
            finding_category = "security_api_documentation"
            finding_status = "manual_review_required"
            finding_severity = "low"
            safe_evidence = "The response resembles an OpenAPI API schema. Public documentation is not automatically a vulnerability; review whether internal routes or sensitive operation details should be disclosed."


    elif normalized_path == "/wp-json/wp/v2/users":
        # WordPress may intentionally publish author profiles; this is a review signal,
        # not proof of private-account exposure. Never include returned names or IDs.
        import json
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            payload = None
        if isinstance(payload, list) and payload and all(
            isinstance(item, dict) and ("id" in item or "slug" in item or "name" in item)
            for item in payload[:10]
        ):
            matched = "WordPress user-profile endpoint returns public records"
            finding_category = "security_api_documentation"
            finding_status = "manual_review_required"
            finding_severity = "low"
            safe_evidence = (
                f"The response resembles a WordPress REST user-record list "
                f"({len(payload)} record(s) in the returned sample). Names, numeric keys, slugs, "
                "and profile values are omitted because author profiles may be intentionally public."
            )

    if not matched:
        return []
    return [_finding(
        finding_category, matched, finding_status, finding_severity, safe_evidence,
        "Publicly accessible configuration, source-control metadata, diagnostic output, or API documentation can disclose implementation details or secrets that attackers may reuse. The response was checked for recognizable content, not just an HTTP 200 status. API documentation exposure may be intentional and requires context.",
        "Restrict the affected path at the web server/CDN, remove backup or repository artifacts from the public document root, and rotate any credentials that may have been exposed. Review access logs and deployment packaging.",
        ["Open the exact URL without being logged in and confirm the sensitive content is no longer returned.",
         "Check server/CDN rules and deployment artifacts; do not paste secret values into tickets or reports.",
         "If credentials may have been exposed, rotate them and review access logs."],
        source_url,
    )]


async def probe_common_exposure_paths(client, base_url: str) -> tuple[list[AuditFinding], list[str]]:
    """Probe a tiny fixed list of common exposure paths using the safe public fetcher."""
    findings: list[AuditFinding] = []
    unverified_probes = 0
    inconclusive_success_probes = 0
    server_error_probes = 0
    limitations: list[str] = [
        f"Passive exposure probes checked only {len(EXPOSURE_PATHS)} common paths; this is not a penetration test or proof that other files are safe."
    ]
    origin = f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}"
    for path in EXPOSURE_PATHS:
        url = urljoin(origin + "/", path.lstrip("/"))
        try:
            status, body, headers, final_url = await _safe_get(client, url)
        except Exception:
            # A failed probe is not evidence that the path is secure or vulnerable.
            unverified_probes += 1
            continue
        final_parts = urlsplit(final_url)
        base_parts = urlsplit(origin)
        # Do not attribute a redirect to a different origin/path to the requested artifact.
        if (final_parts.scheme.lower(), final_parts.netloc.lower(), final_parts.path.lower()) != (
            base_parts.scheme.lower(), base_parts.netloc.lower(), path.lower()
        ):
            unverified_probes += 1
            continue
        path_findings = inspect_exposure_response(path, status, body, headers, final_url)
        findings.extend(path_findings)
        if status >= 500:
            # A server-side failure does not establish that the requested path is safe.
            server_error_probes += 1
        # A successful response without a recognizable sensitive-content signature
        # is inconclusive (for example, an SPA may return its homepage for every path).
        # Do not count that response as proof the probed path is safe.
        if 200 <= status < 300 and not any(
            finding.category == "security_exposure" for finding in path_findings
        ):
            inconclusive_success_probes += 1
    if unverified_probes:
        limitations.append(
            f"{unverified_probes} of {len(EXPOSURE_PATHS)} exposure probes could not be verified due to request failures or redirects."
        )
    if inconclusive_success_probes:
        limitations.append(
            f"{inconclusive_success_probes} of {len(EXPOSURE_PATHS)} exposure probes returned successful responses without a recognizable sensitive-content signature; treated as unverified."
        )
    if server_error_probes:
        limitations.append(
            f"{server_error_probes} of {len(EXPOSURE_PATHS)} exposure probes returned HTTP 5xx server errors; treated as unverified, not safe."
        )
    return findings, limitations


def inspect_security_header_quality(headers: dict[str, str], source_url: str) -> list[AuditFinding]:
    """Review risky values and cookie attributes without claiming exploitability."""
    findings: list[AuditFinding] = []
    csp = headers.get("content-security-policy", "").strip()
    if csp:
        directives = {}
        for part in csp.split(";"):
            tokens = part.strip().split()
            if tokens:
                # CSP duplicate directives are ignored after the first occurrence by browsers.
                # Preserve the first value so a later, stricter duplicate cannot mask a weak one.
                directives.setdefault(tokens[0].lower(), [token.lower() for token in tokens[1:]])
        risky = []
        for directive in ("default-src", "script-src", "object-src", "base-uri", "frame-ancestors"):
            values = directives.get(directive, [])
            if "*" in values:
                risky.append(f"{directive} allows wildcard source")
            if directive in {"script-src", "default-src"} and any("'unsafe-inline'" in value or "'unsafe-eval'" in value for value in values):
                risky.append(f"{directive} permits unsafe-inline/unsafe-eval")
        if risky:
            findings.append(_finding(
                "security_headers", "Content Security Policy may be overly permissive",
                "manual_review_required", "medium",
                "Observed CSP review signals: " + "; ".join(risky) + ". Policy value is not reproduced in full.",
                "A permissive Content Security Policy can reduce the protection it offers against some injected script and framing risks. Some directives may be necessary for a site's current architecture, so this signal needs context.",
                "Review the policy against the scripts, frames, and resources the storefront genuinely requires. Prefer explicit trusted sources, nonces or hashes where practical, and test changes in report-only mode before enforcement.",
                ["Inspect the full CSP in browser DevTools.", "Use CSP reporting and test product, cart, account, and checkout flows before changing policy."],
                source_url,
            ))

        # These directives do not all inherit the same fallback. Missing directives
        # are hardening opportunities, not proof that the site is exploitable.
        missing_protections = []
        if "base-uri" not in directives:
            missing_protections.append("base-uri is not explicitly set")
        if "frame-ancestors" not in directives:
            missing_protections.append("frame-ancestors is not explicitly set")
        if "object-src" not in directives and "default-src" not in directives:
            missing_protections.append("neither object-src nor default-src limits plugin content")
        if missing_protections and not risky:
            findings.append(_finding(
                "security_headers", "Content Security Policy has hardening opportunities",
                "manual_review_required", "low",
                "Observed policy gaps: " + "; ".join(missing_protections) + ". The full policy is not reproduced.",
                "Explicit base-uri and frame-ancestors directives can reduce exposure to base-tag injection and unwanted framing. A restrictive object-src/default-src can limit legacy plugin content. Missing directives alone do not establish an exploitable vulnerability.",
                "Review whether base-uri 'self' (or a narrower value), frame-ancestors appropriate to the site's embedding needs, and object-src 'none' fit the storefront. Test checkout, identity, and embedded widgets before enforcing changes.",
                ["Review the effective CSP and any Content-Security-Policy-Report-Only header.", "Confirm whether the site must be embedded by trusted partners before setting frame-ancestors."],
                source_url,
            ))

    hsts = headers.get("strict-transport-security", "").lower()
    max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts)
    if hsts and (not max_age or int(max_age.group(1)) < 15552000):
        findings.append(_finding(
            "security_headers", "HSTS policy may need review", "manual_review_required", "low",
            "HSTS is present, but its max-age is missing or shorter than six months.",
            "HSTS asks compatible browsers to use HTTPS for future visits. A short duration or missing max-age may provide less persistent protection; rollout must account for all subdomains and HTTPS readiness.",
            "Review an appropriate max-age and whether includeSubDomains is safe for every subdomain. Do not enable preload or includeSubDomains without validating all affected hosts.",
            ["Inspect the Strict-Transport-Security response header.", "Confirm all affected hosts support HTTPS before extending policy."],
            source_url,
        ))

    raw_cookie = headers.get("set-cookie", "")
    if raw_cookie:
        cookies = re.split(r",(?=\s*[^;,=\s]+=[^;,]*)", raw_cookie)
        insecure = []
        session_names = ("session", "sessid", "auth", "token", "jwt")
        for cookie in cookies:
            parts = [part.strip() for part in cookie.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name = parts[0].split("=", 1)[0].strip().lower()
            attrs = {part.split("=", 1)[0].strip().lower() for part in parts[1:] if part}
            missing = []
            if "secure" not in attrs and urlsplit(source_url).scheme.lower() == "https":
                missing.append("Secure")
            if "samesite" not in attrs:
                missing.append("SameSite")
            if any(token in name for token in session_names) and "httponly" not in attrs:
                missing.append("HttpOnly (session-like cookie)")
            if missing:
                insecure.append(f"{name or 'unnamed cookie'} missing {', '.join(missing)}")
        if insecure:
            findings.append(_finding(
                "security_cookies", "Cookie security attributes need review",
                "manual_review_required", "medium",
                f"Found {len(insecure)} cookie(s) with potentially missing attributes: " + "; ".join(insecure[:8]) + ". Cookie values are not included.",
                "Secure, HttpOnly, and SameSite attributes help limit cookie exposure and cross-site request risks. Appropriate attributes depend on whether a cookie is a session, analytics, or cross-site integration cookie.",
                "Review each cookie's purpose. Set Secure on HTTPS cookies, HttpOnly on sensitive session cookies, and an intentional SameSite policy; cross-site payment or identity flows may require SameSite=None; Secure.",
                ["Inspect Set-Cookie headers in browser DevTools without sharing cookie values.", "Test login, cart, consent, and any payment-provider redirect flows after changes."],
                source_url,
            ))
    return findings


def inspect_standard_security_headers(headers: dict[str, str], source_url: str) -> list[AuditFinding]:
    """Report missing baseline browser-security headers as low-severity hardening advice."""
    normalized = {str(key).lower(): str(value).strip() for key, value in (headers or {}).items()}
    missing = []
    if not normalized.get("x-content-type-options"):
        missing.append("X-Content-Type-Options")
    elif normalized["x-content-type-options"].lower() != "nosniff":
        missing.append("X-Content-Type-Options is present but not set to nosniff")
    if not normalized.get("referrer-policy"):
        missing.append("Referrer-Policy")
    if not normalized.get("permissions-policy"):
        missing.append("Permissions-Policy")
    csp = normalized.get("content-security-policy", "")
    frame_protected = "frame-ancestors" in csp.lower() or bool(normalized.get("x-frame-options"))
    if not frame_protected:
        missing.append("a framing restriction (CSP frame-ancestors or X-Frame-Options)")
    if not missing:
        return []
    return [_finding(
        "security_headers", "Baseline browser security headers need review",
        "manual_review_required", "low",
        "Missing or non-standard header signals: " + "; ".join(missing) + ". This is a hardening checklist, not proof of an exploitable vulnerability.",
        "Browser security headers can reduce selected risks involving MIME-type sniffing, referrer leakage, browser capabilities, and unwanted framing. Their absence alone does not establish that a site is vulnerable.",
        "Review X-Content-Type-Options: nosniff, an intentional Referrer-Policy, a Permissions-Policy matched to features the storefront uses, and a framing policy that preserves legitimate checkout or partner embeds. Validate behavior before deployment.",
        ["Inspect response headers on representative public pages.", "Test checkout, payment embeds, analytics, and identity flows before changing policy."],
        source_url,
    )]


async def inspect_transport_security(client, homepage_html: str, final_url: str) -> tuple[list[AuditFinding], list[str]]:
    """Inspect HTTPS certificate validity, HTTP redirect behavior, and static mixed content."""
    findings: list[AuditFinding] = []
    limitations: list[str] = []
    parsed = urlsplit(final_url)
    host = parsed.hostname
    if parsed.scheme.lower() == "https" and host:
        try:
            loop = asyncio.get_running_loop()
            records = await asyncio.wait_for(
                loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM), timeout=4
            )
            addresses = list(dict.fromkeys(record[4][0] for record in records))
            if not addresses or any(not ipaddress.ip_address(addr).is_global for addr in addresses):
                raise OSError("Target DNS returned a non-public address.")
            context = ssl.create_default_context()
            reader = writer = None
            last_error = None
            for address in addresses[:4]:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(address, 443, ssl=context, server_hostname=host),
                        timeout=6,
                    )
                    break
                except Exception as exc:
                    last_error = exc
            if writer is None:
                raise last_error or OSError("TLS connection failed.")
            ssl_object = writer.get_extra_info("ssl_object")
            certificate = ssl_object.getpeercert() if ssl_object else {}
            not_after = certificate.get("notAfter")
            if not_after:
                expiry = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=dt.timezone.utc)
                days_left = (expiry - dt.datetime.now(dt.timezone.utc)).days
                if days_left < 0:
                    status, severity = "verified", "high"
                    evidence = f"The TLS certificate's reported expiry date has passed ({expiry.date().isoformat()})."
                elif days_left <= 14:
                    status, severity = "verified", "medium"
                    evidence = f"The TLS certificate is valid at check time but expires in about {days_left} day(s) ({expiry.date().isoformat()} UTC)."
                else:
                    status, severity = "verified", "info"
                    evidence = f"TLS certificate chain and hostname validation succeeded; certificate expiry: {expiry.date().isoformat()} UTC ({days_left} day(s) remaining)."
                findings.append(_finding(
                    "security_transport", "TLS certificate validity and expiry", status, severity,
                    evidence,
                    "A valid, unexpired TLS certificate helps browsers establish an authenticated encrypted connection. It does not prove the site's application is secure.",
                    "Renew or replace the certificate before expiry, automate renewal where possible, and verify the full certificate chain after renewal.",
                    ["Open the HTTPS URL in a browser and inspect certificate details.", "Repeat the check after renewal and monitor expiry automatically."],
                    final_url,
                ))
            else:
                limitations.append("TLS connection succeeded, but the certificate expiry date was not available for automated inspection.")
            writer.close()
            await writer.wait_closed()
        except ssl.SSLCertVerificationError as exc:
            findings.append(_finding(
                "security_transport", "TLS certificate validation failed", "verified", "high",
                f"The TLS client could not validate the certificate ({type(exc).__name__}); certificate details are not trusted.",
                "Certificate trust, hostname, chain, or validity problems can trigger browser warnings or prevent secure connections.",
                "Install a valid certificate for the exact hostname, include the required intermediate chain, and confirm renewal and server time.",
                ["Test the exact URL in current browsers.", "Verify the certificate chain with a reputable TLS configuration scanner."],
                final_url,
            ))
        except Exception as exc:
            limitations.append(f"TLS certificate expiry inspection could not be completed ({type(exc).__name__}); this is not treated as a pass.")

    http_url = urlunsplit(("http", parsed.netloc, "/", "", "")) if host else ""
    if http_url:
        try:
            status_code, _, _, http_final = await _safe_get(client, http_url)
            if 500 <= status_code < 600:
                limitations.append(
                    f"HTTP-to-HTTPS redirect behavior could not be verified because the HTTP request returned status {status_code}; this is not treated as a pass or a confirmed redirect defect."
                )
            elif urlsplit(http_final).scheme.lower() == "https":
                findings.append(_finding(
                    "security_transport", "HTTP redirects to HTTPS", "verified", "info",
                    f"The HTTP homepage request ended on HTTPS (HTTP response status at final URL: {status_code}).",
                    "Redirecting HTTP visits to HTTPS helps prevent visitors from remaining on an unencrypted page. HSTS is a separate browser-side control.",
                    "Keep a permanent HTTP-to-HTTPS redirect at the edge/server and ensure canonical URLs use HTTPS.",
                    ["Visit the http:// version in a clean browser session and confirm it redirects to the HTTPS canonical URL."],
                    http_url,
                ))
            else:
                findings.append(_finding(
                    "security_transport", "HTTP does not redirect to HTTPS", "verified", "high",
                    f"An HTTP request remained on {urlsplit(http_final).scheme.upper()} at {http_final}; response status {status_code}.",
                    "Visitors who use an HTTP link may receive content without transport encryption unless the host redirects them to HTTPS.",
                    "Configure an HTTP-to-HTTPS redirect at the CDN or web server and verify all public paths preserve the intended HTTPS destination.",
                    ["Open the HTTP homepage and confirm the final URL is HTTPS.", "Check redirect behavior for product, category, and account URLs."],
                    http_final,
                ))
        except Exception as exc:
            limitations.append(f"HTTP-to-HTTPS redirect behavior could not be verified ({type(exc).__name__}).")

    # Static mixed-content inspection applies only to HTTPS documents.
    if parsed.scheme.lower() != "https":
        limitations.append("Mixed-content inspection was skipped because the final page URL is not HTTPS.")
    else:
        try:
            from html.parser import HTMLParser
    
            class _MixedContentParser(HTMLParser):
                def __init__(self):
                    super().__init__(convert_charrefs=True)
                    self.resources = []
    
                def handle_starttag(self, tag, attrs):
                    values = {key.lower(): value or "" for key, value in attrs}
                    tag = tag.lower()
                    resource_attrs = {
                        "script": ("src", True), "iframe": ("src", True),
                        "img": ("src", False), "audio": ("src", False),
                        "video": ("src", False), "source": ("src", False),
                        "link": ("href", False),
                    }
                    if tag not in resource_attrs:
                        return
                    attr, active = resource_attrs[tag]
                    value = values.get(attr, "").strip()
                    if value.lower().startswith("http://"):
                        self.resources.append((tag, active, value))
    
            parser = _MixedContentParser()
            parser.feed(homepage_html)
            active = [item for item in parser.resources if item[1]]
            passive = [item for item in parser.resources if not item[1]]
            if active or passive:
                findings.append(_finding(
                    "security_transport", "HTTP resources referenced by HTTPS page", "verified",
                    "high" if active else "medium",
                    f"Static HTML contains {len(active)} potentially active and {len(passive)} potentially passive HTTP resource reference(s). URLs are omitted to avoid unnecessarily reproducing third-party addresses.",
                    "HTTP resources inside an HTTPS page may be blocked by browsers or expose visitors to tampering. Browser mixed-content rules vary by resource type and browser.",
                    "Change eligible resource URLs to HTTPS, remove obsolete resources, and test all storefront flows. Review CSS and JavaScript-injected requests in browser DevTools as well.",
                    ["Open browser DevTools Console and Network on the HTTPS page.", "Confirm no required resource is loaded over HTTP."],
                    final_url,
                ))
            else:
                findings.append(_finding(
                    "security_transport", "No static HTTP mixed-content references detected", "verified", "info",
                    "No HTTP URLs were found in the inspected HTML attributes for common script, frame, image, media, and link resources.",
                    "This is a static source check only; CSS URLs, redirects, and JavaScript-injected resources may still use HTTP.",
                    "Check the browser's mixed-content console and network requests for a complete runtime view.",
                    ["Review DevTools Console and Network on representative pages."],
                    final_url,
                ))
        except Exception as exc:
            limitations.append(f"Static mixed-content inspection could not be completed ({type(exc).__name__}).")
    return findings, limitations
