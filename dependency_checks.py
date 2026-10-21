"""Bounded detection of versioned frontend CDN dependencies and OSV advisories.

This is not a complete software composition analysis: it only sees package versions
explicitly visible in supported script URL patterns on the initial HTML response.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import aiohttp

from audit_checks import AuditFinding, _finding


MAX_DEPENDENCIES = 20
OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
_VERSION = r"(?P<version>\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)"


class _ScriptSourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "script":
            return
        values = {key.lower(): value or "" for key, value in attrs}
        src = values.get("src", "").strip()
        if src and len(self.sources) < 200:
            self.sources.append(src)


def extract_versioned_dependencies(html: str, page_url: str) -> list[dict[str, str]]:
    """Recognize a conservative allowlist of common versioned CDN script URL forms."""
    parser = _ScriptSourceParser()
    parser.feed(html)
    found: dict[tuple[str, str], dict[str, str]] = {}
    for source in parser.sources:
        try:
            parsed = urlsplit(urljoin(page_url, source))
            host = (parsed.hostname or "").lower()
            path = parsed.path
        except (ValueError, UnicodeError):
            continue

        package = version = ""
        if host in {"cdn.jsdelivr.net", "unpkg.com"}:
            # npm URLs: /npm/jquery@3.7.1/dist/jquery.min.js and
            # /npm/@scope/package@1.2.3/file.js
            match = re.search(
                r"/npm/(?P<package>@[^/]+/[^/@]+|[^/@]+)@" + _VERSION + r"(?:/|$)",
                path,
            )
            if not match:
                match = re.search(r"/(?P<package>@[^/]+/[^/@]+|[^/@]+)@" + _VERSION + r"(?:/|$)", path)
            if match:
                package, version = match.group("package"), match.group("version")
        elif host in {"cdnjs.cloudflare.com", "ajax.googleapis.com"}:
            match = re.search(r"/ajax/libs/(?P<package>[A-Za-z0-9_.-]+)/" + _VERSION + r"(?:/|$)", path)
            if match:
                package, version = match.group("package"), match.group("version")
        elif host == "code.jquery.com":
            match = re.search(r"/jquery-" + _VERSION + r"(?:\.min)?\.js$", path, re.I)
            if match:
                package, version = "jquery", match.group("version")

        if package and version:
            key = (package.lower(), version)
            found[key] = {"name": package, "version": version, "ecosystem": "npm"}
        if len(found) >= MAX_DEPENDENCIES:
            break
    return list(found.values())


async def inspect_client_dependency_versions(html: str, page_url: str) -> tuple[list[AuditFinding], list[str]]:
    """Query OSV for a capped set of versioned dependencies visible in script URLs."""
    dependencies = extract_versioned_dependencies(html, page_url)
    if not dependencies:
        finding = _finding(
            "security_dependency",
            "Frontend dependency vulnerabilities not assessed",
            "not_tested",
            "info",
            "No supported, explicitly versioned frontend CDN script URL was detected in the initial HTML.",
            "This does not mean the site has no dependencies or vulnerabilities. Bundled/minified assets, self-hosted scripts, dynamic imports, package manifests, and dependencies loaded after interaction are outside this narrow detector.",
            "For meaningful dependency coverage, review the site's package manifest and lockfile with a software composition analysis tool, then verify findings against the deployed asset versions.",
            ["Review package.json and the corresponding lockfile where available.", "Run a dependency scanner such as OSV-Scanner or the package manager's audit command.", "Confirm deployed production assets match the reviewed dependency versions."],
            page_url,
        )
        return [finding], [
            "Target-site dependency vulnerability coverage is limited to explicitly versioned frontend CDN script URLs in the initial HTML; bundled and self-hosted dependencies are not inventoried."
        ]

    try:
        timeout = aiohttp.ClientTimeout(total=5.0)
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
            async with session.post(
                OSV_QUERY_URL,
                json={
                    "queries": [
                        {"package": {"name": item["name"], "ecosystem": item["ecosystem"]}, "version": item["version"]}
                        for item in dependencies
                    ]
                },
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                allow_redirects=False,
            ) as response:
                if response.status != 200:
                    raise RuntimeError(f"OSV returned HTTP {response.status}")
                payload = await response.json(content_type=None)
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list) or len(results) != len(dependencies):
            raise ValueError("OSV response did not match the submitted dependency list")
        # A malformed per-item response must never be interpreted as a clean scan.
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("OSV response contained a malformed result")
            vulnerabilities = result.get("vulns", [])
            if not isinstance(vulnerabilities, list) or any(
                not isinstance(vulnerability, dict)
                or not isinstance(vulnerability.get("id"), str)
                or not vulnerability.get("id", "").strip()
                for vulnerability in vulnerabilities
            ):
                raise ValueError("OSV response contained malformed advisory data")
    except Exception as exc:
        return [
            _finding(
                "security_dependency",
                "Frontend dependency vulnerability lookup incomplete",
                "not_tested",
                "info",
                f"Detected {len(dependencies)} versioned frontend CDN dependency reference(s), but the OSV lookup did not complete ({type(exc).__name__}).",
                "No conclusion about known vulnerabilities can be drawn when the advisory lookup is unavailable or malformed.",
                "Retry the lookup and separately run a package-manifest/lockfile scan. This limited CDN check is not a substitute for full dependency inventory.",
                ["Retry the audit when the OSV service is reachable.", "Review the detected versions in a package-aware vulnerability scanner."],
                page_url,
            )
        ], [
            "The OSV dependency-advisory lookup was unavailable or returned an unusable response; detected versions remain unverified."
        ]

    findings: list[AuditFinding] = []
    matched_count = 0
    checked_without_match = 0
    for dependency, result in zip(dependencies, results):
        vulnerabilities = result.get("vulns", []) if isinstance(result, dict) else []
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []
        ids = []
        for vuln in vulnerabilities[:10]:
            if isinstance(vuln, dict):
                vuln_id = str(vuln.get("id") or "").strip()
                if vuln_id:
                    ids.append(vuln_id[:80])
        ids = list(dict.fromkeys(ids))
        if ids:
            matched_count += 1
            findings.append(_finding(
                "security_dependency",
                "Versioned frontend dependency has matching OSV advisories",
                "manual_review_required",
                "medium",
                f"Detected {dependency['name']} {dependency['version']} in a public script URL; OSV returned {len(ids)} advisory ID(s): {', '.join(ids)}. The asset contents were not downloaded or independently verified.",
                "The advisory service associates this declared package/version with known vulnerability records. Confirm the served asset really corresponds to that package and version and review each advisory's affected-version range and conditions before treating it as exploitable.",
                "Upgrade to a supported, patched release after checking compatibility, then retest storefront behavior and rerun the advisory scan. Do not rely on URL version strings alone as proof of the exact served code.",
                ["Verify the script URL and deployed asset provenance.", "Review each advisory and its affected-version conditions.", "Update the dependency through the site's normal release process and rerun checks."],
                page_url,
            ))
        else:
            checked_without_match += 1

    if not findings:
        findings.append(_finding(
            "security_dependency",
            "No matching OSV advisories returned for detected frontend CDN versions",
            "verified",
            "info",
            f"OSV returned no matching advisory records for {checked_without_match} detected versioned frontend CDN dependency reference(s): "
            + ", ".join(f"{item['name']} {item['version']}" for item in dependencies[:10])
            + ("; additional detected references are omitted." if len(dependencies) > 10 else "."),
            "No matching OSV records were returned for these detected references at check time. This is not proof that the site is free of vulnerabilities or that the inventory is complete.",
            "Keep dependencies updated and scan the complete package manifest/lockfile, bundled assets, and server-side components with a software composition analysis tool.",
            ["Review the package manifest and lockfile.", "Check the current OSV advisory results and run a full dependency scanner.", "Confirm production assets match the detected versions."],
            page_url,
        ))
    limitations = [
        f"Target dependency scan queried OSV for {len(dependencies)} explicitly versioned frontend CDN script reference(s); it does not inventory server-side packages, lockfiles, bundled/self-hosted assets, or runtime-loaded dependencies."
    ]
    return findings, limitations
