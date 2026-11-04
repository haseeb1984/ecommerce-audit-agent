"""Isolated, authenticated Playwright runner for bounded public-page diagnostics.

Run as a separate container with outbound network egress restricted to public IP
ranges. Application-level DNS checks are defense in depth, not a substitute for
network-layer egress controls against DNS rebinding and browser-process escape.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import time
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, HttpUrl

app = FastAPI(title="Ecommerce Audit Browser Worker", docs_url=None, redoc_url=None)
MAX_REQUEST_BYTES = 16_384
MAX_BROWSER_REQUESTS = 180
VIEWPORTS = ((320, 800), (360, 800), (375, 812), (390, 844), (414, 896), (768, 1024), (1365, 900))
_BROWSER_SEMAPHORE = asyncio.Semaphore(2)
_SEEN_REQUESTS: dict[str, int] = {}


class BrowserAuditRequest(BaseModel):
    target_url: HttpUrl
    request_id: str = Field(min_length=8, max_length=100)


def _secret() -> bytes:
    value = os.getenv("BROWSER_AUDIT_SHARED_SECRET", "")
    if len(value) < 32:
        raise RuntimeError("BROWSER_AUDIT_SHARED_SECRET must contain at least 32 characters")
    return value.encode()


def _verify_signature(timestamp: str, signature: str, body: bytes) -> None:
    try:
        sent_at = int(timestamp)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid request authentication") from None
    if abs(int(time.time()) - sent_at) > 300:
        raise HTTPException(status_code=401, detail="Expired request authentication")
    expected = hmac.new(_secret(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.removeprefix("sha256=")):
        raise HTTPException(status_code=401, detail="Invalid request authentication")


async def _public_http_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.port not in (None, 80, 443):
            return False
        if parts.username is not None or parts.password is not None:
            return False
        host = parts.hostname.rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
            return False
        try:
            literal = ipaddress.ip_address(host)
            addresses = [literal]
        except ValueError:
            loop = asyncio.get_running_loop()
            records = await asyncio.wait_for(
                loop.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM),
                timeout=3.0,
            )
            addresses = [ipaddress.ip_address(record[4][0].split("%", 1)[0]) for record in records]
        return bool(addresses) and all(address.is_global for address in addresses)
    except (ValueError, OSError, asyncio.TimeoutError):
        return False


def _allowed_navigation_host(target_host: str, request_url: str) -> bool:
    """Keep top-level navigations on the requested hostname or its www alias."""
    try:
        requested_host = urlsplit(request_url).hostname
        original = target_host.rstrip(".").lower()
        allowed = {original}
        allowed.add(original[4:] if original.startswith("www.") else f"www.{original}")
        return bool(requested_host) and requested_host.rstrip(".").lower() in allowed
    except ValueError:
        return False


@app.get("/health")
async def health():
    return {"status": "ok", "browser": "playwright", "viewport_count": len(VIEWPORTS)}


@app.post("/v1/audit")
async def audit(payload: BrowserAuditRequest, request: Request,
                x_audit_timestamp: str = Header(default=""),
                x_audit_signature: str = Header(default="")):
    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail="Request too large")
    _verify_signature(x_audit_timestamp, x_audit_signature, body)
    now = int(time.time())
    for seen_id, expires_at in list(_SEEN_REQUESTS.items()):
        if expires_at <= now:
            _SEEN_REQUESTS.pop(seen_id, None)
    if payload.request_id in _SEEN_REQUESTS:
        raise HTTPException(status_code=409, detail="Duplicate browser audit request")
    if len(_SEEN_REQUESTS) >= 10_000:
        raise HTTPException(status_code=429, detail="Browser request replay cache is at capacity")
    _SEEN_REQUESTS[payload.request_id] = now + 300
    target = str(payload.target_url)
    target_host = urlsplit(target).hostname or ""
    if not await _public_http_url(target):
        raise HTTPException(status_code=422, detail="Target URL is not a permitted public HTTP(S) address")
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise HTTPException(status_code=503, detail="Browser runtime is unavailable") from None

    outcomes = []
    findings = []
    console_errors: set[str] = set()
    failed_requests: set[str] = set()
    request_count = 0
    browser_blocked_requests = 0
    navigation_error = None
    viewport_overflow: list[int] = []
    rendered_dom = None

    try:
        await asyncio.wait_for(_BROWSER_SEMAPHORE.acquire(), timeout=2.0)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=429, detail="Browser worker is at capacity") from None
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])
            try:
                context = await browser.new_context(
                    viewport={"width": 1365, "height": 900},
                    device_scale_factor=1,
                    is_mobile=False,
                    has_touch=False,
                    java_script_enabled=True,
                    service_workers="block",
                )
                page = await context.new_page()
                page.set_default_navigation_timeout(20_000)
                page.set_default_timeout(5_000)
    
                async def guard(route):
                    nonlocal request_count, browser_blocked_requests
                    request_count += 1
                    if request_count > MAX_BROWSER_REQUESTS:
                        browser_blocked_requests += 1
                        await route.abort()
                        return
                    if not await _public_http_url(route.request.url):
                        browser_blocked_requests += 1
                        await route.abort()
                        return
                    if route.request.is_navigation_request() and route.request.frame == page.main_frame and not _allowed_navigation_host(target_host, route.request.url):
                        browser_blocked_requests += 1
                        await route.abort()
                        return
                    await route.continue_()
    
                await page.route("**/*", guard)
                page.on("console", lambda message: console_errors.add(message.text[:300]) if message.type == "error" and len(console_errors) < 30 else None)
                page.on("pageerror", lambda error: console_errors.add(str(error)[:300]) if len(console_errors) < 30 else None)
                page.on("requestfailed", lambda req: failed_requests.add((req.url[:220] + " — " + str(req.failure or "failed"))[:300]) if len(failed_requests) < 30 else None)
    
                try:
                    response = await page.goto(target, wait_until="domcontentloaded", timeout=20_000)
                    await page.wait_for_timeout(1200)
                    if response is not None and response.status >= 400:
                        navigation_error = f"Main document returned HTTP {response.status}"
                except Exception as exc:
                    navigation_error = type(exc).__name__
    
                if navigation_error is None:
                    rendered_dom = await page.evaluate("""() => ({
                      elementCount: document.querySelectorAll('*').length,
                      bodyTextLength: (document.body ? document.body.innerText : '').trim().length
                    })""")
                    outcomes.append({
                        "check_id": "crawl.javascript_rendered_dom", "category": "crawlability", "page_url": page.url,
                        "outcome": "pass" if rendered_dom["elementCount"] > 0 else "warning",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright Chromium post-JavaScript DOM inspection",
                        "evidence": f"Rendered DOM element count: {rendered_dom['elementCount']}; visible body text length: {rendered_dom['bodyTextLength']} characters.",
                        "evidence_ref": "browser.rendered_dom",
                    })
                    for width, height in VIEWPORTS:
                        await page.set_viewport_size({"width": width, "height": height})
                        await page.wait_for_timeout(150)
                        metrics = await page.evaluate("""() => {
                          const root = document.documentElement;
                          const body = document.body;
                          const scrollWidth = Math.max(root ? root.scrollWidth : 0, body ? body.scrollWidth : 0);
                          const clientWidth = root ? root.clientWidth : window.innerWidth;
                          const targets = [...document.querySelectorAll('a,button,input,select,textarea,[role="button"]')]
                            .filter(el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
                              return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; });
                          const smallTargets = targets.filter(el => { const r = el.getBoundingClientRect(); return r.width < 24 || r.height < 24; }).length;
                          return {scrollWidth, clientWidth, horizontalOverflow: scrollWidth > clientWidth + 1,
                            targetCount: targets.length, smallTargetCount: smallTargets, documentHeight: root ? root.scrollHeight : 0};
                        }""")
                        page_url = page.url
                        overflow = bool(metrics["horizontalOverflow"])
                        outcomes.append({
                            "check_id": f"mobile_ux.rendered_horizontal_overflow.{width}",
                            "category": "mobile_ux", "page_url": page_url,
                            "outcome": "issue" if overflow else "pass",
                            "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "method": f"Playwright Chromium rendered viewport {width}x{height}",
                            "evidence": f"Document scroll width: {metrics['scrollWidth']}px; viewport client width: {metrics['clientWidth']}px.",
                            "evidence_ref": f"browser.viewport.{width}",
                        })
                        if overflow:
                            viewport_overflow.append(width)
                            findings.append({
                                "category": "mobile_ux", "title": f"Horizontal page overflow at {width}px viewport",
                                "status": "verified", "severity": "medium",
                                "evidence": f"Rendered document width {metrics['scrollWidth']}px exceeds viewport width {metrics['clientWidth']}px at {width}px.",
                                "explanation": "The rendered page has horizontal overflow at this viewport. This can make content harder to reach on narrow screens; inspect the overflowing element before remediation.",
                                "recommendation": "Identify the overflowing element in the affected template and correct its responsive sizing; retest all supported viewport widths.",
                                "verification_steps": ["Open the page at the recorded viewport width.", "Inspect elements extending beyond the viewport.", "Retest after the responsive layout change."],
                                "source_url": page_url, "test_method": "Playwright Chromium rendered viewport measurement",
                                "evidence_confidence": "high",
                            })
                        outcomes.append({
                            "check_id": f"mobile_ux.rendered_small_targets.{width}",
                            "category": "mobile_ux", "page_url": page_url,
                            "outcome": "warning" if metrics["smallTargetCount"] else "pass",
                            "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "method": f"Playwright bounding-box heuristic at {width}x{height}; 24px minimum dimension",
                            "evidence": f"Visible interactive elements: {metrics['targetCount']}; elements below 24px in either dimension: {metrics['smallTargetCount']}.",
                            "evidence_ref": f"browser.targets.{width}",
                        })
                    outcomes.append({
                        "check_id": "mobile_ux.rendered_viewport_matrix", "category": "mobile_ux", "page_url": page.url,
                        "outcome": "issue" if viewport_overflow else "pass",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright Chromium responsive viewport matrix",
                        "evidence": f"Completed {len(VIEWPORTS)} viewport widths; horizontal overflow observed at: {', '.join(str(width) for width in viewport_overflow) if viewport_overflow else 'none'}.",
                        "evidence_ref": "browser.viewport_matrix",
                    })
                else:
                    outcomes.extend([
                        {
                            "check_id": "crawl.javascript_rendered_dom", "category": "crawlability", "page_url": target,
                            "outcome": "not_assessed", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "method": "Playwright Chromium navigation", "evidence": f"Rendered DOM unavailable because navigation failed: {navigation_error}.",
                            "evidence_ref": "browser.rendered_dom",
                        },
                        {
                            "check_id": "mobile_ux.rendered_viewport_matrix", "category": "mobile_ux", "page_url": target,
                            "outcome": "not_assessed", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "method": "Playwright Chromium navigation", "evidence": f"Viewport matrix not run because navigation failed: {navigation_error}.",
                            "evidence_ref": "browser.viewport_matrix",
                        },
                    ])
                    outcomes.append({
                        "check_id": "browser.navigation", "category": "crawlability", "page_url": target,
                        "outcome": "error", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright Chromium navigation", "evidence": f"Browser navigation unavailable: {navigation_error}.",
                        "evidence_ref": "browser.navigation",
                    })
    
                if console_errors:
                    outcomes.append({
                        "check_id": "performance.browser_console_errors", "category": "performance", "page_url": page.url,
                        "outcome": "warning", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright Chromium console and page-error events",
                        "evidence": f"{len(console_errors)} distinct console/page errors observed; samples: {' | '.join(sorted(console_errors)[:5])}",
                        "evidence_ref": "browser.console",
                    })
                else:
                    outcomes.append({
                        "check_id": "performance.browser_console_errors", "category": "performance", "page_url": page.url,
                        "outcome": "pass", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright Chromium console and page-error events",
                        "evidence": "No console errors or uncaught page exceptions were observed during the bounded render.",
                        "evidence_ref": "browser.console",
                    })
                if failed_requests or browser_blocked_requests:
                    outcomes.append({
                        "check_id": "performance.browser_network_failures", "category": "performance", "page_url": page.url,
                        "outcome": "warning", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright request-failure events and outbound request guard",
                        "evidence": f"Failed requests: {len(failed_requests)}; blocked unsafe/capped requests: {browser_blocked_requests}; samples: {' | '.join(sorted(failed_requests)[:5])}",
                        "evidence_ref": "browser.network",
                    })
                else:
                    outcomes.append({
                        "check_id": "performance.browser_network_failures", "category": "performance", "page_url": page.url,
                        "outcome": "pass", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright request-failure events and outbound request guard",
                        "evidence": "No failed or blocked requests were observed within the bounded render.",
                        "evidence_ref": "browser.network",
                    })
                await context.close()
            finally:
                await browser.close()
    finally:
        _BROWSER_SEMAPHORE.release()

    return {
        "request_id": payload.request_id,
        "findings": findings,
        "check_outcomes": outcomes,
        "summary": {
            "viewports": [width for width, _ in VIEWPORTS],
            "browser_requests": min(request_count, MAX_BROWSER_REQUESTS),
            "blocked_requests": browser_blocked_requests,
            "navigation_error": navigation_error,
            "screenshots": "not_captured: durable evidence storage is not configured",
            "core_web_vitals": "not_measured: no field-data source or stable lab metric collection configured",
        },
    }
