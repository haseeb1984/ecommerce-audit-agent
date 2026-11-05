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
import re
import socket
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, HttpUrl

app = FastAPI(title="Ecommerce Audit Browser Worker", docs_url=None, redoc_url=None)
MAX_REQUEST_BYTES = 16_384
MAX_BROWSER_REQUESTS = 180
MAX_RENDERED_PAGES = 6
MAX_RENDERED_LINKS = 30
RENDERED_METADATA_SCRIPT = """() => {
  const descriptions = [...document.querySelectorAll('meta[name="description" i]')];
  const canonicals = [...document.querySelectorAll('link[rel~="canonical" i]')];
  let canonicalSameOrigin = null;
  if (canonicals.length === 1) {
    try { canonicalSameOrigin = new URL(canonicals[0].href, location.href).origin === location.origin; }
    catch (_) { canonicalSameOrigin = false; }
  }
  const robots = [...document.querySelectorAll('meta[name="robots" i],meta[name="googlebot" i]')]
    .map(meta => meta.content || '').join(',').toLowerCase();
  const scripts = [...document.querySelectorAll('script[type="application/ld+json"]')];
  const stack = scripts.slice(0, 30).map(script => {
    try { return JSON.parse(script.textContent || 'null'); } catch (_) { return null; }
  }).filter(Boolean);
  let productSchemaCount = 0, visited = 0;
  while (stack.length && visited < 10000) {
    const node = stack.pop(); visited += 1;
    if (Array.isArray(node)) { stack.push(...node.slice(0, 1000)); continue; }
    if (!node || typeof node !== 'object') continue;
    const types = Array.isArray(node['@type']) ? node['@type'] : [node['@type']];
    if (types.some(type => typeof type === 'string' &&
      ['product', 'productgroup'].includes(type.toLowerCase().split('/').pop().split('#').pop()))) productSchemaCount += 1;
    for (const value of Object.values(node)) if (value && typeof value === 'object') stack.push(value);
  }
  return {
    title_length: (document.title || '').trim().length,
    description_count: descriptions.length,
    description_length: descriptions.length === 1 ? (descriptions[0].content || '').trim().length : 0,
    canonical_count: canonicals.length,
    canonical_same_origin: canonicalSameOrigin,
    robots_noindex: /(^|[,\\s])noindex([,\\s]|$)/.test(robots),
    visible_h1_count: [...document.querySelectorAll('h1')].filter(el => {
      const rect = el.getBoundingClientRect(), style = getComputedStyle(el);
      return rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden';
    }).length,
    product_schema_count: productSchemaCount
  };
}"""
LAB_VITALS_INIT_SCRIPT = """(() => {
  const state = { lcp_supported: false, cls_supported: false, longtask_supported: false,
    lcp_ms: null, cls: null, long_task_count: null, long_task_total_ms: null, long_task_max_ms: null,
    _cls_entries: [], _long_tasks: [] };
  try {
    const lcp = new PerformanceObserver(list => {
      for (const entry of list.getEntries()) state.lcp_ms = Math.round(entry.startTime);
    });
    lcp.observe({type: 'largest-contentful-paint', buffered: true});
    state.lcp_supported = true;
  } catch (_) {}
  try {
    const cls = new PerformanceObserver(list => {
      for (const entry of list.getEntries()) {
        if (!entry.hadRecentInput) state._cls_entries.push({start: entry.startTime, value: entry.value});
      }
    });
    cls.observe({type: 'layout-shift', buffered: true});
    state.cls_supported = true;
  } catch (_) {}
  try {
    const longTasks = new PerformanceObserver(list => {
      for (const entry of list.getEntries()) state._long_tasks.push(entry.duration);
    });
    longTasks.observe({type: 'longtask', buffered: true});
    state.longtask_supported = true;
  } catch (_) {}
  window.__auditLabVitals = state;
})();"""
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


def _safe_evidence_url(value: str) -> str:
    """Remove credentials, query strings and fragments before storing browser evidence."""
    try:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return parts.scheme or "browser"
        host = parts.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parts.port
        default_port = 80 if parts.scheme == "http" else 443
        netloc = f"{host}:{port}" if port and port != default_port else host
        return parts._replace(netloc=netloc, query="", fragment="").geturl()
    except (TypeError, ValueError):
        return "browser"


def _safe_diagnostic_text(value: str) -> str:
    text = re.sub(
        r"(?i)(token|api[_-]?key|secret|password|authorization|code)=([^&\s]+)",
        r"\1=[redacted]",
        str(value),
    )
    text = re.sub(
        r"https?://[^\s\"<>]+",
        lambda match: _safe_evidence_url(match.group(0)),
        text,
    )
    return text[:300]



def _format_navigation_timing(timing: dict, resource_summary: dict) -> str:
    """Describe browser-observed navigation timings without calling them Core Web Vitals."""
    fields = (
        ("responseStart", timing.get("responseStart")),
        ("domContentLoadedEventEnd", timing.get("domContentLoadedEventEnd")),
        ("loadEventEnd", timing.get("loadEventEnd")),
    )
    rendered = ", ".join(
        f"{name}={round(float(value))}ms"
        for name, value in fields
        if isinstance(value, (int, float)) and value > 0
    )
    return (
        f"Navigation timing (browser lab observation): {rendered or 'timing fields unavailable'}; "
        f"resource entries: {resource_summary.get('count', 0)}; "
        f"transfer bytes reported by Resource Timing: {resource_summary.get('transfer_bytes', 0)}. "
        "These are single-run diagnostics, not field Core Web Vitals or a representative performance score."
    )





def _summarize_lab_vitals(raw: dict) -> dict:
    """Summarize single-render LCP, CLS session windows and Long Tasks API entries."""
    shifts = raw.get("_cls_entries", []) if isinstance(raw, dict) else []
    max_session_value = 0.0
    session_start = None
    session_last = None
    session_value = 0.0
    for entry in sorted(shifts, key=lambda item: float(item.get("start", 0))):
        start = float(entry.get("start", 0))
        value = float(entry.get("value", 0))
        if session_start is None or start - session_last > 1000 or start - session_start > 5000:
            session_start, session_last, session_value = start, start, value
        else:
            session_last = start
            session_value += value
        max_session_value = max(max_session_value, session_value)
    tasks = [float(value) for value in raw.get("_long_tasks", []) if isinstance(value, (int, float))]
    return {
        "lcp_supported": bool(raw.get("lcp_supported")),
        "cls_supported": bool(raw.get("cls_supported")),
        "longtask_supported": bool(raw.get("longtask_supported")),
        "lcp_ms": raw.get("lcp_ms"),
        "cls": round(max_session_value, 4) if raw.get("cls_supported") else None,
        "long_task_count": len(tasks) if raw.get("longtask_supported") else None,
        "long_task_total_ms": round(sum(tasks)) if raw.get("longtask_supported") else None,
        "long_task_max_ms": round(max(tasks)) if tasks and raw.get("longtask_supported") else None,
    }


def _format_lab_vitals_evidence(summary: dict) -> str:
    lcp = summary.get("lcp_ms")
    cls = summary.get("cls")
    tasks = summary.get("long_task_count")
    return (
        f"Observed LCP: {str(lcp) + 'ms' if lcp is not None else 'unavailable'}; "
        f"maximum CLS session window: {cls if cls is not None else 'unavailable'}; "
        f"Long Tasks: {tasks if tasks is not None else 'API unavailable'} "
        f"(total {summary.get('long_task_total_ms') if summary.get('long_task_total_ms') is not None else 'n/a'}ms, "
        f"maximum {summary.get('long_task_max_ms') if summary.get('long_task_max_ms') is not None else 'n/a'}ms). "
        "Single-run browser lab observations collected during a short page render; not field Core Web Vitals, "
        "not a stable Lighthouse run, and not an INP measurement. Consent, page state, viewport changes, "
        "browser support and the observation window can affect these values."
    )


def _lab_vitals_needs_review(summary: dict) -> bool:
    return bool(
        (isinstance(summary.get("lcp_ms"), (int, float)) and summary["lcp_ms"] > 2500)
        or (isinstance(summary.get("cls"), (int, float)) and summary["cls"] > 0.1)
        or (isinstance(summary.get("long_task_count"), int) and summary["long_task_count"] > 0)
    )


def _format_rendered_metadata_evidence(summary: dict) -> str:
    return (
        f"Rendered title characters: {summary.get('title_length', 0)}; "
        f"meta description tags: {summary.get('description_count', 0)} "
        f"(content characters: {summary.get('description_length', 0)}); "
        f"canonical tags: {summary.get('canonical_count', 0)}; "
        f"single canonical same-origin: {summary.get('canonical_same_origin')}; "
        f"robots noindex: {bool(summary.get('robots_noindex'))}; "
        f"visible H1 elements: {summary.get('visible_h1_count', 0)}; "
        f"Product/ProductGroup JSON-LD entities: {summary.get('product_schema_count', 0)}. "
        "These are rendered-page presence/shape signals, not a complete SEO or structured-data validity verdict."
    )


def _rendered_metadata_needs_review(summary: dict) -> bool:
    return bool(
        not summary.get("title_length")
        or summary.get("description_count", 0) != 1
        or summary.get("canonical_count", 0) > 1
        or (summary.get("canonical_count", 0) == 1 and summary.get("canonical_same_origin") is False)
        or not summary.get("visible_h1_count")
    )


def _format_accessibility_evidence(summary: dict) -> str:
    return (
        f"Rendered images: {summary.get('image_count', 0)}; images missing an alt attribute: "
        f"{summary.get('images_missing_alt', 0)}. Visible interactive controls: "
        f"{summary.get('control_count', 0)}; controls without a detectable accessible-name heuristic: "
        f"{summary.get('controls_without_name', 0)}; visible controls with positive tabindex: "
        f"{summary.get('positive_tabindex_count', 0)}; visible controls with tabindex=-1: "
        f"{summary.get('negative_tabindex_count', 0)}. This automated DOM heuristic is not a WCAG conformance verdict."
    )


def _format_rendered_contrast_evidence(summary: dict) -> str:
    samples = summary.get("low_contrast_samples", [])
    sample_text = "; ".join(str(item)[:100] for item in samples[:5]) or "none recorded"
    return (
        f"Visible text candidates measured: {summary.get('inspected_text_count', 0)}; "
        f"low-contrast text candidates: {summary.get('low_contrast_text_count', 0)}; "
        f"unmeasurable candidates: {summary.get('unmeasurable_text_count', 0)}. "
        f"Example color pairs (foreground/background/ratio): {sample_text}. "
        "This conservative browser heuristic measures only text with parseable foreground colors and an opaque solid ancestor background; "
        "it skips gradients, images, translucent layers, opacity effects, and other uncertain combinations. "
        "It is not a complete WCAG 2.2 contrast audit."
    )


def _rendered_contrast_needs_review(summary: dict) -> bool:
    return bool(
        int(summary.get("inspected_text_count", 0) or 0) > 0
        and int(summary.get("low_contrast_text_count", 0) or 0) > 0
    )


def _format_product_page_evidence(summary: dict) -> str:
    return (
        f"Product-like page detected: {bool(summary.get('is_product_page'))}; "
        f"Product JSON-LD entities: {summary.get('product_entities', 0)}; "
        f"visible H1 elements: {summary.get('visible_h1', 0)}; "
        f"visible price candidates: {summary.get('visible_price', 0)}; "
        f"visible purchase controls: {summary.get('purchase_controls', 0)}; visible variant-selection controls: "
        f"{summary.get('variant_controls', 0)}; product image candidates: {summary.get('product_images', 0)}; "
        f"quantity controls: {summary.get('quantity_controls', 0)}. "
        "Rendered selectors are heuristic diagnostics; themes, variants, consent, and inventory state can affect visibility. "
        "This is not a checkout test or a product-data correctness verdict."
    )

def _format_orientation_evidence(summary: dict) -> str:
    return (
        f"Portrait viewport {summary.get('portrait_width', 390)}x{summary.get('portrait_height', 844)}: "
        f"document width {summary.get('portrait_scroll_width', 0)}px; landscape viewport "
        f"{summary.get('landscape_width', 844)}x{summary.get('landscape_height', 390)}: "
        f"document width {summary.get('landscape_scroll_width', 0)}px. "
        "This checks horizontal overflow at two fixed viewport orientations; it does not verify device sensors or rotation behavior."
    )


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



def _normalize_internal_crawl_url(base_url: str, href: str, target_host: str) -> str | None:
    """Return a same-site HTTP(S) URL without credentials, query strings or fragments."""
    try:
        candidate = urljoin(base_url, href)
        parts = urlsplit(candidate)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        if parts.port not in (None, 80, 443) or not _allowed_navigation_host(target_host, candidate):
            return None
        host = parts.hostname.lower().rstrip(".")
        netloc = f"[{host}]" if ":" in host else host
        default_port = 80 if parts.scheme == "http" else 443
        if parts.port and parts.port != default_port:
            netloc = f"{netloc}:{parts.port}"
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", "", ""))
    except (TypeError, ValueError):
        return None


def _format_internal_crawl_evidence(summary: dict) -> str:
    return (
        f"Rendered pages: {summary.get('rendered_pages', 1)} of a maximum {MAX_RENDERED_PAGES}; "
        f"eligible same-site links discovered: {summary.get('eligible_links', 0)}; "
        f"navigation failures: {summary.get('navigation_failures', 0)}; "
        f"page-cap reached: {bool(summary.get('page_cap_reached'))}; "
        f"browser request cap reached: {bool(summary.get('request_cap_reached'))}. "
        "This is a one-hop, JavaScript-discovered sample, not a full-site crawl."
    )


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
    rendered_page_urls = [_safe_evidence_url(target)]
    internal_crawl_summary = {"rendered_pages": 1, "eligible_links": 0, "navigation_failures": 0, "page_cap_reached": False, "request_cap_reached": False}

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
                async def block_websocket(websocket_route):
                    nonlocal browser_blocked_requests
                    browser_blocked_requests += 1
                    await websocket_route.close(
                        code=1008,
                        reason="WebSocket connections are disabled during public audits",
                    )

                await context.route_web_socket("**/*", block_websocket)
                page = await context.new_page()
                page.set_default_navigation_timeout(20_000)
                await page.add_init_script(LAB_VITALS_INIT_SCRIPT)
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
                page.on("console", lambda message: console_errors.add(_safe_diagnostic_text(message.text)) if message.type == "error" and len(console_errors) < 30 else None)
                page.on("pageerror", lambda error: console_errors.add(_safe_diagnostic_text(str(error))) if len(console_errors) < 30 else None)
                page.on("requestfailed", lambda req: failed_requests.add((_safe_evidence_url(req.url) + " — " + str(req.failure or "failed"))[:300]) if len(failed_requests) < 30 else None)
    
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
                    accessibility_summary = await page.evaluate("""() => {
                      const images = [...document.images];
                      const missingAlt = images.filter(image => !image.hasAttribute('alt')).length;
                      const controls = [...document.querySelectorAll('a,button,input,select,textarea,[role="button"],[role="link"]')]
                        .filter(el => {
                          const rect = el.getBoundingClientRect();
                          const style = getComputedStyle(el);
                          return rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden';
                        });
                      const withoutName = controls.filter(el => {
                        const aria = (el.getAttribute('aria-label') || '').trim();
                        const labelledBy = (el.getAttribute('aria-labelledby') || '').trim();
                        const labelledByText = labelledBy.split(/\s+/).map(id => {
                          const ref = document.getElementById(id);
                          return ref ? (ref.innerText || ref.textContent || '').trim() : '';
                        }).filter(Boolean).join(' ');
                        const title = (el.getAttribute('title') || '').trim();
                        const text = (el.innerText || el.value || '').trim();
                        const alt = el.querySelector('img[alt]')?.getAttribute('alt')?.trim() || '';
                        const labels = el.labels ? [...el.labels].map(label => (label.innerText || label.textContent || '').trim()).filter(Boolean).join(' ') : '';
                        return !(aria || labelledByText || title || text || alt || labels);
                      }).length;
                      return {image_count: images.length, images_missing_alt: missingAlt,
                        control_count: controls.length, controls_without_name: withoutName,
                        positive_tabindex_count: controls.filter(el => el.tabIndex > 0).length,
                        negative_tabindex_count: controls.filter(el => el.getAttribute('tabindex') === '-1').length};
                    }""")
                    outcomes.extend([
                      {
                        "check_id": "accessibility.rendered_images_alt",
                        "category": "accessibility", "page_url": _safe_evidence_url(page.url),
                        "outcome": "warning" if accessibility_summary["images_missing_alt"] else "pass",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright rendered DOM image alt-attribute presence heuristic",
                        "evidence": _format_accessibility_evidence(accessibility_summary),
                        "evidence_ref": "browser.accessibility.images",
                      },
                      {
                        "check_id": "accessibility.keyboard_focus_order",
                        "category": "accessibility", "page_url": _safe_evidence_url(page.url),
                        "outcome": "warning" if accessibility_summary["positive_tabindex_count"] or accessibility_summary["negative_tabindex_count"] else "pass",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright rendered DOM focus-order heuristic for visible interactive controls",
                        "evidence": _format_accessibility_evidence(accessibility_summary),
                        "evidence_ref": "browser.accessibility.focus_order",
                      },
                      {
                        "check_id": "accessibility.rendered_controls_name",
                        "category": "accessibility", "page_url": _safe_evidence_url(page.url),
                        "outcome": "warning" if accessibility_summary["controls_without_name"] else "pass",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright rendered DOM accessible-name presence heuristic",
                        "evidence": _format_accessibility_evidence(accessibility_summary),
                        "evidence_ref": "browser.accessibility.controls",
                      },
                    ])
                    contrast_summary = await page.evaluate("""() => {
                      const parseColor = value => {
                        const match = String(value || '').match(/^rgba?\(([^)]+)\)$/i);
                        if (!match) return null;
                        const parts = match[1].split(',').map(item => Number(item.trim()));
                        if (parts.length < 3 || parts.slice(0, 3).some(value => !Number.isFinite(value))) return null;
                        const alpha = parts.length > 3 ? parts[3] : 1;
                        if (!Number.isFinite(alpha) || alpha < 0.999) return null;
                        return parts.slice(0, 3).map(value => Math.max(0, Math.min(255, value)));
                      };
                      const alphaOf = value => {
                        const match = String(value || '').match(/^rgba?\(([^)]+)\)$/i);
                        if (!match) return null;
                        const parts = match[1].split(',').map(item => Number(item.trim()));
                        return parts.length > 3 && Number.isFinite(parts[3]) ? parts[3] : 1;
                      };
                      const luminance = rgb => {
                        const channels = rgb.map(value => {
                          const normalized = value / 255;
                          return normalized <= 0.04045 ? normalized / 12.92 : Math.pow((normalized + 0.055) / 1.055, 2.4);
                        });
                        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
                      };
                      const contrastRatio = (foreground, background) => {
                        const first = luminance(foreground);
                        const second = luminance(background);
                        return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
                      };
                      const candidates = [...document.querySelectorAll('body *')]
                        .filter(el => el.namespaceURI === 'http://www.w3.org/1999/xhtml' && el.children.length === 0 && (el.innerText || el.textContent || '').trim())
                        .slice(0, 500);
                      let inspected = 0;
                      let low = 0;
                      let unmeasurable = 0;
                      const samples = [];
                      for (const el of candidates) {
                        const rect = el.getBoundingClientRect();
                        if (rect.width <= 0 || rect.height <= 0) continue;
                        let ancestor = el;
                        let background = null;
                        let uncertain = false;
                        while (ancestor && ancestor.nodeType === 1) {
                          const style = getComputedStyle(ancestor);
                          if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) < 0.999 || style.filter !== 'none' || style.mixBlendMode !== 'normal') {
                            uncertain = true;
                            break;
                          }
                          if (style.backgroundImage && style.backgroundImage !== 'none') {
                            uncertain = true;
                            break;
                          }
                          const backgroundAlpha = alphaOf(style.backgroundColor);
                          if (backgroundAlpha !== null && backgroundAlpha > 0 && backgroundAlpha < 0.999) {
                            uncertain = true;
                            break;
                          }
                          const parsed = parseColor(style.backgroundColor);
                          if (parsed) { background = parsed; break; }
                          ancestor = ancestor.parentElement;
                        }
                        const style = getComputedStyle(el);
                        const foreground = parseColor(style.color);
                        if (uncertain || !background || !foreground) {
                          unmeasurable += 1;
                          continue;
                        }
                        const ratio = contrastRatio(foreground, background);
                        const fontSize = Number.parseFloat(style.fontSize) || 0;
                        const fontWeight = Number.parseInt(style.fontWeight, 10) || 400;
                        const largeText = fontSize >= 24 || (fontSize >= 18.66 && fontWeight >= 700);
                        const threshold = largeText ? 3 : 4.5;
                        inspected += 1;
                        if (ratio + 0.0001 < threshold) {
                          low += 1;
                          if (samples.length < 10) {
                            const fmt = color => color.map(value => Math.round(value)).join(',');
                            samples.push(fmt(foreground) + '/' + fmt(background) + '/' + ratio.toFixed(2));
                          }
                        }
                      }
                      return {inspected_text_count: inspected, low_contrast_text_count: low,
                        unmeasurable_text_count: unmeasurable, low_contrast_samples: samples};
                    }""")
                    outcomes.append({
                        "check_id": "accessibility.rendered_text_contrast",
                        "category": "accessibility", "page_url": _safe_evidence_url(page.url),
                        "outcome": "not_assessed" if not contrast_summary["inspected_text_count"] else ("warning" if _rendered_contrast_needs_review(contrast_summary) else "pass"),
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright computed foreground/opaque-background color contrast heuristic on visible leaf text",
                        "evidence": _format_rendered_contrast_evidence(contrast_summary),
                        "evidence_ref": "browser.accessibility.text_contrast",
                    })
                    product_page_summary = await page.evaluate("""() => {
                      const visible = el => {
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.display !== 'none' && s.visibility !== 'hidden';
                      };
                      const scripts = [...document.querySelectorAll('script[type="application/ld+json"]')];
                      let productEntities = 0;
                      let visited = 0;
                      const stack = scripts.slice(0, 30).map(script => {
                        try { return JSON.parse(script.textContent || 'null'); } catch (_) { return null; }
                      }).filter(Boolean);
                      while (stack.length && visited < 10000) {
                        const node = stack.pop(); visited += 1;
                        if (Array.isArray(node)) { stack.push(...node.slice(0, 1000)); continue; }
                        if (!node || typeof node !== 'object') continue;
                        const types = Array.isArray(node['@type']) ? node['@type'] : [node['@type']];
                        if (types.some(type => typeof type === 'string' && type.toLowerCase().split('/').pop().split('#').pop() === 'product')) productEntities += 1;
                        for (const value of Object.values(node)) if (value && typeof value === 'object') stack.push(value);
                      }
                      const h1 = [...document.querySelectorAll('h1')].filter(visible).length;
                      const price = [...document.querySelectorAll('[itemprop="price"],[class*="price" i],[data-price],[aria-label*="price" i]')].filter(visible).length;
                      const purchase = [...document.querySelectorAll('button,input[type="submit"], [role="button"]')].filter(visible).filter(el => {
                        const label = [el.innerText, el.value, el.getAttribute('aria-label'), el.getAttribute('title')].filter(Boolean).join(' ').toLowerCase();
                        return /add to cart|add to bag|add to basket|buy now|purchase/.test(label);
                      }).length;
                      const variantControls = [...document.querySelectorAll('select,input[type="radio"],[role="radio"],[name*="size" i],[name*="color" i],[name*="variant" i],[aria-label*="size" i],[aria-label*="color" i]')].filter(visible).length;
                      const productImages = [...document.querySelectorAll('[itemprop="image"],[class*="product" i] img,img[alt*="product" i]')].filter(visible).length;
                      const quantityControls = [...document.querySelectorAll('input[type="number"],input[name*="quantity" i],[aria-label*="quantity" i]')].filter(visible).length;
                      const pathSegments = location.pathname.toLowerCase().split('/').filter(Boolean);
                      const isProductPage = productEntities > 0 || pathSegments.some(part => part === 'product' || part === 'products' || part === 'item' || part === 'items') || price > 0;
                      return {is_product_page: isProductPage, product_entities: productEntities,
                        visible_h1: h1, visible_price: price, purchase_controls: purchase,
                        variant_controls: variantControls, product_images: productImages, quantity_controls: quantityControls};
                    }""")
                    product_page_missing = product_page_summary["is_product_page"] and (
                        product_page_summary["visible_h1"] == 0
                        or product_page_summary["visible_price"] == 0
                        or product_page_summary["purchase_controls"] == 0
                    )
                    outcomes.append({
                        "check_id": "ecommerce.product_page_rendered_signals",
                        "category": "ecommerce", "page_url": _safe_evidence_url(page.url),
                        "outcome": "not_assessed" if not product_page_summary["is_product_page"] else ("warning" if product_page_missing else "pass"),
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright rendered DOM heuristics for product identity, visible price, and purchase controls",
                        "evidence": _format_product_page_evidence(product_page_summary),
                        "evidence_ref": "browser.ecommerce.product_page",
                    })
                    rendered_metadata = await page.evaluate(RENDERED_METADATA_SCRIPT)
                    outcomes.append({
                        "check_id": "seo.javascript_rendered_metadata",
                        "category": "technical_seo", "page_url": _safe_evidence_url(page.url),
                        "outcome": "warning" if _rendered_metadata_needs_review(rendered_metadata) else "pass",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright hydrated DOM metadata presence/shape inspection",
                        "evidence": _format_rendered_metadata_evidence(rendered_metadata),
                        "evidence_ref": "browser.seo.rendered_metadata.homepage",
                    })
                    performance_data = await page.evaluate("""() => {
                      const nav = performance.getEntriesByType('navigation')[0];
                      const resources = performance.getEntriesByType('resource');
                      return {
                        navigation: nav ? {
                          responseStart: nav.responseStart,
                          domContentLoadedEventEnd: nav.domContentLoadedEventEnd,
                          loadEventEnd: nav.loadEventEnd
                        } : {},
                        resources: {
                          count: resources.length,
                          transfer_bytes: resources.reduce((sum, item) => sum + (item.transferSize || 0), 0)
                        }
                      };
                    }""")
                    raw_lab_vitals = await page.evaluate("""() => {
                      const state = window.__auditLabVitals;
                      if (!state) return {};
                      return {...state};
                    }""")
                    lab_vitals = _summarize_lab_vitals(raw_lab_vitals)
                    vitals_supported = lab_vitals["lcp_supported"] or lab_vitals["cls_supported"] or lab_vitals["longtask_supported"]
                    outcomes.append({
                        "check_id": "performance.browser_lab_vitals",
                        "category": "performance", "page_url": _safe_evidence_url(page.url),
                        "outcome": ("warning" if _lab_vitals_needs_review(lab_vitals) else "pass") if vitals_supported else "not_assessed",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Chromium PerformanceObserver for largest-contentful-paint, layout-shift session windows, and longtask; short single-run render",
                        "evidence": _format_lab_vitals_evidence(lab_vitals),
                        "evidence_ref": "browser.performance.lab_vitals",
                    })
                    outcomes.append({
                        "check_id": "performance.browser_navigation_timing",
                        "category": "performance", "page_url": _safe_evidence_url(page.url),
                        "outcome": "pass" if performance_data["navigation"] else "not_assessed",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Chromium Performance Navigation Timing and Resource Timing API; single page render",
                        "evidence": _format_navigation_timing(performance_data["navigation"], performance_data["resources"]),
                        "evidence_ref": "browser.navigation_timing",
                    })
                    outcomes.append({
                        "check_id": "crawl.javascript_rendered_dom", "category": "crawlability", "page_url": _safe_evidence_url(page.url),
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
                                "source_url": _safe_evidence_url(page_url), "test_method": "Playwright Chromium rendered viewport measurement",
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
                    orientation_summary = {}
                    orientation_overflow = False
                    for orientation, width, height in (("portrait", 390, 844), ("landscape", 844, 390)):
                        await page.set_viewport_size({"width": width, "height": height})
                        await page.wait_for_timeout(150)
                        orientation_metrics = await page.evaluate("""() => {
                          const root = document.documentElement;
                          const body = document.body;
                          return Math.max(root ? root.scrollWidth : 0, body ? body.scrollWidth : 0);
                        }""")
                        orientation_summary[f"{orientation}_width"] = width
                        orientation_summary[f"{orientation}_height"] = height
                        orientation_summary[f"{orientation}_scroll_width"] = orientation_metrics
                        orientation_overflow = orientation_overflow or orientation_metrics > width + 1
                    outcomes.append({
                        "check_id": "mobile_ux.rendered_orientation",
                        "category": "mobile_ux", "page_url": _safe_evidence_url(page.url),
                        "outcome": "issue" if orientation_overflow else "pass",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright Chromium fixed portrait and landscape viewport overflow comparison",
                        "evidence": _format_orientation_evidence(orientation_summary),
                        "evidence_ref": "browser.orientation",
                    })
                    outcomes.append({
                        "check_id": "mobile_ux.rendered_viewport_matrix", "category": "mobile_ux", "page_url": page.url,
                        "outcome": "issue" if viewport_overflow else "pass",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright Chromium responsive viewport matrix",
                        "evidence": f"Completed {len(VIEWPORTS)} viewport widths; horizontal overflow observed at: {', '.join(str(width) for width in viewport_overflow) if viewport_overflow else 'none'}.",
                        "evidence_ref": "browser.viewport_matrix",
                    })
                    # Discover links after client-side hydration, then render a bounded
                    # one-hop sample. The route guard validates every navigation and request.
                    raw_links = await page.evaluate("""() => Array.from(document.querySelectorAll('a[href]'))
                      .map(anchor => anchor.href).slice(0, 500)""")
                    candidates = []
                    current_page_url = _normalize_internal_crawl_url(page.url, page.url, target_host)
                    seen_candidates = {current_page_url} if current_page_url else set()
                    for href in raw_links:
                        candidate = _normalize_internal_crawl_url(page.url, href, target_host)
                        if candidate and candidate not in seen_candidates:
                            seen_candidates.add(candidate)
                            candidates.append(candidate)
                        if len(candidates) >= MAX_RENDERED_LINKS:
                            break
                    if candidates:
                        public_results = await asyncio.gather(*(_public_http_url(candidate) for candidate in candidates))
                        candidates = [candidate for candidate, is_public in zip(candidates, public_results) if is_public]
                    internal_crawl_summary["eligible_links"] = len(candidates)
                    selected_pages = candidates[:MAX_RENDERED_PAGES - 1]
                    internal_crawl_summary["page_cap_reached"] = len(candidates) > len(selected_pages)
                    for page_index, candidate in enumerate(selected_pages, start=2):
                        if request_count >= MAX_BROWSER_REQUESTS:
                            internal_crawl_summary["request_cap_reached"] = True
                            break
                        try:
                            secondary_response = await page.goto(candidate, wait_until="domcontentloaded", timeout=8_000)
                            await page.wait_for_timeout(400)
                            if secondary_response is not None and secondary_response.status >= 400:
                                internal_crawl_summary["navigation_failures"] += 1
                                continue
                            secondary_dom = await page.evaluate("""() => ({
                              elementCount: document.querySelectorAll('*').length,
                              bodyTextLength: (document.body ? document.body.innerText : '').trim().length
                            })""")
                            secondary_metadata = await page.evaluate(RENDERED_METADATA_SCRIPT)
                            safe_page_url = _safe_evidence_url(page.url)
                            rendered_page_urls.append(safe_page_url)
                            internal_crawl_summary["rendered_pages"] += 1
                            outcomes.append({
                                "check_id": "seo.javascript_rendered_metadata", "category": "technical_seo",
                                "page_url": safe_page_url,
                                "outcome": "warning" if _rendered_metadata_needs_review(secondary_metadata) else "pass",
                                "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                "method": "Playwright hydrated DOM metadata presence/shape inspection",
                                "evidence": _format_rendered_metadata_evidence(secondary_metadata),
                                "evidence_ref": f"browser.seo.rendered_metadata.page_{page_index}",
                            })
                            outcomes.append({
                                "check_id": "crawl.javascript_rendered_dom", "category": "crawlability",
                                "page_url": safe_page_url,
                                "outcome": "pass" if secondary_dom["elementCount"] > 0 else "warning",
                                "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                "method": "Playwright Chromium post-JavaScript DOM inspection on a bounded internal page",
                                "evidence": f"Rendered DOM element count: {secondary_dom['elementCount']}; visible body text length: {secondary_dom['bodyTextLength']} characters.",
                                "evidence_ref": f"browser.rendered_dom.page_{page_index}",
                            })
                        except Exception:
                            internal_crawl_summary["navigation_failures"] += 1
                    internal_crawl_summary["request_cap_reached"] = internal_crawl_summary["request_cap_reached"] or request_count >= MAX_BROWSER_REQUESTS
                    outcomes.append({
                        "check_id": "crawl.javascript_internal_pages", "category": "crawlability",
                        "page_url": _safe_evidence_url(target),
                        "outcome": "warning" if internal_crawl_summary["navigation_failures"] or internal_crawl_summary["page_cap_reached"] or internal_crawl_summary["request_cap_reached"] else "pass",
                        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright one-hop discovery from hydrated same-site anchor elements; bounded to six pages",
                        "evidence": _format_internal_crawl_evidence(internal_crawl_summary),
                        "evidence_ref": "browser.internal_crawl",
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
                        "check_id": "performance.browser_lab_vitals", "category": "performance", "page_url": target,
                        "outcome": "not_assessed", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Chromium PerformanceObserver lab diagnostics",
                        "evidence": f"LCP, CLS and Long Tasks observations were unavailable because homepage navigation failed: {navigation_error}.",
                        "evidence_ref": "browser.performance.lab_vitals",
                    })
                    outcomes.append({
                        "check_id": "accessibility.rendered_text_contrast", "category": "accessibility", "page_url": target,
                        "outcome": "not_assessed", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright computed text contrast heuristic",
                        "evidence": f"Rendered text contrast was not assessed because homepage navigation failed: {navigation_error}.",
                        "evidence_ref": "browser.accessibility.text_contrast",
                    })
                    outcomes.append({
                        "check_id": "seo.javascript_rendered_metadata", "category": "technical_seo", "page_url": target,
                        "outcome": "not_assessed", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright Chromium navigation", "evidence": f"Rendered SEO metadata inspection was not run because homepage navigation failed: {navigation_error}.",
                        "evidence_ref": "browser.seo.rendered_metadata.homepage",
                    })
                    outcomes.append({
                        "check_id": "crawl.javascript_internal_pages", "category": "crawlability", "page_url": target,
                        "outcome": "not_assessed", "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "method": "Playwright Chromium navigation", "evidence": f"Internal rendered-page discovery was not run because homepage navigation failed: {navigation_error}.",
                        "evidence_ref": "browser.internal_crawl",
                    })
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
            "rendered_pages": rendered_page_urls,
            "internal_crawl": internal_crawl_summary,
            "browser_requests": min(request_count, MAX_BROWSER_REQUESTS),
            "blocked_requests": browser_blocked_requests,
            "navigation_error": navigation_error,
            "screenshots": "not_captured: durable evidence storage is not configured",
            "core_web_vitals": "field data and INP not measured; LCP/CLS are short-run lab observations only",
            "navigation_timing": "single-run browser diagnostics only; not field Core Web Vitals",
        },
    }
