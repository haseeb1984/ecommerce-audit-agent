# Isolated Playwright browser worker

The main SaaS API and scan worker do not install or launch Chromium. The optional
browser worker is a separately deployable service built from the repository root:

```sh
docker build -f browser-worker/Dockerfile -t ecommerce-audit-browser-worker .
```

Run one worker process per container. Set `BROWSER_AUDIT_SHARED_SECRET` to a
random secret of at least 32 characters. Set the same secret and
`BROWSER_AUDIT_SERVICE_URL=https://<private-browser-service-host>` on the
existing scan worker. The scan worker refuses non-HTTPS service URLs and does not
send audit requests unless both settings are present. Requests use HMAC-SHA256
over the timestamp and exact request body; signatures expire after five minutes.

## Network and isolation requirements

This service opens untrusted public websites in Chromium. Deploy it in a separate
container/network from the SaaS API, database credentials, and internal services.
The browser container must have no database credentials, cloud metadata access,
host mounts, Docker socket, or access to private service networks.

**Enforce outbound network policy at the container/network layer.** Deny loopback,
private, link-local, multicast, reserved, metadata-service and other non-public
destinations for IPv4 and IPv6, including after redirects. Allow only DNS resolution
and outbound TCP 80/443 only; block arbitrary UDP, WebRTC/STUN, and WebSocket egress. The worker explicitly closes WebSockets. The in-process DNS/IP check and
Playwright request interception are defense in depth; they are not a substitute
for an egress firewall because Chromium performs its own DNS resolution and a
host can change DNS answers between validation and connection.

Do not expose the service publicly without TLS, rate limiting, request-size limits,
container CPU/memory/process limits, and network egress restrictions. The unauthenticated `/health` endpoint reveals
only service health and viewport count. The audit endpoint is HMAC-authenticated.
Keep browser worker logs free of customer credentials and request bodies.

## Implemented browser checks

- A bounded Chromium render of up to six pages: the submitted URL plus a one-hop sample of up to five JavaScript-exposed same-site links discovered after hydration. Secondary navigation has an 8-second timeout; top-level redirects remain on the requested host or its `www` alias, and web requests are limited to ports 80/443.
- Viewport widths 320, 360, 375, 390, 414, 768 and 1365 CSS pixels, plus fixed 390x844 portrait and 844x390 landscape overflow checks.
- Rendered DOM presence, horizontal overflow, and interactive-element dimensions
  below a 24px heuristic threshold.
- Browser console/page exceptions and failed or blocked network requests.\n- Short-run PerformanceObserver diagnostics for LCP, CLS session windows, and Long Tasks where Chromium exposes those APIs. Values are single-run lab observations and review triggers, not field Core Web Vitals, Lighthouse scores, or INP.
- Rendered accessibility heuristics for image alt-attribute presence, accessible-name signals, and suspicious tabindex patterns on visible interactive controls; these are not WCAG conformance verdicts.
- Product-page rendered-signal heuristic for visible H1, price candidates, Product JSON-LD, purchase controls, variant-selection controls, product-image candidates, and quantity controls; it is not a checkout test or product-data correctness verdict.
- The rendered internal-page sample reports discovered links, rendered pages, navigation failures, and page/request-cap truncation; it is not a full-site crawl and does not recursively follow links.
- Each rendered homepage/internal page also records title length, meta-description count/length, canonical count and same-origin signal, robots noindex presence, visible H1 count, and Product/ProductGroup JSON-LD entity count. These are presence/shape heuristics, not full metadata, canonical, indexing, or schema validity checks.
- Per-check outcomes and evidence summaries returned to the existing scan worker
  and persisted in the existing `WebsiteScanResult`; no second queue or billing path.

## Explicit limitations

- Screenshots are not captured or persisted until durable evidence storage is
  configured. Do not advertise screenshot evidence as available.
- Product-page detection is heuristic and may not identify every theme or variant UI; missing selectors are warnings for review, not proof that a product cannot be purchased.
- This worker does not measure field Core Web Vitals or INP. Its LCP/CLS/Long Tasks values are short-run, single-render lab observations and are sensitive to page state, consent, viewport changes, browser support, and observation duration. The fixed
  portrait/landscape check measures viewport overflow only; it does not verify
  physical device rotation sensors. The tabindex heuristic does not prove actual
  keyboard operability, focus visibility, pinch-zoom behavior, or screen-reader
  behavior.
- The 24px target heuristic is a triage signal, not a WCAG conformance verdict.
- A completed browser request does not establish full site crawl coverage. The
  one-hop internal-page sample is capped at six pages total and 30 eligible
  candidates; it does not recursively follow links or guarantee template coverage.
- Browser service deployment and a live controlled-site acceptance run remain
  release tasks. CI tests authentication, client behavior and SSRF guards with
  mocks; it does not claim a deployed Chromium environment has been verified.
