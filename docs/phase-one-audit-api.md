# Phase-one comprehensive audit PDF endpoint

## Endpoint

`POST /api/v1/comprehensive-audit?domain=https%3A%2F%2Fexample.com%2F`

Send one existing authentication header:

- `X-License-Key: <license-key>`, or
- `X-API-Key: <api-key>`

A successful response is a downloadable `application/pdf` attachment. The endpoint uses the existing monthly quota reservation and audit-lead accounting lifecycle. A successful PDF consumes one audit slot; failed runs attempt to release the reservation.

## Phase-one coverage

- Google PageSpeed Insights mobile Lighthouse performance score and Speed Index.
- Public homepage source checks for title, meta description, viewport declaration, H1 presence, and images missing an `alt` attribute.
- Passive response-header observations for HSTS, Content-Security-Policy, X-Content-Type-Options, and Referrer-Policy.
- Availability checks for root `robots.txt`, `sitemap.xml`, and optional `llms.txt`.
- Canonical declaration review includes malformed targets, missing/multiple declarations, and cross-origin targets that require contextual review; same-origin default-port equivalents are accepted.
- Bounded sitemap discovery considers up to three robots-declared same-origin sitemap documents, with a shared URL budget. Additional sitemap indexes are validated but their child sitemaps are not recursively expanded. This is not a verdict that cross-origin canonicals are always wrong.
- Evidence, plain-language meaning, suggested remediation, retest steps, and explicit limitations.

## Status meanings

- `verified`: the observation itself was directly seen in the returned response. It does not automatically prove business impact.
- `manual_review_required`: the response alone is insufficient to decide whether a configuration is appropriate.
- `not_tested`: the check could not be completed; this is not a pass or a confirmed issue.
- `insufficient_data`: evidence was insufficient for a reliable conclusion.

## Important limitations

This is an initial phase, not a full-site ecommerce audit. The bounded crawler can follow same-origin links discovered from sampled HTML pages, but its 12-URL budget is not exhaustive. It does not yet crawl every product/category URL, compare raw HTML with a browser-rendered DOM, execute checkout flows, run a full Core Web Vitals field-data analysis, prove Google indexing, test every mobile width in a real browser, establish WCAG conformance, or perform penetration testing. Header presence alone does not prove security. The presence or absence of `llms.txt` does not establish ranking or AI citation outcomes.

The custom DNS resolver validates all returned addresses and passes those exact public IPs to aiohttp for the connection, avoiding a second DNS lookup between validation and connection. Keep deployment-level outbound controls blocking private, loopback, link-local, and cloud metadata services as defense-in-depth.

## Verification

1. Submit a known public test site using a valid license/API key.
2. Confirm the response content type is `application/pdf` and the file opens.
3. Confirm the PDF lists the target URL, timestamp, evidence, recommendation, verification steps, and limitations.
4. Independently repeat each evidence URL and compare results; observations may differ by time, cache, user agent, location, and upstream service.
5. Test invalid/private targets and confirm they are rejected before quota reservation.
6. Confirm a failed audit releases its reservation and a successful report counts against the same quota used by the legacy endpoint.
