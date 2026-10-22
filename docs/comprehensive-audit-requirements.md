# Comprehensive Ecommerce Audit Agent — Requirements

## Goal

Build a comprehensive, evidence-first ecommerce website audit and PDF report. The report must be understandable to a non-technical business owner and must not invent findings, measurements, causes, revenue losses, compliance claims, or outcomes.

This document defines intended scope. A category listed here is not implemented or supported until code and tests prove it.

## Finding contract (required for every finding)

Each finding should include:
- Stable finding ID and separate audit category.
- Plain-language title and explanation of technical terms.
- Status: `verified`, `manual_review_required`, or `not_tested` / `insufficient_data`.
- Severity/priority with a documented rule; distinguish technical severity from estimated business impact.
- Affected URL(s), timestamp, test method/tool/version where available, and reproducible evidence.
- Applicable standard or authoritative reference where relevant.
- Fix recommendation with implementation steps and a retest procedure.
- Expected benefit and risk of leaving the issue unresolved, phrased qualitatively unless measurable data supports a number.
- Explicit limitations and evidence confidence.
- Relevant JunctionTools professional remediation service offer, without pressure or unsupported guarantees.

AI may explain and organize collected facts. It must not create findings or quantitative claims unsupported by tool output, evidence, or transparent calculations.

## Separate audit sections

1. Executive summary and audit coverage/limitations.
2. Technical SEO and on-page SEO: titles, meta descriptions, headings, duplicate content, canonical URLs, redirects, HTTP errors, internal/external links, images, JS/CSS, content and crawl diagnostics.
3. Robots.txt: availability, HTTP result, parseable directives, sitemap references, and likely accidental blocks. Explain that robots rules do not guarantee de-indexing or indexing.
4. XML sitemap: discovery, availability, XML parseability, URL status, canonical consistency, and obvious non-indexable URLs.
5. LLMs.txt: availability and basic format/content checks only; explain that it is a proposed convention and not a guaranteed ranking/indexing control.
6. Google indexing: public signals separated from verified index status. Actual Google Search Console indexing/performance data requires authorized owner-provided access or export; never infer exact index state from a public crawl alone.
7. SSL/TLS: certificate validity/expiry/hostname/chain, HTTPS availability and redirects, mixed content, and TLS configuration where safely measurable.
8. Website security: public, non-destructive checks such as security headers, mixed content, exposed directory listings or clearly exposed sensitive files. Deeper vulnerability testing requires authorization and a separate safe test scope. Do not call a website secure based only on headers.
9. Performance and Core Web Vitals: Google PageSpeed Insights/Lighthouse lab results, available field data, and page-level distinctions. Record run context and avoid promising ranking or conversion improvements.
10. WCAG accessibility (target reference: WCAG 2.2 Level A/AA): automated checks plus explicit manual-review checklist. Never claim full WCAG conformance from automated checks alone.
11. ARIA and image alt text: missing/empty alternatives, accessible names, ARIA usage and issues that need human context; meaningful image alternatives require contextual review.
12. Trust Inspector: map JunctionTools Trust Inspector checks individually (e.g. visible payment marks, guarantee seals, SSL/security badges, reviews summaries only where the tool actually checks them). Presence is not authenticity; visible badges do not prove valid TLS.
13. Pixel & Analytics Diagnostic: detectable tags/pixels versus verified event firing and attribution. Do not claim conversions work merely because a script is present. Consent and authenticated test flows may require manual/authorized testing.
14. Mobile UX: responsive layout, viewport, overflow, target sizes, readability and sticky elements where measurable; manual/device testing required for interactions.
15. Ecommerce product/category/collection pages: product data, canonical/indexability, structured data, availability signals, variant/filter/pagination behavior and product page usability, as applicable.
16. Structured data/schema: syntax and eligible properties validated against relevant validators; do not guarantee rich results.
17. International SEO: hreflang/language/region checks when applicable.
18. Backlink and competitor SEO: only when an appropriate external dataset/API or user-provided export is available; label source, date, coverage and plan limits.
19. Content quality: detectable duplication, missing/thin content and basic structure; subjective quality claims require review and clear criteria.
20. Conversion journey/checkout: only checks supported by observable pages or authorized test access; never assume payment, analytics, or checkout behavior without testing.
21. Additional audit modules for any existing JunctionTools tools must be mapped by their actual checks and output—not just by the tool name or URL.

## Professional services

For a verified issue, offer the relevant remediation service (e.g. performance optimization, technical SEO fixes, WCAG remediation, pixel/event troubleshooting, trust-signal implementation, SSL/TLS remediation). Keep the service CTA separate from evidence and recommendations. Do not imply a fix is necessary when the finding is not verified.

## Verification and third-party cross-checking

- Provide source links, evidence, affected URLs and repeatable steps so clients can cross-check findings using relevant independent free/paid tools.
- Do not claim every finding can be verified by every tool.
- Tool results can differ due to crawl scope, user agent, location, cache, time, rendering and data source; explain this where relevant.
- Cite official documentation/standards for rule definitions and test criteria.
- Record what was tested, skipped, blocked, or unavailable.

## Implementation and rollout requirements

1. Inspect and map current backend, API schema, database persistence, deployment, and existing tests before changing behavior.
2. Implement a modular audit runner with independently reported categories; a failure in one check should not silently fabricate a pass or discard other valid results.
3. Store raw/normalized evidence and report metadata with bounded payloads and safe timeouts.
4. Add safe URL/domain validation and SSRF protections before crawling customer-supplied targets; restrict private, loopback, link-local, metadata and non-HTTP(S) destinations, including redirects and DNS resolution concerns.
5. Use bounded concurrency, crawl limits, timeouts, response-size limits, and a clear user-agent.
6. Produce a readable PDF with a summary, separate audit sections, issue details, action plan, sources, coverage and limitations. If PDF generation fails, return a clear error rather than pretending a report exists.
7. Add unit tests for each checker, malformed/unavailable remote responses, timeout/redirect cases, URL/SSRF protections, evidence classification, PDF output, and regression tests for existing license/quota behavior.
8. Keep the current license quota reservation/release behavior intact and test it after integration.
9. Ship in small reviewable pull requests. Do not describe a module as implemented until code and tests support that claim.

## Initial repository gap confirmed during requirement review

The inspected `main.py` currently calls `UniversalEcommerceAgent.process_lead()` and persists a small set of PageSpeed metrics plus a generated outreach pitch. The inspected `ecommerce_agent.py` currently collects a mobile PageSpeed performance score and Speed Index; its output model does not yet represent the comprehensive audit sections above. The inspected `requirements.txt` does not list a PDF-generation library. Therefore this is an audit-engine/reporting build, not just a PDF wording change.


## Additional modern-web requirements (explicit checks)

### Mobile viewport and responsive rendering
- Inspect the `meta name="viewport"` declaration, including missing or problematic width/initial-scale configuration; explain the impact and avoid prescribing `maximum-scale=1` or disabling zoom.
- Test representative widths including 320 CSS px (WCAG reflow reference), 360/375/390/414 CSS px, tablet widths, and desktop widths. Record exact viewport and device emulation context.
- Detect horizontal overflow, clipped/overlapping content, layout shifts, hidden or unreachable controls, text readability, image/video overflow, sticky headers/footers obscuring content, and responsive navigation failures.
- Check portrait/landscape where applicable, browser zoom/reflow, and touch target sizing. A viewport meta tag alone does not prove responsive quality.
- Distinguish static DOM/CSS checks from rendered-browser tests; rendered tests require a controlled browser runner and bounded resource usage.

### Modern performance and browser diagnostics
- Include LCP, INP and CLS where reliable field data is available; identify lab vs field data and sample/window/device context. Include TTFB and other diagnostics as supporting metrics, not substitutes for Core Web Vitals.
- Inspect image dimensions/responsive sources, modern formats, lazy-loading usage (without lazy-loading the likely LCP image by default), font loading, render-blocking CSS/JS, unused assets where tool evidence exists, caching/compression, third-party scripts, and main-thread/long-task issues where measurable.
- Report browser console errors, failed network requests, mixed content and JavaScript exceptions when a real browser run is available.
- Check basic HTML document language, encoding, title, viewport, and semantic landmarks; avoid duplicating results without linking to the original finding.

### JavaScript rendering and modern crawling
- Compare raw HTML with rendered DOM when feasible; note content and links available only after JavaScript execution.
- Check links that are not discoverable as standard navigable links, client-side routing failures, lazy-loaded product listings, pagination/load-more behavior, and crawlable URLs.
- Respect robots directives, rate limits, site terms, and crawl budgets. Do not bypass authentication or access controls.

### Ecommerce catalog and purchase journey
- Inspect product name, price, currency, availability, images, variant/size/color selection, product identifiers and visible-vs-structured-data consistency where available.
- Check Product/Offer/ProductGroup structured data, breadcrumb and organization data when relevant; validate only properties applicable to the page.
- Inspect category/collection pagination, faceted filter URL explosion, duplicate parameter URLs, canonical strategy, out-of-stock/discontinued product behavior, and internal links to important products.
- Assess shipping/returns/contact/privacy policies, review presentation and payment trust signals as presence/consistency checks—not as proof of legitimacy or policy compliance.
- Verify cart/checkout flows only in an explicitly authorized safe test mode; do not submit real orders, payments, emails or customer data.

### Privacy, consent and tracking
- Distinguish detected tags from verified requests/events and successful attribution.
- Where a consent banner is present, test observable consent choices and whether optional tracking behavior appears to respect them; legal compliance requires jurisdiction/context and may require expert review.
- Check for obvious public exposure of secrets or personal data only using safe, non-destructive methods; do not collect or reproduce sensitive data in the PDF.
- Report cookie/security attributes only when actually observed, and avoid declaring privacy-law compliance from a public scan.

### Security framework and safe scope
- Reference OWASP Top 10:2025 as a risk-awareness taxonomy, not a complete vulnerability test or compliance certificate.
- Keep unauthenticated passive checks separate from authenticated/active penetration testing. Active testing requires explicit authorization, agreed scope, safe rate limits, and a separate approval step.
- SSRF protections must handle redirects, DNS rebinding/resolution changes, IPv4/IPv6, alternate IP representations, and metadata/private network destinations; avoid fetching arbitrary local/internal resources.
- Sanitize HTML and URLs included in reports; never execute target content inside the report renderer. Apply output escaping, size limits and safe PDF generation.

### Report accessibility, reproducibility and client usability
- The generated PDF should have selectable text, clear headings, bookmarks/table of contents for long reports, readable contrast, page numbers, source links, and accessible reading order/tags where supported by the PDF library.
- Include audit timestamp, target scope, sampled URLs, crawl depth/page limits, user agent, tools/versions, lab/field distinctions, failed checks and exclusions.
- Include a prioritized action plan that separates severity, effort estimate, dependencies and business relevance. Mark effort as an estimate with stated basis.
- Add a glossary for non-technical owners and a methodology section describing how independent cross-checks can be repeated.

## Mandatory per-issue visual report standard (user-approved reference)

The supplied “Meta Description SEO Audit Dashboard” image is the visual quality and information-density reference for **every individual issue/check detail**, not merely the executive summary. The report generator must implement a reusable issue-dashboard layout with the following elements for each finding:

1. **Issue identity header:** audit category, exact check name, status badge, severity/action priority, and evidence reference IDs.
2. **Outcome summary:** compact visual breakdown of pass / issue / warning / not assessed counts and percentages for the actual sampled pages. Counts must be calculated from recorded check outcomes; never infer a pass from the mere absence of a finding. If the data model cannot establish all four states, label the summary unavailable rather than fabricate 100% pass.
3. **What was observed:** concise, factual, finding-specific observations tied to affected URLs and evidence.
4. **What this means:** plain-language interpretation, separating confirmed technical behavior from hypotheses.
5. **Recommended solution:** actionable steps specific to the check, with retest instructions.
6. **Potential benefit if addressed** and **risk if unresolved:** qualitative unless measurable site/analytics data supports quantified claims.
7. **How to verify:** reproducible cross-check steps and authoritative references where applicable.
8. **Evidence panel:** the actual browser screenshot of the affected page when available, plus the relevant source/DOM/network excerpt or other raw evidence for that exact check. Clearly label viewport, capture time and source URL. Do not reuse a generic homepage screenshot as if it proves an issue on another URL. If evidence is unavailable, show a clear “Evidence not captured” state and explain why; never create fake screenshots or source snippets.
9. **Affected-pages table:** exact URL, observed value, outcome, issue/warning status, and check-specific measurements where applicable. Keep repeated URLs consolidated when multiple identical instances can be represented without losing evidence traceability.
10. **Overall result panel:** issue-specific outcome, tested-page denominator, unassessed-page count, and a concise interpretation with explicit limits.

### Outcome and data integrity rules
- Every audited check must have an explicit outcome record: pass, issue, warning, not_assessed, or error, plus tested-page denominator and evidence links.
- A check that ran and found no issue is a pass only if the checker recorded a successful, valid evaluation. Missing finding records alone are not proof of a pass.
- Keep check execution status separate from finding severity. “Verified” means the observation is supported by evidence; it does not by itself mean the check passed.
- Use real counts and percentages with the denominator visible. A page with missing/invalid markup must not be silently excluded from the denominator.
- Each issue/check gets its own appropriately themed infographic and evidence panel. The infographic must depict that specific check, not repeat a generic icon/graphic as a substitute for evidence.
- Capture issue-level evidence during the same bounded, authorized browser crawl. Store bounded/sanitized excerpts and screenshot references in the finding model; never store credentials, cookies, payment details, or sensitive customer data in a report.
- Keep the full report professional and readable across page boundaries: consistent spacing, no clipped tables, no stranded headings, page numbers, and a table of contents for long reports.
- Add regression tests that inspect each required panel, evidence-to-URL linkage, counts/denominators, unavailable-evidence handling, and PDF pagination. Update visual snapshots for representative SEO, accessibility, performance, security, ecommerce, and conversion findings.

**Acceptance gate:** do not mark per-issue dashboard reporting complete until the generated PDF for each representative audit category visually demonstrates these elements with real evidence and tests pass. A successful PDF-generation job alone is not acceptance.
