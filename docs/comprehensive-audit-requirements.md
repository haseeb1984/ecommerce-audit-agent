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
