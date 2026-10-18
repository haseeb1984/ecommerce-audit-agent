# Agreed Audit Scope — Completion Gate

This document tracks the already-agreed Ecommerce Audit Agent scope. It does not authorize new features or expand the scope. Status is based on the current implementation and the stated limitations in the Phase 1 and Phase 2 pull requests; a feature is not marked complete merely because a related heuristic exists.

## Status definitions

- **Partial** — a limited implementation exists, but the agreed coverage or acceptance checks are not complete.
- **Missing / verify** — no implementation evidence has yet been confirmed in the current PR scope. Inspect the repository and tests before coding.
- **Release blocked** — must not be represented as complete or released until its acceptance checks pass.

## Phase status

| Agreed area | Current evidence | Status | Completion gate |
|---|---|---|---|
| Safe public URL fetching | URL normalization, public-address checks, DNS-pinned resolver, redirect validation, timeouts and response-size bounds described in Phase 1 | Partial until regression tests and production config are confirmed | SSRF/DNS-rebinding/redirect tests pass; outbound network restrictions remain defense-in-depth |
| Core homepage audit | Title, description, viewport, H1, image alt, passive headers, robots.txt, basic sitemap.xml and optional llms.txt checks | Partial | Verify each check's evidence/status and limitations; no implied guarantee from absence of findings |
| Bounded same-origin crawl | First-hop internal HTML crawl capped at 12 URLs; 100-link parsing cap; conventional sitemap discovery capped at 100 locations | Partial by design | Confirm limits, URL scope, deduplication and failure paths through tests; disclose unvisited pages and JavaScript-rendering limitation |
| Technical SEO / ecommerce signals | Sampled page metadata, HTML and X-Robots-Tag noindex, canonical review, basic Product/ProductGroup JSON-LD property presence, category H1/ItemList signals | Partial | Verify Google indexing is not claimed without an authoritative indexing source; distinguish heuristic review signals from confirmed defects |
| Performance / mobile | Static signals including viewport, image dimensions and external/inline asset heuristics | Partial | Real browser rendering and Core Web Vitals field data are not implied; implement only the agreed checks not already present |
| Accessibility / WCAG / ARIA | Source-level signals for button/link names, form labels, document language, images missing an alt attribute, and duplicate HTML IDs | Partial | Do not claim WCAG conformance; verify duplicate issues consolidate across URLs while different fixes remain separate; duplicate IDs are review signals, not automatic conformance verdicts |
| SSL/TLS and transport | TLS certificate/expiry, HTTPS redirect and static mixed-content signals are described in the current checks | Partial | Confirm timeout/error cases remain unverified, not passed; cover certificate/redirect test cases |
| Security / exposure | Passive security headers and a limited set of public exposure-path probes; HTTP 5xx, request failures, redirects, and generic successful responses are explicitly treated as unverified; scoped baseline score | Partial | Score only known observations; unknown checks never count as passes; never label a site hack-proof or provide hack-probability claims |
| Dependency / known vulnerabilities | `.github/dependabot.yml` checks Python and GitHub Actions updates weekly; `.github/workflows/tests.yml` verifies hash-pinned production/development installs, runs `pip-audit`, saves audit JSON and resolved dependency versions as artifacts, then runs regression tests | Partial until the current PR-head audit and artifact are reviewed | Confirm the existing workflow executes for this PR and review its vulnerability findings/artifact; a failing audit must be investigated rather than bypassed, and dependency updates require regression tests |
| Trust Inspector | `trust_checks.py` inventories payment-method, guarantee/returns, review/testimonial, and support/policy cues in sampled public HTML; absence is manual-review-only; tests cover source cues and exclude script/style text | Partial | Confirm real storefront examples and report presentation; source presence does not authenticate badges, reviews, payment availability, or policy adequacy |
| Pixel / analytics diagnostic | `conversion_checks.py` scans initial HTML for known Google tag/Analytics, Meta Pixel, TikTok Pixel, and Microsoft Clarity signatures; findings explicitly say tag presence does not prove event firing, consent handling, or attribution; tests cover positive and no-signature cases | Partial | Improve evidence specificity and false-positive tests; verify with browser tag tools before claiming event delivery; no conversion or attribution result without runtime evidence |
| Mobile UX / viewport | `mobile_ux_checks.py` checks missing viewport declarations, viewport settings without `width=device-width`, and `user-scalable=no` / `maximum-scale=1` directives on sampled HTML pages; tests cover positive, negative, and malformed input cases | Partial | Run browser-based reflow, zoom, target-size and overflow checks where available; source-only signals are not proof of a rendered defect or responsive success |
| Conversion & Paid-Traffic Waste Audit | `conversion_checks.py` inspects static homepage forms, same-origin cart/checkout/contact-like links, and buttons without a source-level accessible name; it does not measure spend, CPC, attribution, conversion rate, or revenue loss | Partial | Extend only with evidence-backed checks; browser-test actual flows when authorized; do not estimate wasted spend without account/campaign data |
| PDF report | Structured evidence-based PDF, severity/status, limitations, scoped security assessment, consolidated same-action findings, shared evidence reference index | Partial | Validate executive summary and layout; include observed issue, plain-language meaning, recommendation, expected benefit/risk only when supported, and verification steps; disclaimer appears once at the end |
| Regression / release acceptance | Latest recorded test run for prior consolidation changes passed; the current PDF polish commit is still running CI | Release blocked | Current PR-head CI passes; inspect generated PDF and edge cases; review PRs; no production deploy without explicit user approval |

## Required report behavior

1. Consolidate repeated instances of the same issue when the underlying cause and recommended action match. List affected pages and unique evidence references together.
2. Keep findings separate when their remediation differs, even if the title is similar.
3. List each evidence URL once in a shared **Evidence & References** section and refer to it by ID within findings.
4. Never invent audit results, conversion loss, revenue impact, security coverage, WCAG conformance, Google indexing status, or business outcomes.
5. If expected benefits or risks cannot be substantiated from the observed issue, phrase them as possible outcomes rather than guaranteed results.
6. Keep the disclaimer once, at the end of the report. A repeating page footer may identify the report but must not repeat the disclaimer.
7. This phase is audit-only. Do not add automatic website-fixing code to the audit engine.

## Release rule

Do not merge or deploy solely because CI passes. First verify the agreed scope against this checklist, confirm the current PR head and generated PDF, and obtain the user's explicit approval for production promotion.