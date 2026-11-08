# Audit engine coverage and evidence semantics

The comprehensive audit records what each checker actually evaluated. A missing finding is not a pass unless the relevant checker completed and emitted an explicit `pass` outcome.

## Static check groups now explicitly recorded

For each successfully fetched HTML page, the bounded crawler records independent outcomes for:

- Ecommerce catalog navigation and product/category signals.
- Sensitive-looking fields in GET forms.
- Accessible-name and ARIA relationships, including native and custom `role=button` / `role=link` controls, labels, duplicate IDs, focusable content hidden from assistive technology, unnamed input button/submit/reset controls, embedded iframe titles, and linked image-map area names.
- Product structured-data inspection, including a clean no-signal result.
- Hreflang and international SEO declarations.
- Analytics/pixel tags and visible consent-interface signals.
- Cookie security attributes, separately from general response-header quality.
- Public API documentation/schema exposure, separately from exposed configuration artifacts.
- TLS/transport and mixed-content review.
- Common public exposure-path probes.
- Sampled internal URL HTTP responses.
- Cross-page duplicate title and meta-description comparisons within the bounded crawl sample.
- Visible-text volume and exact duplicate body-copy comparisons within the bounded crawl sample; near-duplicates and subjective writing quality are not assessed.

An outcome is scoped to the page and method shown in its record. The internal-link outcome covers only the bounded sample actually fetched; it is not a full-site link inventory.

## Outcome interpretation

- `pass`: the stated checker completed and did not emit an issue or review signal.
- `issue`: the checker confirmed an actionable condition under its rule.
- `warning`: the checker found a signal that needs contextual/manual review.
- `not_assessed`: the method could not assess the condition or did not have sufficient evidence.
- `error`: the checker failed before reaching a reliable conclusion.

A `verified` finding means the observation was confirmed; it does not automatically mean the observation is a defect. Informational positive detections, such as the presence of structured data, are not counted as issues solely because they were verified.

## Scope boundaries

This remains a bounded public, unauthenticated HTTP(S) audit. When the isolated signed Playwright browser service is configured, both synchronous licensed audits and bulk scan workers perform bounded rendered-page inspection at configured viewport widths and merge its findings/outcomes into the coverage manifest. If the browser service is unavailable or navigation fails, browser checks remain explicitly unavailable/not assessed; static HTML signals are never promoted to rendered passes.

The browser worker does not claim full cross-browser/device coverage, field Core Web Vitals or INP, manual WCAG conformance, Google Search Console index status, backlink/competitor dataset analysis, authorized checkout completion, consent-dependent analytics event delivery, or active penetration testing. Those methods remain explicitly not assessed until the corresponding browser, owner-authorized provider, or manual-review capability is configured.

Security findings reference OWASP Top 10:2025 as a risk-awareness taxonomy only. Passive response-header checks validate selected standard-header values and review signals; they do not test the full OWASP categories, establish exploitability, or provide a compliance certification.

The crawler remains capped by its page, link, response-size, and timeout limits. Findings and outcomes are evidence summaries, not a guarantee of ranking, conversion, security, or legal compliance.


## Content-quality signal boundaries

The bounded crawler now records visible-text volume and exact duplicate visible-text comparisons across the fetched same-origin sample. These are low-severity editorial review signals only: scripts, styles, navigation, headers and footers are excluded; the checker does not score writing quality, originality, usefulness, or ranking potential. Short/image-led pages remain manual review, and near-duplicate content is not assessed.
