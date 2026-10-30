# Phase 6 — PDF and Audit Results Completion

## Implementation status

**Source implementation: complete for the agreed Phase 6 scope.** This status describes repository code only. It is not a claim that a real client PDF has been visually accepted, production migrations have been applied, or the release has been deployed.

## PDF report structure

The report renderer in `report_generator.py` produces selectable-text A4 PDFs with bookmarks/table of contents, page numbering, running report identity, and these sections:

1. Executive overview and explanation of verified / manual-review / not-tested statuses.
2. Actual desktop/mobile website captures when valid capture data is supplied; unavailable captures are disclosed rather than fabricated.
3. Scoped security baseline with an explicit warning that the score is not hack probability or a security certification.
4. Executive finding summaries, audit-area summaries, phase scorecard, and prioritized actions.
5. Conversion and paid-traffic review with explicit disclosure that spend, attribution, conversion rate, and revenue are not measured by public source checks.
6. Individual finding dashboards with finding IDs, check/finding identity, category, status, severity priority, evidence counts, recorded outcome breakdown when the exact check can be linked, affected URLs, evidence references, observations, interpretation, recommendations, qualitative benefit/risk, verification steps, standards, dependencies, and effort assumptions.
7. A shared evidence-reference index and sampled-page list.
8. Explicit recorded outcome totals and category distribution.
9. A check-by-check outcome register keyed by exact `check_id`, including recorded pass / issue / warning / not-assessed / error counts, record denominator, distinct page count, method, evidence sample, and a source page where available.
10. Coverage manifest, limitations, manual accessibility review checklist, methodology / independent verification guidance, run limits, security scope, glossary, optional professional support offer, and one final disclaimer.

## Outcome integrity

- Only explicit `CheckOutcome` records contribute to pass, issue, warning, not-assessed, or error totals.
- The denominator is the count of recorded outcomes for the displayed check or category; missing records are never converted into passes.
- A check without an exact linked outcome is labelled unavailable for that check. The overall page count is not substituted as its denominator.
- Category-signal coverage and checker-group execution coverage are described separately; execution does not mean that every check passed.
- Verified findings describe supported observations and may represent either a positive signal or an issue. Severity is a triage priority, not a measured business impact.
- Screenshots are accepted only as bounded, valid PNG/JPEG data. A general screenshot is never represented as proof of an issue on a different affected URL. Missing issue-level captures are explicitly disclosed.

## Evidence safety and client report history

- Report text is escaped and bounded; URL display strips credentials, query strings, and fragments, and rejects unsupported or malformed destinations.
- Finding evidence, recommendations, references, and affected URLs are consolidated without combining findings that require different remediation.
- Authenticated report listing, PDF download, coverage, and paginated evidence endpoints remain scoped to the owning license.
- Saved evidence is allowlisted and redacted before being returned to the customer portal.
- The customer portal shows recorded outcome counts, provides separate saved-findings and check-outcomes views, supports pagination, and offers PDF download and opt-in email delivery.
- PDF storage and evidence metadata use the existing `AuditReport` persistence model and migration; no new Phase 6 production migration is introduced.

## Explicit limitations

The report does not claim full-site crawl coverage, complete individual-check execution coverage, Google indexing verification without authorized Search Console data, full software composition analysis, penetration testing, WCAG conformance, verified analytics event delivery, legal/privacy compliance, checkout/payment success, measured wasted ad spend, or quantified revenue impact. Human and authorized testing remains clearly identified as not performed.

## Release and verification boundary

The Phase 6 source changes are prepared on the draft implementation branch. No test suite, live audit, PDF QA job, database migration, merge, or production deployment was run as part of this implementation batch, in accordance with the current project instruction to complete source requirements before verification. Before release, the owner must authorize a controlled real-result audit, review the resulting PDF and evidence-to-page mapping, verify report ownership isolation and email delivery in the intended environment, confirm required database migrations, and explicitly approve merge/deployment.
