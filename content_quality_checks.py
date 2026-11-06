"""Conservative visible-content volume and exact-duplicate checks.

These are bounded source-level editorial review signals. They do not judge
writing quality, usefulness, originality, or search-engine quality.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Mapping

from audit_checks import AuditFinding, CheckOutcome


MIN_VISIBLE_WORDS = 100
FINGERPRINT_MIN_WORDS = 100


class _VisibleContentParser(HTMLParser):
    _IGNORED = {"script", "style", "noscript", "svg", "template", "nav", "footer", "header"}
    _VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.body_parts: list[str] = []
        self.main_parts: list[str] = []
        self._ignored_depth = 0
        self._main_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if self._ignored_depth:
            if tag not in self._VOID:
                self._ignored_depth += 1
            return
        if tag in self._IGNORED:
            self._ignored_depth = 1
            return
        if tag in {"main", "article"}:
            self._main_depth += 1

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._ignored_depth:
            self._ignored_depth = max(0, self._ignored_depth - 1)
            return
        if tag in {"main", "article"}:
            self._main_depth = max(0, self._main_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._ignored_depth or not data.strip():
            return
        normalized = " ".join(data.split())
        if normalized:
            self.body_parts.append(normalized)
            if self._main_depth:
                self.main_parts.append(normalized)


def _normalized_visible_text(html: str) -> str:
    parser = _VisibleContentParser()
    parser.feed(html[:1_000_000])
    parser.close()
    main_text = " ".join(parser.main_parts)
    body_text = " ".join(parser.body_parts)
    selected = main_text if len(re.findall(r"\w+", main_text, flags=re.UNICODE)) >= 20 else body_text
    normalized = unicodedata.normalize("NFKC", selected).casefold()
    return " ".join(normalized.split())


def inspect_content_quality(
    html: str,
    page_url: str,
    *,
    prior_fingerprints: Mapping[str, str] | None = None,
) -> tuple[list[AuditFinding], list[CheckOutcome], str | None]:
    """Return low-volume/exact-duplicate review signals and explicit outcomes."""
    normalized_text = _normalized_visible_text(html)
    words = re.findall(r"[\w]+(?:['’\-][\w]+)*", normalized_text, flags=re.UNICODE)
    word_count = len(words)
    findings: list[AuditFinding] = []
    outcomes: list[CheckOutcome] = []
    observed_at = datetime.now(timezone.utc).isoformat()

    if word_count < MIN_VISIBLE_WORDS:
        evidence = (
            f"The bounded HTML text extractor found {word_count} visible word(s) "
            f"against a {MIN_VISIBLE_WORDS}-word review threshold. This is a low-volume signal, "
            "not a judgment of content quality or page usefulness."
        )
        findings.append(AuditFinding(
            category="content_quality",
            title="Low visible-text volume needs editorial review",
            status="manual_review_required",
            severity="low",
            evidence=evidence,
            explanation=(
                "A small amount of visible text can make a page difficult to understand, but image-led "
                "products, interactive applications, and intentionally concise landing pages may be valid. "
                "This source-only heuristic does not assess originality, usefulness, or search ranking."
            ),
            recommendation=(
                "Review the page in its rendered context. Add clear, genuinely useful product or category "
                "information only where it helps visitors; do not add filler text to reach a word count."
            ),
            verification_steps=[
                "Inspect the rendered page and identify the primary user task.",
                "Confirm that important product/category details are visible and understandable.",
                "Have the content owner review whether the page needs additional unique explanatory content.",
            ],
            source_url=page_url,
            test_method="bounded static HTML visible-text extraction excluding script, style, navigation, header and footer content",
            evidence_confidence="limited",
        ))
        volume_outcome = "warning"
    else:
        evidence = (
            f"The bounded HTML text extractor found {word_count} visible word(s), meeting the "
            f"{MIN_VISIBLE_WORDS}-word low-volume review threshold. This does not establish content quality."
        )
        volume_outcome = "pass"
    outcomes.append(CheckOutcome(
        check_id="content.visible_text_volume",
        category="content_quality",
        page_url=page_url,
        outcome=volume_outcome,
        observed_at_utc=observed_at,
        method="bounded static HTML visible-text extraction",
        evidence=evidence,
        evidence_ref="content.visible_text_volume",
    ))

    fingerprint = None
    if word_count >= FINGERPRINT_MIN_WORDS:
        fingerprint = hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
        duplicate_url = (prior_fingerprints or {}).get(fingerprint)
        if duplicate_url and duplicate_url != page_url:
            duplicate_evidence = (
                "The normalized visible text exactly matches another page in the bounded crawl sample: "
                f"{duplicate_url}. Page text is not reproduced in the evidence."
            )
            findings.append(AuditFinding(
                category="content_quality",
                title="Exact duplicate visible content across sampled pages",
                status="manual_review_required",
                severity="low",
                evidence=duplicate_evidence,
                explanation=(
                    "Exact visible-text duplication can be intentional for localized, faceted, or template "
                    "pages, but may also indicate duplicated page content. This comparison is limited to the "
                    "bounded HTML sample and does not evaluate canonicalization or search-engine selection."
                ),
                recommendation=(
                    "Review both pages and their canonical/variant intent. Keep genuinely distinct pages "
                    "useful and self-consistent; consolidate or canonicalize only where the site owner confirms "
                    "the pages are duplicate variants."
                ),
                verification_steps=[
                    "Compare both rendered pages and their intended audience/search intent.",
                    "Review canonical URLs, product variants, locale and filter parameters.",
                    "Confirm any consolidation or canonical change with the site owner.",
                ],
                source_url=page_url,
                test_method="SHA-256 comparison of normalized visible text across the bounded same-origin HTML sample",
                evidence_confidence="moderate",
            ))
            duplicate_outcome = "warning"
        else:
            duplicate_evidence = (
                "No exact duplicate normalized visible-text match was found among earlier pages in this bounded sample. "
                "Near-duplicates and content quality were not assessed."
            )
            duplicate_outcome = "pass"
    else:
        duplicate_evidence = (
            f"Exact duplicate comparison was not performed because the page had fewer than "
            f"{FINGERPRINT_MIN_WORDS} visible words."
        )
        duplicate_outcome = "not_assessed"
    outcomes.append(CheckOutcome(
        check_id="content.exact_duplicate_copy",
        category="content_quality",
        page_url=page_url,
        outcome=duplicate_outcome,
        observed_at_utc=observed_at,
        method="bounded exact normalized visible-text fingerprint comparison",
        evidence=duplicate_evidence,
        evidence_ref="content.exact_duplicate_copy",
    ))
    return findings, outcomes, fingerprint
