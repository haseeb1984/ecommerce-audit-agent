"""Source-level checks for core HTML document metadata and landmarks.

These checks inspect returned HTML only. They do not establish rendered behavior,
screen-reader usability, or WCAG conformance.
"""
from __future__ import annotations

from html.parser import HTMLParser

from audit_checks import AuditFinding, _finding


class _DocumentBasicsParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.html_lang: str = ""
        self.charsets: list[str] = []
        self.titles: list[str] = []
        self.landmarks: set[str] = set()
        self._in_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        values = {str(key).lower(): (value or "").strip() for key, value in attrs}
        if tag == "html" and not self.html_lang:
            self.html_lang = values.get("lang", "")
        if tag == "meta":
            if values.get("charset"):
                self.charsets.append(values["charset"])
            elif values.get("http-equiv", "").lower() == "content-type":
                content = values.get("content", "")
                import re
                match = re.search(r"charset\\s*=\\s*['\"]?([a-zA-Z0-9._-]+)", content, re.I)
                if match:
                    self.charsets.append(match.group(1))
        if tag == "title":
            self._in_title = True
            self._title_parts = []
        if tag in {"main", "nav", "header", "footer", "aside"}:
            self.landmarks.add(tag)
        if tag == "form" and values.get("role", "").lower() == "search":
            self.landmarks.add("search")

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title" and self._in_title:
            self.titles.append(" ".join(" ".join(self._title_parts).split()))
            self._in_title = False


def inspect_document_basics(html: str, page_url: str) -> list[AuditFinding]:
    """Report missing/ambiguous basic document signals without overclaiming usability."""
    parser = _DocumentBasicsParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:
        return [_finding(
            "technical_seo",
            "Core HTML document metadata could not be assessed",
            "not_tested",
            "info",
            f"The HTML parser raised {type(exc).__name__} while inspecting {page_url}.",
            "A parser error is not evidence that the page is defective; these source-level document checks are inconclusive.",
            "Inspect the returned HTML and rendered DOM, then repeat the document metadata review.",
            ["Open the page source and inspect the html, head, title, and meta declarations.",
             "Compare the source with the rendered DOM if JavaScript changes document metadata."],
            page_url,
        )]

    findings: list[AuditFinding] = []
    if not parser.html_lang:
        findings.append(_finding(
            "accessibility",
            "Document language is not declared in the HTML element",
            "manual_review_required",
            "medium",
            f"No non-empty lang attribute was detected on the html element for {page_url}.",
            "Assistive technology and language-aware processing may use the document language to choose pronunciation and text handling. This source check cannot determine whether scripts set it later.",
            "Declare the primary language on the html element using the appropriate BCP 47 language tag, then verify language changes for any substantial passages in other languages.",
            ["Inspect the final rendered html element for a valid lang attribute.",
             "Check that the declared language matches the page's primary content."],
            page_url,
        ))
    if not parser.charsets:
        findings.append(_finding(
            "technical_seo",
            "Character encoding declaration not detected",
            "manual_review_required",
            "low",
            f"No meta charset or equivalent content-type charset declaration was detected in the returned HTML for {page_url}.",
            "An explicit encoding declaration helps browsers interpret text consistently. HTTP response headers may also specify the encoding, so the absence of a meta declaration alone does not prove incorrect rendering.",
            "Review the HTTP Content-Type charset and document head. Ensure the response encoding and any HTML declaration agree.",
            ["Inspect the HTTP Content-Type response header.",
             "Inspect the first part of the HTML document for a charset declaration and check for visibly corrupted text."],
            page_url,
        ))
    if not parser.titles or not any(title for title in parser.titles):
        findings.append(_finding(
            "technical_seo",
            "Non-empty page title not detected",
            "manual_review_required",
            "medium",
            f"No non-empty title element was detected in the returned HTML for {page_url}.",
            "A descriptive document title helps users identify the page in browser tabs and can support search-result presentation. This source check does not measure ranking impact.",
            "Add one concise, page-specific title and confirm it remains correct in the rendered DOM.",
            ["Inspect the source and rendered document title.",
             "Confirm that the title describes this page rather than repeating a generic site-wide label."],
            page_url,
        ))
    elif len([title for title in parser.titles if title]) > 1:
        findings.append(_finding(
            "technical_seo",
            "Multiple non-empty title elements detected",
            "manual_review_required",
            "low",
            f"Found {len([title for title in parser.titles if title])} non-empty title elements in returned HTML for {page_url}.",
            "Multiple title elements make the intended document title ambiguous; client-side scripts may also modify the title after load.",
            "Keep one intentional title element and verify the final rendered document title.",
            ["Inspect title elements in source and rendered DOM.",
             "Check whether a template or client-side script injects duplicate title elements."],
            page_url,
        ))
    if not parser.landmarks:
        findings.append(_finding(
            "accessibility",
            "No common semantic landmark elements detected",
            "manual_review_required",
            "low",
            f"No main, nav, header, footer, aside, or search landmark was detected in returned HTML for {page_url}.",
            "Semantic landmarks can help assistive-technology users navigate page regions. Their absence from this source sample does not prove the page is unusable or that no landmark is created at runtime.",
            "Review the page structure and add appropriate semantic landmarks where they match the content; avoid adding landmark elements solely to silence an automated check.",
            ["Inspect the rendered accessibility tree for main navigation and primary content landmarks.",
             "Confirm landmark labels are clear when multiple landmarks of the same type exist."],
            page_url,
        ))
    return findings
