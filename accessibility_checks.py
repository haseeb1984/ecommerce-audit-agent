"""Conservative HTML accessibility signals; not a WCAG conformance test."""
from __future__ import annotations

from html.parser import HTMLParser

from audit_checks import AuditFinding


class _AccessibilityParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.html_lang = ""
        self.ids: set[str] = set()
        self.id_counts: dict[str, int] = {}
        self.aria_references: list[tuple[str, str, str]] = []
        self.label_for: set[str] = set()
        self.wrapped_label_depth = 0
        self.inputs: list[dict[str, str]] = []
        self.links: list[dict[str, str | bool]] = []
        self.buttons: list[dict[str, str | bool]] = []
        self.images_missing_alt: int = 0
        self._active_link: dict[str, str | bool] | None = None
        self._active_button: dict[str, str | bool] | None = None
        self._active_label_depth = 0

    def handle_starttag(self, tag, attrs):
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "html":
            self.html_lang = values.get("lang", "").strip()
        if values.get("id"):
            self.ids.add(values["id"])
            self.id_counts[values["id"]] = self.id_counts.get(values["id"], 0) + 1
        for attribute in ("aria-labelledby", "aria-describedby", "aria-controls", "aria-owns", "aria-errormessage"):
            for referenced_id in values.get(attribute, "").split():
                self.aria_references.append((attribute, referenced_id, tag))
        if tag == "label" and values.get("for", "").strip():
            self.aria_references.append(("label for", values["for"].strip(), tag))
        if tag == "label":
            if values.get("for"):
                self.label_for.add(values["for"])
            self._active_label_depth += 1
        if (
            (tag == "input" and values.get("type", "text").lower() not in {"hidden", "submit", "button", "reset", "image"})
            or tag in {"select", "textarea"}
        ):
            self.inputs.append({
                "id": values.get("id", ""),
                "aria_label": values.get("aria-label", "").strip(),
                "aria_labelledby": values.get("aria-labelledby", "").strip(),
                "title": values.get("title", "").strip(),
                "inside_label": "true" if self._active_label_depth else "false",
            })
        if tag == "a" and values.get("href") is not None:
            self._active_link = {
                "text": "", "aria_label": values.get("aria-label", "").strip(),
                "title": values.get("title", "").strip(), "has_image_alt": False,
                "has_svg_title": False,
            }
            self.links.append(self._active_link)
        elif tag == "button":
            self._active_button = {
                "text": "", "aria_label": values.get("aria-label", "").strip(),
                "title": values.get("title", "").strip(), "has_image_alt": False,
            }
            self.buttons.append(self._active_button)
        if tag == "img":
            # Missing alt is a clear source-level review signal. An explicit empty
            # alt may be correct for decorative imagery, so it is not flagged here.
            if "alt" not in values and values.get("role", "").lower() not in {"presentation", "none"}:
                self.images_missing_alt += 1
            if self._active_link is not None and values.get("alt", "").strip():
                self._active_link["has_image_alt"] = True
            if self._active_button is not None and values.get("alt", "").strip():
                self._active_button["has_image_alt"] = True
        if tag == "svg" and self._active_link is not None:
            # SVG title handling is approximate; rendered accessibility tree needs review.
            self._active_link["has_svg_title"] = bool(values.get("aria-label", "").strip())

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "a":
            self._active_link = None
        elif tag == "button":
            self._active_button = None
        elif tag == "label" and self._active_label_depth:
            self._active_label_depth -= 1

    def handle_data(self, data):
        if self._active_link is not None:
            self._active_link["text"] = str(self._active_link["text"]) + data.strip()
        if self._active_button is not None:
            self._active_button["text"] = str(self._active_button["text"]) + data.strip()


def inspect_static_accessibility_signals(html: str, page_url: str) -> list[AuditFinding]:
    """Flag clear source-level review signals without asserting WCAG compliance."""
    parser = _AccessibilityParser()
    try:
        parser.feed(html)
    except Exception:
        return []

    findings: list[AuditFinding] = []
    unresolved_refs = sorted({(attribute, identifier) for attribute, identifier, _tag in parser.aria_references if identifier not in parser.ids})
    if unresolved_refs:
        details = ", ".join(f"{attribute}='{identifier}'" for attribute, identifier in unresolved_refs[:10])
        findings.append(AuditFinding(
            category="accessibility", title="Some label or ARIA references point to missing IDs",
            status="manual_review_required", severity="medium",
            evidence=f"Found {len(unresolved_refs)} unique reference(s) to IDs not present in returned HTML for {page_url}: {details}.",
            explanation="A label or ARIA relationship that points to a missing element may not provide the intended name, description, control relationship, or error message. This source check cannot assess JavaScript-created elements or the final accessibility tree.",
            recommendation="Correct each reference to an existing, unique ID or remove the relationship if it is not needed. Verify the relationship in the rendered page.",
            verification_steps=["Inspect each listed attribute and confirm its target exists in the rendered DOM.", "Check accessible names, descriptions, controls, and validation messages using the browser accessibility tree."],
            source_url=page_url,
        ))
    duplicate_ids = sorted(identifier for identifier, count in parser.id_counts.items() if count > 1)
    if duplicate_ids:
        findings.append(AuditFinding(
            category="accessibility", title="Duplicate HTML IDs may affect accessible relationships",
            status="manual_review_required", severity="medium",
            evidence=f"Found {len(duplicate_ids)} duplicate ID value(s) in returned HTML for {page_url}: {', '.join(duplicate_ids[:10])}.",
            explanation="IDs are expected to be unique within a document. Duplicates can make labels, fragment links, and ARIA references point to an unintended element. This source check identifies repeated values but cannot confirm the impact in the rendered accessibility tree.",
            recommendation="Make each ID unique and update any associated label-for, fragment link, and ARIA references consistently.",
            verification_steps=["Inspect each repeated ID and its references in the rendered DOM.", "Check form labels and aria-labelledby / aria-describedby relationships with a browser accessibility tree."],
            source_url=page_url,
        ))
    if parser.images_missing_alt:
        findings.append(AuditFinding(
            category="accessibility", title="Images may be missing text alternatives",
            status="manual_review_required", severity="medium",
            evidence=f"Found {parser.images_missing_alt} image(s) without an alt attribute in returned HTML for {page_url}.",
            explanation="People who cannot see an image may miss information conveyed by it. A missing alt attribute differs from an intentionally empty alt used for decorative images; this source check cannot determine the right alternative for each image.",
            recommendation="Review each image in context. Give informative product, category, and functional images concise text alternatives; use alt=\"\" for purely decorative images when appropriate.",
            verification_steps=["Inspect each flagged image in the rendered page and decide whether it conveys information or performs an action.", "Check product images, linked logos, and image-based controls with a browser accessibility tree or scanner."],
            source_url=page_url,
        ))
    unlabeled_inputs = [item for item in parser.inputs if not (
        item["aria_label"] or item["aria_labelledby"] or item["title"] or
        item["inside_label"] == "true" or (item["id"] and item["id"] in parser.label_for)
    )]
    if unlabeled_inputs:
        findings.append(AuditFinding(
            category="accessibility", title="Form controls may lack accessible labels",
            status="manual_review_required", severity="medium",
            evidence=f"Found {len(unlabeled_inputs)} form control(s) without a detectable associated label, aria-label, aria-labelledby, or title in returned HTML for {page_url}.",
            explanation="People using screen readers need each form control's purpose announced. This static check may miss labels or accessible names created by JavaScript and cannot assess whether a label is meaningful.",
            recommendation="Give each user-facing form control a visible, programmatically associated label where possible. Use aria-label or aria-labelledby only when a visible label is not practical, and verify the rendered accessibility tree.",
            verification_steps=["Inspect each flagged control in the rendered page and browser accessibility tree.", "Test keyboard navigation and screen-reader announcements; retest after template changes."],
            source_url=page_url,
        ))

    unnamed_links = [item for item in parser.links if not (
        str(item["text"]).strip() or item["aria_label"] or item["title"] or
        item["has_image_alt"] or item["has_svg_title"]
    )]
    if unnamed_links:
        findings.append(AuditFinding(
            category="accessibility", title="Links may have no accessible name",
            status="manual_review_required", severity="medium",
            evidence=f"Found {len(unnamed_links)} link(s) with no detectable text, aria-label, title, informative image alt, or SVG label in returned HTML for {page_url}.",
            explanation="A link needs an accessible name so assistive technology users can understand its destination or purpose. This source check cannot determine whether JavaScript adds a name or whether existing link text is clear.",
            recommendation="Provide concise link text that describes the destination or action. For icon-only links, provide an appropriate accessible name and verify the rendered accessibility tree.",
            verification_steps=["Inspect flagged links in the rendered DOM and accessibility tree.", "Navigate links with a keyboard and test with an accessibility scanner."],
            source_url=page_url,
        ))

    unnamed_buttons = [item for item in parser.buttons if not (
        str(item["text"]).strip() or item["aria_label"] or item["title"] or item["has_image_alt"]
    )]
    if unnamed_buttons:
        findings.append(AuditFinding(
            category="accessibility", title="Buttons may have no accessible name",
            status="manual_review_required", severity="medium",
            evidence=f"Found {len(unnamed_buttons)} button(s) with no detectable text, aria-label, title, or image alt in returned HTML for {page_url}.",
            explanation="Buttons need an accessible name that describes the action. Icon-only controls and names added by JavaScript require rendered-page review.",
            recommendation="Add meaningful visible button text where possible. For icon-only buttons, provide a concise accessible name and check it in the rendered accessibility tree.",
            verification_steps=["Inspect flagged buttons in the rendered DOM and accessibility tree.", "Test keyboard activation and screen-reader announcements."],
            source_url=page_url,
        ))

    if not parser.html_lang:
        findings.append(AuditFinding(
            category="accessibility", title="Document language is not declared in returned HTML",
            status="manual_review_required", severity="low",
            evidence=f"No lang attribute was detected on the html element in returned HTML for {page_url}.",
            explanation="A declared page language helps assistive technology pronounce content correctly. This check examines only the returned source and does not validate language tags or language changes within the page.",
            recommendation="Set an appropriate BCP 47 language tag on the html element, such as lang=\"en\", matching the page's primary language. Mark meaningful language changes on individual elements when needed.",
            verification_steps=["Inspect the rendered html element and confirm its lang value matches the primary page language.", "Run an accessibility scanner and manually review language changes."],
            source_url=page_url,
        ))
    return findings
