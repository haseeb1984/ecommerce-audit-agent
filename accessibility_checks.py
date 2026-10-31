"""Conservative HTML accessibility signals; not a WCAG conformance test."""
from __future__ import annotations

from html.parser import HTMLParser
import re

from audit_checks import AuditFinding



# These checks require rendered/browser or human context and are never inferred from static HTML.
MANUAL_WCAG_REVIEW_CHECKLIST = (
    "Keyboard-only navigation: logical focus order, visible focus, and no keyboard traps.",
    "Rendered contrast and non-text contrast, including states and overlays.",
    "Zoom/reflow and responsive layouts at narrow viewport widths.",
    "Meaningful image alternatives and decorative-image handling in page context.",
    "Dynamic updates, validation errors, dialogs, menus, and focus management with assistive technology.",
    "Captions/transcripts for relevant media and accessible names/instructions for interactive controls.",
    "Task completion using a screen reader and keyboard for representative shopping journeys; do not submit real orders.",
)


class _AccessibilityParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.html_lang = ""
        self.main_landmarks = 0
        self.ids: set[str] = set()
        self.id_counts: dict[str, int] = {}
        self.id_text: dict[str, str] = {}
        self._text_id_stack: list[tuple[str, str]] = []
        self.aria_references: list[tuple[str, str, str]] = []
        self.label_for: set[str] = set()
        self.wrapped_label_depth = 0
        self.inputs: list[dict[str, str]] = []
        self.element_labelledby: list[str] = []
        self.image_submit_inputs: list[dict[str, str]] = []
        self.input_action_controls: list[dict[str, str]] = []
        self.links: list[dict[str, str | bool]] = []
        self.buttons: list[dict[str, str | bool]] = []
        self.images_missing_alt: int = 0
        self.aria_hidden_focusables: list[tuple[str, str]] = []
        self.aria_hidden_descendant_focusables: list[tuple[str, str]] = []
        self._aria_hidden_stack: list[tuple[str, bool]] = []
        self._active_link: dict[str, str | bool] | None = None
        self._active_button: dict[str, str | bool] | None = None
        self._role_control_stack: list[tuple[str, dict[str, str | bool]]] = []
        self._active_svg_control: dict[str, str | bool] | None = None
        self._inside_svg = 0
        self._in_svg_title = False
        self._active_label_depth = 0

    def handle_starttag(self, tag, attrs):
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        inherited_aria_hidden = any(hidden for _ancestor, hidden in self._aria_hidden_stack)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self._text_id_stack.append((tag, values.get("id", "")))
        if tag == "html":
            self.html_lang = values.get("lang", "").strip()
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self._aria_hidden_stack.append((tag, inherited_aria_hidden or values.get("aria-hidden", "").strip().lower() == "true"))
        tabindex = values.get("tabindex", "").strip()
        is_focusable = tag in {"a", "button", "input", "select", "textarea"} and (tag != "a" or "href" in values)
        if values.get("aria-hidden", "").strip().lower() == "true" and (is_focusable or (tabindex.lstrip("+-").isdigit() and int(tabindex) >= 0)):
            self.aria_hidden_focusables.append((tag, values.get("type", "").strip().lower()))
        if inherited_aria_hidden and (is_focusable or (tabindex.lstrip("+-").isdigit() and int(tabindex) >= 0)):
            self.aria_hidden_descendant_focusables.append((tag, values.get("type", "").strip().lower()))
        # Count a native <main> or a non-main element with role=main once.
        # Do not double-count <main role=main> as two landmarks.
        if tag == "main" or values.get("role", "").strip().lower() == "main":
            self.main_landmarks += 1
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
        if tag == "input" and values.get("type", "text").lower() == "image":
            # Image submit controls need an accessible name; alt text is the usual
            # source-level mechanism. Do not silently exclude them as ordinary buttons.
            self.image_submit_inputs.append({
                "alt": values.get("alt", "").strip(),
                "aria_label": values.get("aria-label", "").strip(),
                "aria_labelledby": values.get("aria-labelledby", "").strip(),
                "title": values.get("title", "").strip(),
            })
        if tag == "input" and values.get("type", "text").lower() in {"button", "submit", "reset"}:
            self.input_action_controls.append({
                "type": values.get("type", "text").lower(),
                "value": values.get("value", "").strip(),
                "has_value": "true" if "value" in values else "false",
                "aria_label": values.get("aria-label", "").strip(),
                "aria_labelledby": values.get("aria-labelledby", "").strip(),
                "title": values.get("title", "").strip(),
            })
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
                "aria_labelledby": values.get("aria-labelledby", "").strip(),
                "title": values.get("title", "").strip(), "has_image_alt": False,
                "has_svg_title": bool(values.get("aria-label", "").strip()),
                "svg_title": "",
            }
            self.links.append(self._active_link)
        elif tag == "button":
            self._active_button = {
                "text": "", "aria_label": values.get("aria-label", "").strip(),
                "aria_labelledby": values.get("aria-labelledby", "").strip(),
                "title": values.get("title", "").strip(), "has_image_alt": False,
                "has_svg_title": bool(values.get("aria-label", "").strip()),
                "svg_title": "",
            }
            self.buttons.append(self._active_button)
        elif values.get("role", "").strip().lower() in {"button", "link"}:
            role = values.get("role", "").strip().lower()
            item = {
                "text": "", "aria_label": values.get("aria-label", "").strip(),
                "aria_labelledby": values.get("aria-labelledby", "").strip(),
                "title": values.get("title", "").strip(), "has_image_alt": False,
                "has_svg_title": bool(values.get("aria-label", "").strip()),
                "svg_title": "",
            }
            if role == "button":
                self.buttons.append(item)
            else:
                self.links.append(item)
            self._role_control_stack.append((tag, item))
        if tag == "img":
            # Missing alt is a clear source-level review signal. An explicit empty
            # alt may be correct for decorative imagery, so it is not flagged here.
            if "alt" not in values and values.get("role", "").lower() not in {"presentation", "none"}:
                self.images_missing_alt += 1
            if self._active_link is not None and values.get("alt", "").strip():
                self._active_link["has_image_alt"] = True
            if self._active_button is not None and values.get("alt", "").strip():
                self._active_button["has_image_alt"] = True
        if tag == "svg":
            self._inside_svg += 1
            self._active_svg_control = (
                self._active_link or self._active_button
                or (self._role_control_stack[-1][1] if self._role_control_stack else None)
            )
            if self._active_svg_control is not None and values.get("aria-label", "").strip():
                self._active_svg_control["has_svg_title"] = True
            if self._active_svg_control is not None and values.get("aria-labelledby", "").strip():
                self._active_svg_control["svg_labelledby"] = values.get("aria-labelledby", "").strip()
        elif tag == "title" and self._inside_svg and self._active_svg_control is not None:
            self._in_svg_title = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        for index in range(len(self._aria_hidden_stack) - 1, -1, -1):
            if self._aria_hidden_stack[index][0] == tag:
                del self._aria_hidden_stack[index:]
                break
        for index in range(len(self._text_id_stack) - 1, -1, -1):
            if self._text_id_stack[index][0] == tag:
                del self._text_id_stack[index:]
                break
        if tag == "a":
            self._active_link = None
        elif tag == "button":
            self._active_button = None
        for index in range(len(self._role_control_stack) - 1, -1, -1):
            if self._role_control_stack[index][0] == tag:
                self._role_control_stack.pop(index)
                break
        elif tag == "title" and self._in_svg_title:
            self._in_svg_title = False
            if self._active_svg_control is not None and str(self._active_svg_control.get("svg_title", "")).strip():
                self._active_svg_control["has_svg_title"] = True
        elif tag == "svg":
            self._inside_svg = max(0, self._inside_svg - 1)
            if self._inside_svg == 0:
                self._active_svg_control = None
        elif tag == "label" and self._active_label_depth:
            self._active_label_depth -= 1

    def handle_data(self, data):
        for _tag, identifier in self._text_id_stack:
            if identifier:
                self.id_text[identifier] = self.id_text.get(identifier, "") + data
        if self._in_svg_title and self._active_svg_control is not None:
            self._active_svg_control["svg_title"] = str(self._active_svg_control.get("svg_title", "")) + data.strip()
        # SVG <title> names the SVG; do not misclassify its text as visible link/button text.
        if self._active_link is not None and not self._in_svg_title:
            self._active_link["text"] = str(self._active_link["text"]) + data.strip()
        if self._active_button is not None and not self._in_svg_title:
            self._active_button["text"] = str(self._active_button["text"]) + data.strip()
        if not self._in_svg_title:
            for _tag, item in self._role_control_stack:
                item["text"] = str(item["text"]) + data.strip()


def inspect_static_accessibility_signals(html: str, page_url: str) -> list[AuditFinding]:
    """Flag clear source-level review signals without asserting WCAG compliance."""
    parser = _AccessibilityParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:
        # A parser failure is an unavailable assessment, not evidence that the
        # page passed accessibility checks. Preserve the failure in the audit.
        return [AuditFinding(
            category="accessibility",
            title="Accessibility source checks could not be completed",
            status="not_tested",
            severity="info",
            evidence=(
                f"The returned HTML could not be parsed for static accessibility signals "
                f"({type(exc).__name__}) at {page_url}. No accessibility pass or defect is inferred."
            ),
            explanation=(
                "The static accessibility checker could not reliably inspect this response. "
                "This does not establish WCAG conformance or prove that an accessibility defect exists."
            ),
            recommendation=(
                "Retry the audit and inspect the returned HTML for malformed or truncated markup. "
                "Use a browser-based accessibility tree and keyboard review for rendered behavior."
            ),
            verification_steps=[
                "Retry the audit and confirm the page response is complete.",
                "Inspect the rendered accessibility tree and keyboard behavior in a browser.",
            ],
            source_url=page_url,
            test_method="static HTML accessibility source inspection",
            evidence_confidence="limited",
        )]

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
    def has_resolvable_labelledby(item: dict[str, str]) -> bool:
        """Count aria-labelledby only when every referenced ID exists in returned HTML."""
        identifiers = (item.get("aria_labelledby", "") + " " + item.get("svg_labelledby", "")).split()
        return bool(identifiers) and all(
            identifier in parser.ids
            and parser.id_counts.get(identifier, 0) == 1
            and parser.id_text.get(identifier, "").strip()
            for identifier in identifiers
        )

    unlabeled_inputs = [item for item in parser.inputs if not (
        item["aria_label"] or has_resolvable_labelledby(item) or item["title"] or
        item["inside_label"] == "true" or (
            item["id"] and item["id"] in parser.label_for
            and parser.id_counts.get(item["id"], 0) == 1
        )
    )]
    unlabeled_image_submit_inputs = [
        item for item in parser.image_submit_inputs
        if not (item["alt"] or item["aria_label"] or item["aria_labelledby"] or item["title"])
    ]
    unnamed_input_actions = [
        item for item in parser.input_action_controls
        if not (
            item["value"] or item["aria_label"] or has_resolvable_labelledby(item) or item["title"]
        )
    ]
    if unnamed_input_actions:
        types = ", ".join(sorted({item["type"] for item in unnamed_input_actions}))
        findings.append(AuditFinding(
            category="accessibility",
            title="Input action controls may lack accessible names",
            status="manual_review_required",
            severity="medium",
            evidence=(
                f"Found {len(unnamed_input_actions)} input action control(s) of type {types} "
                f"without a non-empty value, aria-label, aria-labelledby, or title in returned HTML for {page_url}."
            ),
            explanation=(
                "Input button, submit, and reset controls use their value or another accessible-name "
                "mechanism to communicate the action. An explicitly empty or missing value may leave "
                "the control without a useful name; browser defaults and runtime changes require rendered review."
            ),
            recommendation=(
                "Provide a concise, meaningful value or accessible name for each input action control, "
                "and verify its computed name in the rendered accessibility tree."
            ),
            verification_steps=[
                "Inspect each flagged input action control in the rendered DOM and accessibility tree.",
                "Test keyboard activation and confirm the announced action matches the control's purpose.",
            ],
            source_url=page_url,
        ))

    if unlabeled_image_submit_inputs:
        findings.append(AuditFinding(
            category="accessibility", title="Image submit controls may lack accessible names",
            status="manual_review_required", severity="medium",
            evidence=(
                f"Found {len(unlabeled_image_submit_inputs)} image submit control(s) without detectable "
                f"alt text, aria-label, aria-labelledby, or title in returned HTML for {page_url}."
            ),
            explanation=(
                "An input with type=image acts as a submit control and needs an accessible name that "
                "communicates its action. This static check cannot determine whether JavaScript adds a "
                "name or whether a detected name is meaningful."
            ),
            recommendation=(
                "Give each image submit control a concise accessible name, usually with meaningful alt text, "
                "and verify the computed name in the rendered accessibility tree."
            ),
            verification_steps=[
                "Inspect each image submit control in the rendered DOM and accessibility tree.",
                "Test keyboard submission and confirm the control's purpose is announced clearly.",
            ],
            source_url=page_url,
        ))

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
        str(item["text"]).strip() or item["aria_label"] or has_resolvable_labelledby(item) or
        item["title"] or item["has_image_alt"] or item["has_svg_title"]
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
        str(item["text"]).strip() or item["aria_label"] or has_resolvable_labelledby(item) or
        item["title"] or item["has_image_alt"] or item["has_svg_title"]
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

    if parser.main_landmarks == 0:
        findings.append(AuditFinding(
            category="accessibility",
            title="Primary page landmark was not detected",
            status="manual_review_required",
            severity="low",
            evidence=f"No native main element or role=main landmark was detected in returned HTML for {page_url}.",
            explanation="A main landmark can help assistive-technology users jump to the page's primary content. Some applications add landmarks after JavaScript runs, so absence in the initial HTML is a review signal rather than proof the rendered page lacks one.",
            recommendation="Inspect the rendered accessibility tree. Where appropriate, identify the page's primary content with one main landmark, without wrapping repeated site-wide navigation or footer content inside it.",
            verification_steps=[
                "Inspect the rendered accessibility tree for a main landmark.",
                "Confirm the landmark contains the page's primary content and is not duplicated by application templates.",
            ],
            source_url=page_url,
        ))
    elif parser.main_landmarks > 1:
        findings.append(AuditFinding(
            category="accessibility",
            title="Multiple primary page landmarks need review",
            status="manual_review_required",
            severity="medium",
            evidence=f"Found {parser.main_landmarks} native main element(s) or role=main landmark(s) in returned HTML for {page_url}.",
            explanation="Multiple main landmarks in the same document can make the primary content boundary unclear. Hidden templates or runtime-rendered content can affect the final accessibility tree, so inspect the rendered page before changing it.",
            recommendation="Review the rendered page and ensure only the intended primary content is exposed as the main landmark at a time. Keep secondary regions in appropriately named navigation, complementary, or contentinfo landmarks.",
            verification_steps=[
                "Inspect each main element and role=main in the rendered DOM and accessibility tree.",
                "Check responsive and application templates for duplicate or hidden primary-content containers.",
            ],
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
    elif not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", parser.html_lang):
        findings.append(AuditFinding(
            category="accessibility", title="Document language tag needs review",
            status="manual_review_required", severity="low",
            evidence=f"The html lang value {parser.html_lang[:40]!r} does not match the basic language-tag pattern checked in returned HTML for {page_url}.",
            explanation="An invalid or nonstandard language tag may prevent assistive technology from selecting the intended pronunciation rules. This conservative pattern catches common syntax issues but is not a complete BCP 47 validator.",
            recommendation="Confirm the primary language and use a valid BCP 47 language tag, such as lang=\"en\" or lang=\"en-GB\", then verify the rendered html element.",
            verification_steps=["Check the page's primary language and the exact html lang value.", "Verify the tag against a BCP 47 language-tag validator when regional or script subtags are used."],
            source_url=page_url,
        ))
    hidden_focusables = list(dict.fromkeys(parser.aria_hidden_focusables + parser.aria_hidden_descendant_focusables))
    if hidden_focusables:
        examples = ", ".join(
            tag + (f"[type={kind}]" if kind else "")
            for tag, kind in hidden_focusables[:8]
        )
        findings.append(AuditFinding(
            category="accessibility",
            title="Focusable controls may be hidden from assistive technology",
            status="manual_review_required",
            severity="medium",
            evidence=(
                f"Found {len(hidden_focusables)} focusable element(s) on or inside aria-hidden=\"true\" content "
                f"in returned HTML for {page_url}: {examples}."
            ),
            explanation=(
                "A keyboard-focusable control hidden from the accessibility tree can leave screen-reader "
                "users focused on an element they cannot perceive. This source check flags controls "
                "on the element itself or within a detected aria-hidden ancestor; JavaScript-driven state "
                "and the final accessibility tree still require review."
            ),
            recommendation=(
                "Do not apply aria-hidden=\"true\" to interactive controls that remain keyboard-focusable. "
                "If a control should be unavailable, manage its interaction and focus state consistently, "
                "then verify the rendered accessibility tree."
            ),
            verification_steps=[
                "Inspect each flagged element's computed accessibility-tree state and keyboard focus behavior.",
                "Check hidden menus, dialogs, responsive navigation, and duplicated desktop/mobile controls.",
            ],
            source_url=page_url,
        ))

    findings.append(AuditFinding(
        category="accessibility",
        title="Manual WCAG 2.2 A/AA review checklist remains required",
        status="manual_review_required",
        severity="info",
        evidence=(
            "Static returned-HTML checks cannot establish WCAG conformance. The following browser/manual "
            f"checks remain unverified for this page ({page_url}): "
            + " | ".join(MANUAL_WCAG_REVIEW_CHECKLIST)
        ),
        explanation=(
            "Automated source inspection detects only a subset of accessibility barriers; it cannot establish WCAG conformance. "
            "Keyboard behavior, rendered contrast, responsive reflow, assistive-technology behavior, media alternatives and task "
            "completion require browser or human review. This record is a checklist, not a claim that these "
            "criteria failed or passed."
        ),
        recommendation=(
            "Complete and record each checklist item in an authorized test environment. Pair automated scans "
            "with keyboard-only and screen-reader review; do not claim full WCAG conformance from this audit alone."
        ),
        verification_steps=list(MANUAL_WCAG_REVIEW_CHECKLIST),
        standard_references=["https://www.w3.org/TR/WCAG22/"],
        source_url=page_url,
    ))
    return findings
