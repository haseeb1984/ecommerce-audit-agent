"""PDF rendering for structured audit findings."""
from __future__ import annotations

from io import BytesIO
import base64
import re
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Flowable,
    KeepTogether,
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from audit_checks import AuditCheckResult, AuditFinding


def _p(value: object, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(value or "Not available")), style)


def _link(url: str, style: ParagraphStyle) -> Paragraph:
    safe_url = escape(url, {'"': "&quot;"})
    label = escape(url)
    return Paragraph(f'<link href="{safe_url}" color="#1759a8">{label}</link>', style)


SECURITY_HEADER_LABELS = {
    "HSTS header",
    "Content Security Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "X-Frame-Options",
    "Permissions-Policy",
}


def calculate_security_assessment(findings: list[AuditFinding], limitations: list[str]) -> dict[str, object]:
    """Score only explicit, observable baseline controls; never label a site hack-proof."""
    passed = 0
    issues = 0
    unverified = 0
    header_findings = {
        finding.title: finding
        for finding in findings
        if finding.category == "security_headers" and finding.title in SECURITY_HEADER_LABELS
    }
    for label in SECURITY_HEADER_LABELS:
        finding = header_findings.get(label)
        if finding is None:
            unverified += 1
        elif finding.status == "verified" and "Response did not include" not in finding.evidence:
            passed += 1
        else:
            issues += 1

    probe_limit = next(
        (item for item in limitations if "Passive exposure probes checked only" in item),
        None,
    )
    exposure_findings = [
        finding for finding in findings if finding.category == "security_exposure"
    ]
    if probe_limit:
        import re
        match = re.search(r"checked only (\d+) common paths", probe_limit)
        checked_paths = int(match.group(1)) if match else 0
        issues += min(len(exposure_findings), checked_paths)
        unverified_match = next(
            (re.search(r"(\d+) of \d+ exposure probes could not be verified", item)
             for item in limitations
             if "exposure probes could not be verified" in item),
            None,
        )
        unverified_probes = int(unverified_match.group(1)) if unverified_match else 0
        inconclusive_match = next(
            (re.search(r"(\d+) of \d+ exposure probes returned successful responses without a recognizable sensitive-content signature", item)
             for item in limitations
             if "returned successful responses without a recognizable sensitive-content signature" in item),
            None,
        )
        inconclusive_probes = int(inconclusive_match.group(1)) if inconclusive_match else 0
        unverified_probes = min(
            unverified_probes + inconclusive_probes,
            max(0, checked_paths - len(exposure_findings)),
        )
        unverified += unverified_probes
        passed += max(0, checked_paths - len(exposure_findings) - unverified_probes)
    else:
        checked_paths = 0
        unverified += 14

    transport_titles = {
        "TLS certificate validity and expiry",
        "TLS certificate validation failed",
        "HTTP redirects to HTTPS",
        "HTTP does not redirect to HTTPS",
        "HTTP resources referenced by HTTPS page",
        "No static HTTP mixed-content references detected",
    }
    transport_findings = [
        finding for finding in findings
        if finding.category == "security_transport" and finding.title in transport_titles
    ]
    expected_transport_checks = 3
    seen_transport_titles = set()
    for finding in transport_findings:
        if finding.title in seen_transport_titles:
            continue
        seen_transport_titles.add(finding.title)
        if finding.status in {"manual_review_required", "not_tested", "insufficient_data"}:
            # A non-verified observation must never improve the score merely
            # because its severity field happens to be "info".
            unverified += 1
        elif finding.status == "verified" and finding.severity == "info":
            passed += 1
        else:
            issues += 1
    unverified += max(0, expected_transport_checks - len(seen_transport_titles))

    assessed = passed + issues + unverified
    # Unknown controls never count as passes; this is a conservative coverage score.
    # Do not display 0% when every check is unverified: that would confuse
    # "no evidence collected" with "all assessed controls failed".
    score = round(100 * passed / assessed) if (passed + issues) else None
    return {
        "score": score,
        "passed": passed,
        "issues": issues,
        "unverified": unverified,
        "assessed": assessed,
        "checked_exposure_paths": checked_paths,
    }


def _consolidate_findings(findings: list[AuditFinding]) -> list[dict[str, object]]:
    """Merge repeated instances of the same actionable issue across inspected pages."""
    groups: dict[tuple[str, str, str, str, str, str, str, str], dict[str, object]] = {}
    for finding in findings:
        key = (
            finding.category, finding.title, finding.status, finding.severity,
            finding.explanation, finding.recommendation,
            finding.potential_benefit or "", finding.risk_if_unresolved or "",
        )
        if key not in groups:
            groups[key] = {
                "category": finding.category,
                "title": finding.title,
                "status": finding.status,
                "severity": finding.severity,
                "explanation": finding.explanation,
                "recommendation": finding.recommendation,
                "potential_benefit": finding.potential_benefit,
                "risk_if_unresolved": finding.risk_if_unresolved,
                "evidence": [],
                "verification_steps": [],
                "source_urls": [],
                "instances": 0,
            }
        item = groups[key]
        item["instances"] = int(item["instances"]) + 1
        evidence = str(finding.evidence or "").strip()
        if evidence and evidence not in item["evidence"]:
            item["evidence"].append(evidence)
        for step in finding.verification_steps:
            if step not in item["verification_steps"]:
                item["verification_steps"].append(step)
        if finding.source_url and finding.source_url not in item["source_urls"]:
            item["source_urls"].append(finding.source_url)
    return list(groups.values())



def _prioritized_actions(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    """Return evidence-backed high/critical actions in a stable, conservative order."""
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    eligible = [
        item for item in findings
        if str(item.get("severity", "")).lower() in {"critical", "high", "medium"}
        and str(item.get("status", "")) in {"verified", "manual_review_required"}
    ]
    return sorted(
        eligible,
        key=lambda item: (
            rank.get(str(item.get("severity", "")).lower(), 9),
            str(item.get("title", "")).casefold(),
        ),
    )


class PhaseVisual(Flowable):
    """Small vector illustration for the report's audit-phase overview.

    These are explanatory graphics, not screenshots or evidence of a finding.
    """
    def __init__(self, title: str, subtitle: str, kind: str):
        super().__init__()
        self.title = title
        self.subtitle = subtitle
        self.kind = kind
        self.width = 78 * mm
        self.height = 29 * mm

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(colors.HexColor("#F2F6FB"))
        c.setStrokeColor(colors.HexColor("#D5DFEA"))
        c.roundRect(0, 0, self.width, self.height, 5, fill=1, stroke=1)
        accent = colors.HexColor("#245B8F")
        c.setFillColor(accent)
        c.roundRect(5 * mm, 7 * mm, 16 * mm, 16 * mm, 3, fill=1, stroke=0)
        c.setStrokeColor(colors.white)
        c.setFillColor(colors.white)
        if self.kind == "performance":
            c.line(8 * mm, 11 * mm, 10 * mm, 15 * mm)
            c.line(10 * mm, 15 * mm, 13 * mm, 13 * mm)
            c.line(13 * mm, 13 * mm, 17 * mm, 19 * mm)
            c.circle(17 * mm, 19 * mm, 1, fill=1, stroke=0)
        elif self.kind == "accessibility":
            c.circle(13 * mm, 18 * mm, 2, fill=0, stroke=1)
            c.line(13 * mm, 16 * mm, 13 * mm, 11 * mm)
            c.line(9 * mm, 15 * mm, 17 * mm, 15 * mm)
            c.line(13 * mm, 11 * mm, 10 * mm, 8 * mm)
            c.line(13 * mm, 11 * mm, 16 * mm, 8 * mm)
        elif self.kind == "security":
            p = c.beginPath()
            p.moveTo(13 * mm, 20 * mm)
            p.lineTo(18 * mm, 18 * mm)
            p.lineTo(17 * mm, 12 * mm)
            p.lineTo(13 * mm, 9 * mm)
            p.lineTo(9 * mm, 12 * mm)
            p.lineTo(8 * mm, 18 * mm)
            p.close()
            c.drawPath(p, fill=0, stroke=1)
            c.line(10 * mm, 14 * mm, 12 * mm, 12 * mm)
            c.line(12 * mm, 12 * mm, 16 * mm, 16 * mm)
        else:
            c.rect(9 * mm, 10 * mm, 8 * mm, 9 * mm, fill=0, stroke=1)
            c.line(11 * mm, 16 * mm, 15 * mm, 16 * mm)
            c.line(11 * mm, 13 * mm, 15 * mm, 13 * mm)
        c.setFillColor(colors.HexColor("#17365D"))
        c.setFont("Helvetica-Bold", 8.5)
        c.drawString(25 * mm, 17 * mm, self.title[:30])
        c.setFillColor(colors.HexColor("#46576A"))
        c.setFont("Helvetica", 7)
        # Keep this label deliberately descriptive, not a claim that the phase is complete.
        c.drawString(25 * mm, 11 * mm, self.subtitle[:42])
        c.restoreState()


def render_audit_pdf(result: AuditCheckResult, screenshot_data_uri: str | None = None) -> bytes:
    """Render an audit result into a readable, text-selectable PDF."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Ecommerce website audit — {result.target_url}",
        author="Ecommerce Audit Agent",
        subject="Evidence-first public website audit",
    )
    base = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "AuditTitle", parent=base["Title"], fontName="Helvetica-Bold",
        fontSize=20, leading=25, alignment=TA_CENTER, spaceAfter=10,
    )
    section_style = ParagraphStyle(
        "AuditSection", parent=base["Heading1"], fontSize=14, leading=18,
        textColor=colors.HexColor("#17365D"), spaceBefore=10, spaceAfter=6,
        keepWithNext=True,
    )
    finding_style = ParagraphStyle(
        "FindingTitle", parent=base["Heading2"], fontSize=11, leading=14,
        spaceBefore=8, spaceAfter=4, keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "AuditBody", parent=base["BodyText"], fontSize=9, leading=12,
        spaceAfter=4, wordWrap="LTR",
    )
    small_style = ParagraphStyle(
        "AuditSmall", parent=body_style, fontSize=8, leading=10,
        textColor=colors.HexColor("#555555"),
    )

    story = [
        Spacer(1, 12 * mm),
        Paragraph("Ecommerce Website Audit", title_style),
        Paragraph("Evidence-first technical checks", base["Heading2"]),
        Spacer(1, 4 * mm),
        _p("Website: " + result.target_url, body_style),
        _p("Report generated (UTC): " + result.checked_at_utc, body_style),
        _p(f"Pages successfully inspected: {len(set(result.pages_checked))}", body_style),
        _p("Assessment scope: publicly accessible pages and responses only; the sample and exclusions are listed below.", body_style),
        Spacer(1, 3 * mm),
        HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#AAB7C4")),
        Paragraph("How to read this report", section_style),
        _p("Verified means the reported observation was directly seen in the response inspected; it does not automatically mean the business impact is proven. Manual review required means human/contextual review is needed. Not tested means the check could not be completed and must not be treated as a pass or failure.", body_style),
        _p("Severity is a triage aid, not a revenue-loss estimate. This report does not guarantee rankings, conversions, legal compliance, accessibility conformance, or security.", body_style),
        Paragraph("Summary", section_style),
        _p("This report checks a bounded sample of publicly accessible pages. Each visual below is an explanatory illustration of an audit area, not a screenshot of your website.", small_style),
    ]

    phase_cards = [
        [PhaseVisual("Performance & experience", "Speed signals and page delivery", "performance"),
         PhaseVisual("Accessibility & usability", "Labels, structure and mobile signals", "accessibility")],
        [PhaseVisual("Security & trust signals", "Observable public-facing controls", "security"),
         PhaseVisual("SEO & page structure", "Metadata and sampled page signals", "seo")],
    ]
    phase_table = Table(phase_cards, colWidths=[83 * mm, 83 * mm], hAlign="LEFT")
    phase_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 2 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2 * mm),
    ]))
    story.extend([phase_table, Spacer(1, 3 * mm)])

    # Only embed a real image supplied by the PageSpeed response. Validate it again
    # at the PDF boundary; invalid/unsupported data is omitted, never fabricated.
    screenshot_flowable = None
    if isinstance(screenshot_data_uri, str) and len(screenshot_data_uri) <= 1_400_000:
        match = re.fullmatch(
            r"data:(image/png|image/jpeg);base64,([A-Za-z0-9+/]*={0,2})",
            screenshot_data_uri,
        )
        if match:
            try:
                image_bytes = base64.b64decode(match.group(2), validate=True)
                valid_png = match.group(1) == "image/png" and image_bytes.startswith(bytes.fromhex("89504e470d0a1a0a"))
                valid_jpeg = match.group(1) == "image/jpeg" and image_bytes.startswith(bytes.fromhex("ffd8ff"))
                if image_bytes and len(image_bytes) <= 1_000_000 and (valid_png or valid_jpeg):
                    candidate = Image(BytesIO(image_bytes), width=150 * mm, height=84 * mm, kind="proportional")
                    candidate.hAlign = "CENTER"
                    screenshot_flowable = candidate
            except (ValueError, TypeError, OSError):
                screenshot_flowable = None

    story.append(Paragraph("Actual website screenshot", section_style))
    if screenshot_flowable is not None:
        story.extend([
            _p(
                "This is a real browser screenshot captured from the target website during this audit run, "
                "not an illustrative graphic. It shows the captured viewport and may not represent every page or device.",
                small_style,
            ),
            screenshot_flowable,
            Spacer(1, 2 * mm),
        ])
    else:
        story.append(_p(
            "A real browser screenshot could not be captured for this run. No website screenshot was fabricated. "
            "The phase illustrations below are explanatory graphics only.",
            body_style,
        ))


    security = calculate_security_assessment(result.findings, result.limitations)
    story.extend([
        Paragraph("Security assessment score", section_style),
        _p(
            (
                f"Observed baseline controls score: {security['score']}% "
                if security["score"] is not None else
                "Observed baseline controls score: Not enough verified checks to calculate. "
            ) +
            "This is NOT a percentage probability of being hacked and does NOT mean the website is hack-proof. "
            f"Controls passing: {security['passed']}; controls with observed issues: {security['issues']}; "
            f"controls not verified: {security['unverified']}. "
            f"Common exposure paths checked: {security['checked_exposure_paths']}. "
            "The score covers only the baseline response headers and the small set of public exposure paths listed in this report; "
            "it excludes authenticated flows, application logic, dependencies, infrastructure, and penetration testing.",
            body_style,
        ),
    ])

    consolidated_findings = _consolidate_findings(result.findings)
    counts: dict[str, int] = {}
    for finding in consolidated_findings:
        status = str(finding["status"])
        counts[status] = counts.get(status, 0) + 1
    high_priority_count = sum(
        1 for finding in consolidated_findings
        if str(finding["severity"]).lower() in {"critical", "high"}
    )
    overview_cells = [
        _p("CONSOLIDATED ISSUES", small_style),
        _p("PAGES INSPECTED", small_style),
        _p("HIGH / CRITICAL", small_style),
    ]
    overview_values = [
        _p(str(len(consolidated_findings)), title_style),
        _p(str(len(set(result.pages_checked))), title_style),
        _p(str(high_priority_count), title_style),
    ]
    overview = Table(
        [overview_cells, overview_values],
        colWidths=[51 * mm, 51 * mm, 51 * mm],
        hAlign="LEFT",
    )
    overview.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F2F5F9")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#C8D1DC")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DCE5")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    summary_rows = [["Status", "Consolidated issues"]] + [[status.replace("_", " ").title(), str(count)] for status, count in sorted(counts.items())]
    summary = Table(summary_rows, colWidths=[100 * mm, 35 * mm], repeatRows=1, hAlign="LEFT")
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C8D1DC")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    # Keep the KPI labels and their values on the same page; otherwise ReportLab can
    # split the two table rows across a page break and leave orphaned numbers.
    story.append(KeepTogether([overview, Spacer(1, 4 * mm), summary, Spacer(1, 4 * mm)]))

    story.append(Paragraph("Recommended action plan", section_style))
    story.append(_p(
        "This short list orders observed high-, critical-, and medium-severity items for triage. "
        "Severity is a technical review aid, not a measured estimate of lost sales, ranking changes, or security impact. "
        "Items requiring manual review remain unconfirmed until a person validates them.",
        body_style,
    ))
    priority_actions = _prioritized_actions(consolidated_findings)
    if priority_actions:
        for action in priority_actions[:8]:
            story.append(Paragraph(
                f"<b>{escape(str(action['severity']).title())} — {escape(str(action['title']))}</b>",
                finding_style,
            ))
            story.append(_p(
                f"Status: {str(action['status']).replace('_', ' ').title()}",
                small_style,
            ))
            story.append(_p(str(action["recommendation"]), body_style))
        if len(priority_actions) > 8:
            story.append(_p(
                f"{len(priority_actions) - 8} additional medium/high/critical action(s) are detailed in the findings section.",
                small_style,
            ))
    else:
        story.append(_p(
            "No verified or manual-review high/critical/medium actions were recorded in this run. "
            "This does not prove that no material issues exist; review coverage limitations and unverified checks.",
            body_style,
        ))

    story.append(Paragraph("Findings and recommended actions", section_style))
    if not consolidated_findings:
        story.append(_p("No findings were produced. This is not proof that the website has no issues; review the limitations and check execution status.", body_style))

    # Build one shared reference index so a page URL is not printed repeatedly under every finding.
    evidence_urls: list[str] = []
    for finding in consolidated_findings:
        for url in finding["source_urls"]:
            if url not in evidence_urls:
                evidence_urls.append(url)
    evidence_ids = {url: f"E{index}" for index, url in enumerate(evidence_urls, 1)}

    for index, finding in enumerate(consolidated_findings, 1):
        blocks = [
            Paragraph(f"{index}. {escape(str(finding['title']))}", finding_style),
            _p(
                f"Category: {str(finding['category']).replace('_', ' ').title()} | "
                f"Status: {str(finding['status']).replace('_', ' ').title()} | "
                f"Severity: {str(finding['severity']).title()}",
                small_style,
            ),
        ]
        instances = int(finding["instances"])
        urls = list(finding["source_urls"])
        if instances > 1:
            blocks.append(_p(f"Occurrences consolidated: {instances}", small_style))
        if urls:
            refs = ", ".join(evidence_ids[url] for url in urls)
            blocks.append(_p(f"Evidence references: {refs}", small_style))
            blocks.append(_p(f"Affected pages with recorded evidence: {len(urls)}", small_style))
        blocks.extend([
            Paragraph("<b>What was observed</b>", body_style),
            _p(" | ".join(finding["evidence"]) or "No specific evidence text was recorded.", body_style),
            Paragraph("<b>What this means</b>", body_style),
            _p(finding["explanation"], body_style),
            Paragraph("<b>Recommended solution</b>", body_style),
            _p(finding["recommendation"], body_style),
        ])
        # Optional business context is only shown when supplied by an evidence-backed check.
        if finding.get("potential_benefit"):
            blocks.extend([
                Paragraph("<b>Potential benefit if addressed</b>", body_style),
                _p(finding["potential_benefit"], body_style),
            ])
        if finding.get("risk_if_unresolved"):
            blocks.extend([
                Paragraph("<b>Risk if left unresolved</b>", body_style),
                _p(finding["risk_if_unresolved"], body_style),
            ])
        blocks.extend([
            Paragraph("<b>How to verify</b>", body_style),
        ])
        for step in finding["verification_steps"]:
            blocks.append(_p("• " + step, body_style))
        blocks.append(Spacer(1, 3 * mm))
        # Let ReportLab split long findings across pages. Keeping every paragraph
        # in one indivisible group can raise LayoutError for a verbose finding.
        story.extend(blocks)

    if evidence_urls:
        story.append(Paragraph("Evidence & References", section_style))
        story.append(_p(
            "Each reference ID below is used by the relevant consolidated finding. URLs are listed once here to keep the report concise.",
            body_style,
        ))
        for url, reference_id in evidence_ids.items():
            story.append(_p(f"{reference_id}: {url}", small_style))

    story.append(Paragraph("Sampled pages in scope", section_style))
    if result.pages_checked:
        story.append(_p(
            "The following URLs were successfully inspected during this run. This list is the observed sample, not a claim that every site URL was crawled.",
            body_style,
        ))
        for page_url in dict.fromkeys(result.pages_checked):
            story.append(_p("• " + page_url, small_style))
    else:
        story.append(_p(
            "No page was recorded as successfully inspected. Findings and coverage should be interpreted accordingly.",
            body_style,
        ))

    story.append(Paragraph("Coverage and limitations", section_style))
    if result.limitations:
        for limitation in dict.fromkeys(result.limitations):
            story.append(_p("• " + limitation, body_style))
    else:
        story.append(_p(
            "No explicit limitation strings were supplied by the audit engine. This absence does not mean the checks were comprehensive; use the sampled-page list and findings to understand scope.",
            body_style,
        ))

    story.extend([
        Spacer(1, 3 * mm),
        Paragraph("Methodology and independent verification", section_style),
        _p(
            "The audit evaluates bounded public HTTP responses and source-level signals. It does not automatically prove how a page behaves after JavaScript execution, after login, in every browser or region, or in Google Search. Recheck each finding using the listed verification steps and an independent tool appropriate to the issue; record the date, tested URL, environment and outcome. For example, performance observations can be compared with Google PageSpeed Insights, structured data with Google's Rich Results Test where applicable, and accessibility signals with a manual keyboard/screen-reader review plus an accessibility checker. Tool output can differ by run and does not replace expert review.",
            body_style,
        ),
        Paragraph("Plain-language glossary", section_style),
        _p(
            "Verified: the stated observation was seen in the sampled response. Manual review required: context or a person is needed before confirming a defect. Not tested / insufficient data: no conclusion can be drawn. Evidence reference: a URL recorded for an observation. Source-level check: inspection of returned HTML or headers, not a full browser interaction. Severity: a triage label, not a measured financial impact.",
            body_style,
        ),
        Spacer(1, 3 * mm),
        Paragraph("Optional implementation support", section_style),
        _p("If you would prefer a team to implement and retest the recommended changes, JunctionTools can discuss relevant remediation services. This offer is separate from the findings; no fix, ranking improvement, revenue uplift, or compliance outcome is guaranteed.", body_style),
        _p("Method note: checks are limited to the URLs and responses listed in this report. Results can differ by time, location, cache, user agent, rendering mode, and third-party data source. Independently repeat each verification step before making business decisions.", small_style),
        Spacer(1, 2 * mm),
        Paragraph("Disclaimer", section_style),
        _p("This report presents observations from a bounded set of public website checks at the time shown. It is not a complete security assessment, penetration test, WCAG conformance audit, legal opinion, guarantee of search rankings, or forecast of conversions or revenue. Checks not performed or not verified must not be interpreted as passing. Confirm findings in the relevant production context before acting on them.", body_style),
    ])

    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#D5DCE5"))
        canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(18 * mm, 8 * mm, "Ecommerce Audit Agent — client audit report")
        canvas.drawRightString(A4[0] - 18 * mm, 8 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
