"""PDF rendering for structured audit findings."""
from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
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


def render_audit_pdf(result: AuditCheckResult) -> bytes:
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
        _p(f"Pages successfully inspected: {len(result.pages_checked)}", body_style),
        Spacer(1, 3 * mm),
        HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#AAB7C4")),
        Paragraph("How to read this report", section_style),
        _p("Verified means the reported observation was directly seen in the response inspected; it does not automatically mean the business impact is proven. Manual review required means human/contextual review is needed. Not tested means the check could not be completed and must not be treated as a pass or failure.", body_style),
        _p("Severity is a triage aid, not a revenue-loss estimate. This report does not guarantee rankings, conversions, legal compliance, accessibility conformance, or security.", body_style),
        Paragraph("Summary", section_style),
    ]

    counts: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.status] = counts.get(finding.status, 0) + 1
    summary_rows = [["Status", "Count"]] + [[status.replace("_", " ").title(), str(count)] for status, count in sorted(counts.items())]
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
    story.extend([summary, Spacer(1, 4 * mm)])

    story.append(Paragraph("Findings and recommended actions", section_style))
    if not result.findings:
        story.append(_p("No findings were produced. This is not proof that the website has no issues; review the limitations and check execution status.", body_style))

    for index, finding in enumerate(result.findings, 1):
        blocks = [
            Paragraph(f"{index}. {escape(finding.title)}", finding_style),
            _p(f"Category: {finding.category.replace('_', ' ').title()} | Status: {finding.status.replace('_', ' ').title()} | Severity: {finding.severity.title()}", small_style),
            Paragraph("<b>What was observed</b>", body_style),
            _p(finding.evidence, body_style),
            Paragraph("<b>What this means</b>", body_style),
            _p(finding.explanation, body_style),
            Paragraph("<b>Recommended solution</b>", body_style),
            _p(finding.recommendation, body_style),
            Paragraph("<b>How to verify</b>", body_style),
        ]
        for step in finding.verification_steps:
            blocks.append(_p("• " + step, body_style))
        if finding.source_url:
            blocks.extend([Paragraph("<b>Evidence URL</b>", body_style), _link(finding.source_url, small_style)])
        blocks.append(Spacer(1, 3 * mm))
        story.append(KeepTogether(blocks))

    story.append(Paragraph("Coverage and limitations", section_style))
    for limitation in result.limitations:
        story.append(_p("• " + limitation, body_style))
    story.extend([
        Spacer(1, 3 * mm),
        Paragraph("Optional implementation support", section_style),
        _p("If you would prefer a team to implement and retest the recommended changes, JunctionTools can discuss relevant remediation services. This offer is separate from the findings; no fix, ranking improvement, revenue uplift, or compliance outcome is guaranteed.", body_style),
        _p("Method note: checks are limited to the URLs and responses listed in this report. Results can differ by time, location, cache, user agent, rendering mode, and third-party data source. Independently repeat each verification step before making business decisions.", small_style),
    ])

    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#D5DCE5"))
        canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(18 * mm, 8 * mm, "Ecommerce Audit Agent — public checks, not a compliance certificate")
        canvas.drawRightString(A4[0] - 18 * mm, 8 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
