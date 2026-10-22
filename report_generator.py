"""PDF rendering for structured audit findings."""
from __future__ import annotations

from io import BytesIO
import base64
import re
from xml.sax.saxutils import escape
from urllib.parse import urlsplit, urlunsplit

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Flowable,
    KeepTogether,
    PageBreak,
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
    """Render only validated public HTTP(S) links and redact URL secrets in the PDF."""
    try:
        parts = urlsplit(str(url or "").strip())
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port  # Access validates malformed and out-of-range ports.
        if (
            scheme not in {"http", "https"}
            or not host
        ):
            return _p("Link omitted (unsupported or unsafe URL)", style)
        display_host = f"[{host.lower()}]" if ":" in host else host.lower()
        default_port = 443 if scheme == "https" else 80
        if port is not None and port != default_port:
            display_host = f"{display_host}:{port}"
        clean_url = urlunsplit((scheme, display_host, parts.path or "/", "", ""))
        # Query strings and fragments can contain session IDs, email addresses,
        # tracking values, or reset tokens. Keep evidence links useful without
        # embedding those values in a downloadable customer report.
        safe_href = escape(clean_url, {'"': "&quot;"})
        label = escape(clean_url)
        return Paragraph(f'<link href="{safe_href}" color="#1759a8">{label}</link>', style)
    except (ValueError, UnicodeError):
        return _p("Link omitted (malformed URL)", style)


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



def _business_impact_context(finding: dict[str, object]) -> tuple[str, str]:
    """Supply cautious category-level impact context when a check has no custom wording.

    These statements describe plausible outcomes, not measured revenue or guaranteed gains.
    Evidence-backed finding-specific text always takes precedence.
    """
    category = str(finding.get("category", "")).lower()
    status = str(finding.get("status", "")).lower()
    severity = str(finding.get("severity", "")).lower()
    if category in {"security_dependency", "dependency_advisory"}:
        benefit = "Confirming the deployed package and addressing an applicable advisory can reduce exposure to known vulnerable versions; a detected version string alone does not prove exploitability."
        risk = "If the affected version is actually served and remains exposed, a known weakness may remain available to attackers. This scan does not establish that exploitation or compromise occurred."
    elif category in {"security", "security_headers", "security_exposure", "security_transport", "security_cookies", "security_api_documentation", "security_baseline"}:
        benefit = "Addressing a confirmed security weakness can reduce the specific exposure described; it cannot guarantee that the website is secure or prevent every attack."
        risk = "If the signal is confirmed in context and left unresolved, the website may remain exposed to the weakness described. This audit does not establish that a compromise has occurred."
    elif category in {"accessibility", "aria", "aria_alt_text"}:
        benefit = "Addressing the observed accessibility signal can make the affected control or content easier to identify and use; a complete outcome requires contextual and assistive-technology testing."
        risk = "If the issue is confirmed and left unresolved, some visitors may have difficulty understanding, navigating, or operating the affected content."
    elif category in {"trust", "trust_inspector"}:
        benefit = "Making accurate payment, returns, review, and support information easy to verify can help shoppers understand purchase conditions; detected cues do not verify authenticity or legal adequacy."
        risk = "If relevant information is difficult to find or conflicts with actual service, shoppers may hesitate or need extra support. This scan does not prove a badge or review is invalid."
    elif category in {"ecommerce", "ecommerce_category"}:
        benefit = "Correct, consistent product and category signals can help shoppers understand the offer and help crawlers interpret important catalog pages."
        risk = "If product details, availability, canonical targets, or category navigation are inconsistent, shoppers and crawlers may encounter confusing or duplicate versions of catalog content."
    elif category in {"broken_internal_links"}:
        benefit = "Repairing a confirmed broken internal destination can help visitors reach the intended page and preserve useful navigation paths."
        risk = "If the destination is genuinely broken and remains so, visitors may hit an error or fail to reach an important product, policy, or support page."
    elif category in {"content_quality", "duplicate_content"}:
        benefit = "Reviewing overlapping or thin content can help make each page more useful and distinguishable; content quality still needs human context."
        risk = "If substantial duplication or missing information is confirmed, visitors may have trouble finding the most useful page and search systems may have less clear page signals."
    elif category in {"international_seo"}:
        benefit = "Correct language and regional annotations can help search engines associate localized pages with their intended audiences."
        risk = "If localization annotations are inconsistent, search systems may have difficulty interpreting the intended language or regional version."
    elif category in {"seo", "technical_seo", "structured_data", "indexing", "crawlability", "indexability", "robots_txt", "sitemap_xml", "llms_txt"}:
        benefit = "Addressing the observed discovery or technical signal can help crawlers interpret or discover the affected content; ranking or indexing improvements are not guaranteed."
        risk = "If the issue is confirmed and left unresolved, crawlers may have difficulty discovering, interpreting, or presenting the affected content as intended."
    elif category in {"conversion_paid_traffic", "pixel_analytics", "conversion", "paid_traffic"}:
        benefit = "Clarifying the observed journey or validating tag behavior may reduce avoidable user uncertainty; conversion rate, CPC, revenue, and attribution impact were not measured."
        risk = "If the signal reflects a real journey or tracking problem and remains unresolved, visitors may face friction or campaign reporting may remain unreliable. Lost sales and ad spend were not quantified."
    elif category in {"performance", "static_performance", "mobile_ux"}:
        benefit = "Addressing the observed usability or performance signal can reduce friction on affected devices; actual user experience should be confirmed with browser and field measurements."
        risk = "If confirmed and left unresolved, the affected experience may remain slower or harder to use for some visitors. This static signal does not quantify business loss."
    else:
        qualifier = "This item requires human review." if status == "manual_review_required" else "The impact has not been measured."
        benefit = f"Validating this observation can help determine whether a targeted change is worthwhile. {qualifier}"
        risk = f"If the observation reflects a real issue and remains unresolved, its specific effect may persist. {qualifier}"
    if severity == "info" or status in {"not_tested", "insufficient_data"}:
        risk = "No adverse outcome is established by this result. Verify the observation in context before deciding whether action is needed."
    return (
        str(finding.get("potential_benefit") or benefit),
        str(finding.get("risk_if_unresolved") or risk),
    )


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


class PremiumCoverHero(Flowable):
    """Premium editorial cover panel with evidence-based audit metrics."""
    def __init__(self, target_url: str, generated_at: str, pages: int, findings: int, priority: int):
        super().__init__()
        self.target_url = target_url
        self.generated_at = generated_at
        self.pages = pages
        self.findings = findings
        self.priority = priority
        self.width = 174 * mm
        self.height = 65 * mm

    def draw(self):
        c = self.canv
        c.saveState()
        navy = colors.HexColor("#10243A")
        blue = colors.HexColor("#1C4164")
        teal = colors.HexColor("#49D3C4")
        muted = colors.HexColor("#D5E2EF")
        c.setFillColor(navy)
        c.roundRect(0, 0, self.width, self.height, 5 * mm, fill=1, stroke=0)
        c.setFillColor(teal)
        c.roundRect(0, 0, 3 * mm, self.height, 1.5 * mm, fill=1, stroke=0)
        c.setFillColor(teal)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(9 * mm, self.height - 9 * mm, "ECOMMERCE AUDIT AGENT  /  CLIENT REPORT")
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 22)
        c.drawString(9 * mm, self.height - 21 * mm, "Ecommerce website")
        c.drawString(9 * mm, self.height - 29 * mm, "audit")
        c.setFillColor(muted)
        c.setFont("Helvetica", 8)
        c.drawString(9 * mm, self.height - 36 * mm, "Evidence-led findings • prioritized actions • verification guidance")
        try:
            parts = urlsplit(self.target_url)
            host = (parts.hostname or self.target_url).lower()
            target = host + (parts.path.rstrip("/") if parts.path and parts.path != "/" else "")
        except (ValueError, UnicodeError):
            target = self.target_url
        if len(target) > 62:
            target = target[:59] + "..."
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(9 * mm, self.height - 44 * mm, target)
        c.setFillColor(muted)
        c.setFont("Helvetica", 7)
        c.drawString(9 * mm, self.height - 49 * mm, "GENERATED (UTC)  " + str(self.generated_at)[:25])
        metrics = [
            ("PAGES INSPECTED", str(self.pages)),
            ("RECORDED FINDINGS", str(self.findings)),
            ("HIGH / CRITICAL", str(self.priority)),
        ]
        gap = 2 * mm
        left = 9 * mm
        usable = self.width - 18 * mm
        card_w = (usable - gap * 2) / 3
        y = 3.5 * mm
        for i, (label, value) in enumerate(metrics):
            x = left + i * (card_w + gap)
            c.setFillColor(blue)
            c.roundRect(x, y, card_w, 10 * mm, 2 * mm, fill=1, stroke=0)
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 12)
            c.drawString(x + 3 * mm, y + 4.8 * mm, value)
            c.setFillColor(muted)
            c.setFont("Helvetica-Bold", 5.7)
            c.drawRightString(x + card_w - 2.5 * mm, y + 5.2 * mm, label)
        c.restoreState()


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
        elif self.kind == "conversion":
            # A simple basket/cart glyph; this is an area label, not a finding.
            c.line(8 * mm, 18 * mm, 10 * mm, 18 * mm)
            c.line(10 * mm, 18 * mm, 12 * mm, 11 * mm)
            c.line(12 * mm, 11 * mm, 18 * mm, 11 * mm)
            c.line(18 * mm, 11 * mm, 20 * mm, 16 * mm)
            c.line(11 * mm, 16 * mm, 19 * mm, 16 * mm)
            c.circle(13 * mm, 8.5 * mm, 1.2 * mm, fill=0, stroke=1)
            c.circle(18 * mm, 8.5 * mm, 1.2 * mm, fill=0, stroke=1)
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



class FindingInsightInfographic(Flowable):
    """Compact visual summary that translates one recorded finding into an at-a-glance signal."""
    def __init__(self, finding: dict[str, object]):
        super().__init__()
        self.width = 174 * mm
        self.height = 23 * mm
        self.finding = finding
        self.status = str(finding.get("status", "")).lower()
        self.severity = str(finding.get("severity", "info")).lower()
        self.category = str(finding.get("category", "")).lower()
        self.positive = self.severity == "info" and self.status == "verified"
        self.review = self.status in {"manual_review_required", "not_tested", "insufficient_data"}
        self.label = "POSITIVE SIGNAL — QUALITY NOT FULLY SCORED" if self.positive else ("NEEDS HUMAN REVIEW" if self.review else f"{self.severity.upper()} PRIORITY")
        self.color = "#23734D" if self.positive else ("#9A6700" if self.review else {"critical":"#8E2430","high":"#D3543C","medium":"#B87912","low":"#2E83A6"}.get(self.severity,"#6D7C91"))
        self.action = "Keep the signal; validate quality separately." if self.positive else ("Collect the missing evidence before concluding." if self.review else "Review evidence and prioritize an appropriate corrective action.")

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(colors.HexColor("#F7F9FC"))
        c.setStrokeColor(colors.HexColor("#D8E1EC"))
        c.roundRect(0, 0, self.width, self.height, 5, fill=1, stroke=1)
        c.setFillColor(colors.HexColor(self.color))
        c.roundRect(0, 0, 4 * mm, self.height, 2, fill=1, stroke=0)
        c.setFillColor(colors.HexColor(self.color))
        c.circle(12 * mm, 15 * mm, 3 * mm, fill=1, stroke=0)
        c.setStrokeColor(colors.white)
        c.setLineWidth(1.2)
        if self.positive:
            c.line(10.5 * mm, 15 * mm, 11.7 * mm, 13.8 * mm)
            c.line(11.7 * mm, 13.8 * mm, 14 * mm, 16.3 * mm)
        elif self.review:
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 8)
            c.drawCentredString(12 * mm, 12.2 * mm, "?")
        else:
            c.line(12 * mm, 16.5 * mm, 12 * mm, 13.5 * mm)
            c.circle(12 * mm, 11.7 * mm, .5 * mm, fill=1, stroke=0)
        c.setFillColor(colors.HexColor(self.color))
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(20 * mm, 16 * mm, self.label[:72])
        c.setFillColor(colors.HexColor("#26384B"))
        c.setFont("Helvetica", 7)
        c.drawString(20 * mm, 9 * mm, self.action[:110])
        c.setFillColor(colors.HexColor("#536579"))
        c.setFont("Helvetica", 6.5)
        c.drawRightString(self.width - 4 * mm, 3.5 * mm, "Evidence-led signal • not a fabricated score")
        c.restoreState()


class FindingMixInfographic(Flowable):
    """Evidence-derived severity infographic; counts are not severity scores."""
    def __init__(self, findings: list[dict[str, object]]):
        super().__init__()
        self.width = 174 * mm
        self.height = 38 * mm
        self.counts = {
            level: sum(1 for item in findings if str(item.get("severity", "")).lower() == level)
            for level in ("critical", "high", "medium", "low", "info")
        }
        self.total = sum(self.counts.values())

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(colors.HexColor("#F4F7FB"))
        c.setStrokeColor(colors.HexColor("#D8E1EC"))
        c.roundRect(0, 0, self.width, self.height, 7, fill=1, stroke=1)
        c.setFillColor(colors.HexColor("#17365D"))
        c.setFont("Helvetica-Bold", 10)
        c.drawString(5 * mm, self.height - 7 * mm, "FINDING SEVERITY SNAPSHOT")
        c.setFillColor(colors.HexColor("#536579"))
        c.setFont("Helvetica", 7)
        c.drawRightString(self.width - 5 * mm, self.height - 7 * mm, f"{self.total} consolidated findings")
        palette = {
            "critical": "#8E2430", "high": "#D3543C", "medium": "#E3A12F",
            "low": "#2E83A6", "info": "#6D7C91",
        }
        labels = [("critical", "CRITICAL"), ("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW"), ("info", "INFO")]
        usable_width = self.width - 10 * mm
        gap = 2 * mm
        card_width = (usable_width - gap * 4) / 5
        for index, (level, label) in enumerate(labels):
            x = 5 * mm + index * (card_width + gap)
            c.setFillColor(colors.white)
            c.setStrokeColor(colors.HexColor("#D8E1EC"))
            c.roundRect(x, 5 * mm, card_width, 20 * mm, 3, fill=1, stroke=1)
            c.setFillColor(colors.HexColor(palette[level]))
            c.roundRect(x, 5 * mm, 2 * mm, 20 * mm, 1, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#17365D"))
            c.setFont("Helvetica-Bold", 15)
            c.drawCentredString(x + card_width / 2, 15 * mm, str(self.counts[level]))
            c.setFillColor(colors.HexColor(palette[level]))
            c.setFont("Helvetica-Bold", 6.5)
            c.drawCentredString(x + card_width / 2, 9 * mm, label)
        c.setFillColor(colors.HexColor("#536579"))
        c.setFont("Helvetica-Oblique", 6.5)
        c.drawString(5 * mm, 2.5 * mm, "Counts are grouped by recorded severity; they are not business-impact or revenue-loss estimates.")
        c.restoreState()

class AuditAreaInfographic(Flowable):
    """Compact, evidence-derived bar chart showing where consolidated findings cluster."""
    LABELS = {
        "accessibility": "Accessibility",
        "mobile_ux": "Mobile UX",
        "performance": "Performance",
        "static_performance": "Performance",
        "technical_seo": "Technical SEO",
        "on_page_seo": "On-page SEO",
        "seo": "SEO",
        "security": "Security",
        "security_headers": "Security",
        "security_exposure": "Security",
        "security_transport": "Security",
        "structured_data": "Structured data",
        "conversion_paid_traffic": "Conversion & paid traffic",
        "conversion": "Conversion & paid traffic",
        "paid_traffic": "Conversion & paid traffic",
        "trust": "Trust signals",
    }

    def __init__(self, findings: list[dict[str, object]]):
        super().__init__()
        self.width = 174 * mm
        self.height = 49 * mm
        grouped: dict[str, int] = {}
        for item in findings:
            category = str(item.get("category", "other")).lower()
            label = self.LABELS.get(category, category.replace("_", " ").title() or "Other")
            grouped[label] = grouped.get(label, 0) + 1
        self.items = sorted(grouped.items(), key=lambda pair: (-pair[1], pair[0]))[:5]
        self.max_count = max((count for _, count in self.items), default=1)

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(colors.HexColor("#F4F7FB"))
        c.setStrokeColor(colors.HexColor("#D8E1EC"))
        c.roundRect(0, 0, self.width, self.height, 7, fill=1, stroke=1)
        c.setFillColor(colors.HexColor("#17365D"))
        c.setFont("Helvetica-Bold", 10)
        c.drawString(5 * mm, self.height - 7 * mm, "FINDINGS BY AUDIT AREA")
        if not self.items:
            c.setFillColor(colors.HexColor("#536579"))
            c.setFont("Helvetica", 8)
            c.drawString(5 * mm, self.height - 17 * mm, "No consolidated findings were recorded in this run.")
            c.restoreState()
            return
        label_x = 5 * mm
        bar_x = 57 * mm
        bar_width = 87 * mm
        count_x = self.width - 5 * mm
        row_y = self.height - 15 * mm
        for label, count in self.items:
            c.setFillColor(colors.HexColor("#334A62"))
            c.setFont("Helvetica", 7.5)
            c.drawString(label_x, row_y, label[:34])
            c.setFillColor(colors.HexColor("#E0E8F1"))
            c.roundRect(bar_x, row_y - 1.2 * mm, bar_width, 3.2 * mm, 1.5, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#2E83A6"))
            c.roundRect(bar_x, row_y - 1.2 * mm, max(1.5 * mm, bar_width * count / self.max_count), 3.2 * mm, 1.5, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#17365D"))
            c.setFont("Helvetica-Bold", 7.5)
            c.drawRightString(count_x, row_y, str(count))
            row_y -= 6.1 * mm
        c.setFillColor(colors.HexColor("#536579"))
        c.setFont("Helvetica-Oblique", 6.5)
        c.drawString(5 * mm, 2.5 * mm, "Counts reflect consolidated recorded findings, not severity, business impact, or revenue loss.")
        c.restoreState()



class ExecutiveSummaryInfographic(Flowable):
    """Compact, first-glance severity and execution-status summary."""
    def __init__(self, findings: list[dict[str, object]], pages_inspected: int):
        super().__init__()
        self.width = 174 * mm
        self.height = 37 * mm
        self.pages_inspected = pages_inspected
        self.metrics = [
            ("CRITICAL / HIGH", sum(1 for x in findings if str(x.get("severity", "")).lower() in {"critical", "high"}), "#8E2430"),
            ("MEDIUM", sum(1 for x in findings if str(x.get("severity", "")).lower() == "medium"), "#B87912"),
            ("LOW / INFO", sum(1 for x in findings if str(x.get("severity", "")).lower() in {"low", "info"}), "#2E83A6"),
            ("VERIFIED", sum(1 for x in findings if str(x.get("status", "")).lower() == "verified"), "#23734D"),
            ("REVIEW NEEDED", sum(1 for x in findings if str(x.get("status", "")).lower() == "manual_review_required"), "#9A6700"),
            ("NOT TESTED", sum(1 for x in findings if str(x.get("status", "")).lower() in {"not_tested", "insufficient_data"}), "#6D7C91"),
        ]

    def draw(self):
        c = self.canv
        c.saveState()
        navy = colors.HexColor("#17365D")
        c.setFillColor(navy)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(0, self.height - 4 * mm, "AUDIT AT A GLANCE")
        gap = 2 * mm
        card_w = (self.width - gap * 2) / 3
        card_h = 12 * mm
        start_y = self.height - 18 * mm
        for i, (label, value, color_hex) in enumerate(self.metrics):
            col, row = i % 3, i // 3
            x = col * (card_w + gap)
            y = start_y - row * (card_h + 2 * mm)
            c.setFillColor(colors.HexColor("#F4F7FB"))
            c.setStrokeColor(colors.HexColor("#D8E1EC"))
            c.roundRect(x, y, card_w, card_h, 3, fill=1, stroke=1)
            c.setFillColor(colors.HexColor(color_hex))
            c.roundRect(x, y, 2 * mm, card_h, 1, fill=1, stroke=0)
            c.setFillColor(colors.HexColor(color_hex))
            c.setFont("Helvetica-Bold", 13)
            c.drawString(x + 4 * mm, y + 4.5 * mm, str(value))
            c.setFillColor(navy)
            c.setFont("Helvetica-Bold", 6.5)
            c.drawString(x + 17 * mm, y + 4.8 * mm, label)
        c.setFillColor(colors.HexColor("#536579"))
        c.setFont("Helvetica-Oblique", 6.5)
        c.drawString(0, 0, f"{self.pages_inspected} page(s) inspected. Counts are consolidated findings, not a complete-check pass rate.")
        c.restoreState()


class PhaseScorecardInfographic(Flowable):
    """Per-phase visual snapshot of recorded evidence, not a fabricated check pass rate."""
    PHASES = [
        ("Technical SEO & discovery", {"seo", "technical_seo", "on_page_seo", "structured_data", "indexing", "crawlability", "robots_txt", "sitemap_xml", "llms_txt", "crawl"}),
        ("Performance & mobile UX", {"performance", "static_performance", "mobile_ux"}),
        ("Accessibility", {"accessibility", "aria_alt_text"}),
        ("Security & trust", {"security", "security_headers", "security_exposure", "security_transport", "security_dependency", "trust"}),
        ("Conversion & paid traffic", {"conversion_paid_traffic", "conversion", "paid_traffic"}),
    ]

    def __init__(self, findings: list[dict[str, object]]):
        super().__init__()
        self.width = 174 * mm
        self.row_height = 26 * mm
        self.height = 12 * mm + len(self.PHASES) * self.row_height
        self.rows = []
        for label, categories in self.PHASES:
            items = [item for item in findings if str(item.get("category", "")).lower() in categories]
            verified = sum(1 for item in items if str(item.get("status", "")).lower() == "verified")
            review = sum(1 for item in items if str(item.get("status", "")).lower() == "manual_review_required")
            not_tested = sum(1 for item in items if str(item.get("status", "")).lower() in {"not_tested", "insufficient_data"})
            total = len(items)
            evidence_pct = round(100 * verified / total) if total else None
            severity = {
                level: sum(1 for item in items if str(item.get("severity", "")).lower() == level)
                for level in ("critical", "high", "medium", "low", "info")
            }
            self.rows.append((label, total, verified, review, not_tested, evidence_pct, severity))

    def draw(self):
        c = self.canv
        c.saveState()
        navy = colors.HexColor("#17365D")
        muted = colors.HexColor("#536579")
        border = colors.HexColor("#D8E1EC")
        c.setFillColor(navy)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(0, self.height - 7 * mm, "PHASE-BY-PHASE EVIDENCE SNAPSHOT")
        y = self.height - 12 * mm
        for label, total, verified, review, not_tested, evidence_pct, severity in self.rows:
            y -= self.row_height
            c.setFillColor(colors.HexColor("#F4F7FB"))
            c.setStrokeColor(border)
            c.roundRect(0, y, self.width, self.row_height - 2 * mm, 4, fill=1, stroke=1)
            c.setFillColor(navy)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(4 * mm, y + 17 * mm, label)
            c.setFillColor(muted)
            c.setFont("Helvetica", 7)
            c.drawString(4 * mm, y + 10.5 * mm, f"{total} recorded finding(s)  |  {verified} verified  |  {review} review needed  |  {not_tested} not tested / insufficient")
            if total:
                pct_text = f"{evidence_pct}% of findings verified"
                c.setFillColor(colors.HexColor("#23734D") if evidence_pct is not None and evidence_pct >= 75 else colors.HexColor("#9A6700"))
            else:
                # An empty finding bucket is not evidence of a successful audit.
                # Paid-traffic checks requiring ad-account or browser-network data
                # remain unassessed in a public-HTML-only run.
                if "conversion" in label.lower() or "paid traffic" in label.lower():
                    pct_text = "Coverage incomplete"
                else:
                    pct_text = "No finding recorded"
                c.setFillColor(muted)
            c.setFont("Helvetica-Bold", 7.5)
            c.drawRightString(self.width - 4 * mm, y + 17 * mm, pct_text)
            # Severity distribution bar is a visual index of recorded findings only.
            levels = [
                ("critical", "#8E2430"), ("high", "#D3543C"), ("medium", "#E3A12F"),
                ("low", "#2E83A6"), ("info", "#6D7C91"),
            ]
            total_severity = sum(severity.values())
            x = 4 * mm
            bar_y = y + 4 * mm
            bar_width = self.width - 8 * mm
            c.setFillColor(colors.HexColor("#E0E8F1"))
            c.roundRect(x, bar_y, bar_width, 3 * mm, 1.5, fill=1, stroke=0)
            if total_severity:
                cursor = x
                for level, hex_color in levels:
                    count = severity[level]
                    segment = bar_width * count / total_severity
                    if segment > 0:
                        c.setFillColor(colors.HexColor(hex_color))
                        c.rect(cursor, bar_y, segment, 3 * mm, fill=1, stroke=0)
                        cursor += segment
            c.setFillColor(muted)
            c.setFont("Helvetica-Oblique", 6)
            c.drawRightString(self.width - 4 * mm, y + 1 * mm, "Severity mix of recorded findings")
        c.restoreState()


def _paid_media_coverage_rows() -> list[list[str]]:
    """Describe paid-media evidence coverage without implying account-level access."""
    return [
        ["Evidence area", "Coverage in this audit"],
        ["Landing-page forms, links and visible trust signals", "Checked from bounded public HTML where available"],
        ["Publicly detectable marketing-tag signatures", "Static presence signal only; firing and event payloads not verified"],
        ["Ad-account spend, clicks and campaign settings", "Not connected / not assessed"],
        ["Conversion attribution, CPA and ROAS", "Not connected / not assessed"],
        ["Pixel or analytics event delivery", "Not verified in a live browser network session"],
        ["Campaign-to-landing-page message match", "Requires campaign creatives, targeting and landing-page context"],
    ]


def _conversion_paid_traffic_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    """Select the dedicated conversion/paid-traffic category without implying measured ad loss."""
    return [
        finding for finding in findings
        if str(finding.get("category", "")).strip().lower() == "conversion_paid_traffic"
    ]


def render_audit_pdf(
    result: AuditCheckResult,
    screenshot_data_uri: str | None = None,
    desktop_screenshot_data_uri: str | None = None,
    coverage_manifest: dict[str, object] | None = None,
) -> bytes:
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

    cover_findings = _consolidate_findings(result.findings)
    cover_priority_count = sum(
        1 for finding in cover_findings
        if str(finding.get("severity", "")).lower() in {"critical", "high"}
    )
    story = [
        PremiumCoverHero(
            result.target_url,
            result.checked_at_utc,
            len(set(result.pages_checked)),
            len(cover_findings),
            cover_priority_count,
        ),
        Spacer(1, 5 * mm),
        Paragraph("Executive overview", section_style),
        _p(
            "A decision-focused review of observable website signals, likely areas for human verification, and practical next steps. "
            "This report distinguishes direct observations from items that need further evidence.",
            body_style,
        ),
        Paragraph("How to read this report", section_style),
        _p(
            "Verified means the stated observation was directly seen in the sampled response; it does not automatically prove business impact. "
            "Manual review required means context or human validation is needed. Not tested / insufficient data means no pass or failure can be inferred.",
            body_style,
        ),
        _p(
            "Severity is a triage aid, not a revenue-loss estimate. This report does not guarantee rankings, conversions, legal compliance, accessibility conformance, or security.",
            small_style,
        ),
    ]

    phase_cards = [
        [PhaseVisual("Technical SEO & discovery", "Metadata, crawl and index signals", "seo"),
         PhaseVisual("Performance & mobile UX", "Delivery and rendered viewport signals", "performance")],
        [PhaseVisual("Accessibility & usability", "Labels, semantics and keyboard signals", "accessibility"),
         PhaseVisual("Security & trust", "Headers and public exposure checks", "security")],
        [PhaseVisual("Conversion & paid traffic", "Journey friction and campaign-data limits", "conversion"),
         PhaseVisual("Evidence & coverage", "Sampled pages and verification status", "evidence")],
    ]
    phase_table = Table(phase_cards, colWidths=[87 * mm, 87 * mm], hAlign="LEFT")
    phase_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 2 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2 * mm),
    ]))
    story.extend([phase_table, Spacer(1, 3 * mm)])
    story.append(PageBreak())

    # Validate screenshots at the PDF boundary; only actual browser captures are accepted.
    def _screenshot_flowable(data_uri: str | None):
        if not isinstance(data_uri, str) or len(data_uri) > 1_400_000:
            return None
        match = re.fullmatch(r"data:(image/png|image/jpeg);base64,([A-Za-z0-9+/]*={0,2})", data_uri)
        if not match:
            return None
        try:
            image_bytes = base64.b64decode(match.group(2), validate=True)
            valid_png = match.group(1) == "image/png" and image_bytes.startswith(bytes.fromhex("89504e470d0a1a0a"))
            valid_jpeg = match.group(1) == "image/jpeg" and image_bytes.startswith(bytes.fromhex("ffd8ff"))
            if not image_bytes or len(image_bytes) > 1_000_000 or not (valid_png or valid_jpeg):
                return None
            candidate = Image(BytesIO(image_bytes), width=174 * mm, height=76 * mm, kind="proportional")
            candidate.hAlign = "CENTER"
            return candidate
        except (ValueError, TypeError, OSError):
            return None

    mobile_capture = _screenshot_flowable(screenshot_data_uri)
    desktop_capture = _screenshot_flowable(desktop_screenshot_data_uri)
    if desktop_capture is not None or mobile_capture is not None:
        # Keep the section heading with its real screenshots. Without this grouping,
        # ReportLab could leave the heading at the foot of one page and move both
        # screenshots to the next page, creating a confusing blank gap.
        screenshot_section = [
            Paragraph("Real website screenshots", section_style),
            _p(
                "Captured from the audited website during this run. Screenshots are visual evidence of the captured view only; "
                "they do not by themselves prove a finding or represent every page.",
                small_style,
            ),
        ]
        capture_label_style = ParagraphStyle(
            "ScreenshotCaptureLabel", parent=small_style, fontName="Helvetica-Bold",
            fontSize=8, leading=10, textColor=colors.HexColor("#245B8F"),
            backColor=colors.HexColor("#EEF4FA"), borderColor=colors.HexColor("#D5DFEA"),
            borderWidth=0.5, borderPadding=5, spaceBefore=2, spaceAfter=4,
        )
        if desktop_capture is not None:
            screenshot_section.extend([
                Paragraph("DESKTOP CAPTURE  •  1440 CSS px viewport  •  Live browser evidence", capture_label_style),
                desktop_capture, Spacer(1, 3 * mm),
            ])
        if mobile_capture is not None:
            screenshot_section.extend([
                Paragraph("MOBILE CAPTURE  •  390 CSS px viewport  •  Live browser evidence", capture_label_style),
                mobile_capture, Spacer(1, 2 * mm),
            ])
        if desktop_capture is None:
            screenshot_section.append(_p("Desktop screenshot unavailable for this run.", small_style))
        if mobile_capture is None:
            screenshot_section.append(_p("Mobile screenshot unavailable for this run.", small_style))
        story.append(KeepTogether(screenshot_section))
    else:
        story.extend([
            Paragraph("Real website screenshots", section_style),
            _p(
                "Desktop and mobile browser screenshots could not be captured for this run. No website screenshot was fabricated. "
                "The phase illustrations below are explanatory graphics only.",
                body_style,
            ),
        ])


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

    story.append(PageBreak())

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
        colWidths=[58 * mm, 58 * mm, 58 * mm],
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
    summary = Table(summary_rows, colWidths=[120 * mm, 54 * mm], repeatRows=1, hAlign="LEFT")
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
    story.append(ExecutiveSummaryInfographic(consolidated_findings, len(set(result.pages_checked))))
    story.append(Spacer(1, 4 * mm))
    story.append(KeepTogether([overview, Spacer(1, 4 * mm), summary, Spacer(1, 4 * mm)]))
    story.extend([FindingMixInfographic(consolidated_findings), Spacer(1, 3 * mm), AuditAreaInfographic(consolidated_findings), Spacer(1, 4 * mm)])
    story.append(PhaseScorecardInfographic(consolidated_findings))
    story.append(Spacer(1, 4 * mm))
    story.append(_p(
        "The phase percentage is the share of recorded findings marked verified, not a check pass rate. A verified finding means the observation was confirmed; it can describe either a positive signal or an issue. This audit result schema does not yet record every executed check and its pass/fail outcome, so true check success rate and execution coverage are not available here. A phase with no recorded findings is shown as not recorded, never as 100% passed.",
        small_style,
    ))

    story.append(PageBreak())
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
            story.append(KeepTogether([
                Paragraph(
                    f"<b>{escape(str(action['severity']).title())} — {escape(str(action['title']))}</b>",
                    finding_style,
                ),
                _p(
                    f"Status: {str(action['status']).replace('_', ' ').title()}",
                    small_style,
                ),
                _p(str(action["recommendation"]), body_style),
                Spacer(1, 2 * mm),
            ]))
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

    # Keep conversion-path diagnostics visible as their own commercial review area.
    # These are source-level signals, not measured ad attribution or lost-revenue figures.
    conversion_findings = _conversion_paid_traffic_findings(consolidated_findings)
    story.append(PageBreak())
    story.append(Paragraph("Conversion & Paid-Traffic Waste Audit", section_style))
    story.append(_p(
        "This section highlights observable friction and trust signals that may deserve attention on lead, product, cart, or checkout journeys. "
        "The audit does not access ad-account spend, campaign attribution, analytics conversion events, or order data; it cannot quantify wasted spend or lost sales. "
        "A finding here is a review lead, not proof that a campaign is underperforming.",
        body_style,
    ))
    coverage_rows = _paid_media_coverage_rows()
    coverage_table = Table(
        [[_p(cell, small_style) for cell in row] for row in coverage_rows],
        colWidths=[70 * mm, 104 * mm],
        repeatRows=1,
        hAlign="LEFT",
    )
    coverage_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C8D1DC")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([coverage_table, Spacer(1, 3 * mm)])
    if conversion_findings:
        for item in conversion_findings:
            conversion_block = [
                Paragraph(
                    f"<b>{escape(str(item['title']))}</b>",
                    finding_style,
                ),
                _p(
                    f"Status: {str(item['status']).replace('_', ' ').title()} | "
                    f"Severity: {str(item['severity']).title()}",
                    small_style,
                ),
            ]
            evidence_items = list(item.get("evidence", []))
            if evidence_items:
                conversion_block.append(Paragraph("<b>Observed signal</b>", body_style))
                conversion_block.extend(_p("• " + str(evidence_item), body_style) for evidence_item in evidence_items[:2])
            conversion_block.extend([
                Paragraph("<b>Recommended review</b>", body_style),
                _p(str(item["recommendation"]), body_style),
                Spacer(1, 2 * mm),
            ])
            story.append(KeepTogether(conversion_block))
    else:
        story.append(_p(
            "No findings were classified under the dedicated conversion/paid-traffic category in this run. "
            "That does not establish that checkout works or that paid campaigns are efficient; the relevant journeys and campaign data were not proven by this category alone.",
            body_style,
        ))

    story.append(PageBreak())
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
        severity = str(finding["severity"]).lower()
        severity_colors = {
            "critical": "#8E2430",
            "high": "#D3543C",
            "medium": "#B87912",
            "low": "#2E83A6",
            "info": "#6D7C91",
        }
        status_colors = {
            "verified": "#23734D",
            "manual_review_required": "#9A6700",
            "not_tested": "#6D7C91",
            "insufficient_data": "#6D7C91",
        }
        severity_color = colors.HexColor(severity_colors.get(severity, "#6D7C91"))
        status = str(finding["status"]).lower()
        status_color = colors.HexColor(status_colors.get(status, "#6D7C91"))
        header = Table(
            [[
                Paragraph(
                    f"<b>{index}. {escape(str(finding['title']))}</b>",
                    ParagraphStyle(
                        f"FindingCardTitle{index}", parent=finding_style,
                        textColor=colors.HexColor("#17365D"), fontSize=10.5,
                        leading=13, spaceBefore=0, spaceAfter=0,
                    ),
                ),
                Paragraph(
                    f'<font color="{severity_colors.get(severity, "#6D7C91")}">'
                    f"<b>{escape(severity.upper())}</b></font>",
                    ParagraphStyle(
                        f"FindingCardSeverity{index}", parent=small_style,
                        alignment=TA_CENTER, fontSize=7.5, leading=9,
                    ),
                ),
            ]],
            colWidths=[144 * mm, 30 * mm],
            hAlign="LEFT",
        )
        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F2F6FB")),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D5DFEA")),
            ("LINEBEFORE", (0, 0), (0, -1), 3, severity_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        # Defer the visual header until the status and result blocks are ready, so
        # a finding title never gets stranded at the bottom of a page by itself.
        category_line = _p(
            f"Category: {str(finding['category']).replace('_', ' ').title()}",
            small_style,
        )

        # Keep each finding's visual header away from the foot of a page. The body may
        # continue naturally, but the title/status/result panel should start as a unit.
        story.append(KeepTogether([
            Spacer(1, 2 * mm),
            header,
            Spacer(1, 1.5 * mm),
            FindingInsightInfographic(finding),
            Spacer(1, 1.5 * mm),
            category_line,
            Spacer(1, 1 * mm),
        ]))
        blocks = []
        instances = int(finding["instances"])
        urls = list(finding["source_urls"])
        if instances > 1:
            blocks.append(_p(f"Occurrences consolidated: {instances}", small_style))
        if urls:
            refs = ", ".join(evidence_ids[url] for url in urls)
            blocks.append(_p(f"Evidence references: {refs}", small_style))
            blocks.append(_p(f"Affected pages with recorded evidence: {len(urls)}", small_style))
        blocks.append(Paragraph("<b>What was observed</b>", body_style))
        evidence_items = list(finding["evidence"])
        if evidence_items:
            # Keep observations distinct instead of flattening them into one long
            # paragraph; this preserves the connection between each evidence item
            # and its affected page when findings are consolidated across URLs.
            for evidence_item in evidence_items:
                blocks.append(_p("• " + evidence_item, body_style))
        else:
            blocks.append(_p("No specific evidence text was recorded.", body_style))
        blocks.extend([
            Paragraph("<b>What this means</b>", body_style),
            _p(finding["explanation"], body_style),
            Paragraph("<b>Recommended solution</b>", body_style),
            _p(finding["recommendation"], body_style),
        ])
        # Every finding gets an impact explanation, but fallback language stays cautious:
        # no conversion/revenue gains are presented as measured or guaranteed outcomes.
        potential_benefit, risk_if_unresolved = _business_impact_context(finding)
        blocks.extend([
            Paragraph("<b>Potential benefit if addressed</b>", body_style),
            _p(potential_benefit, body_style),
            Paragraph("<b>Risk if left unresolved</b>", body_style),
            _p(risk_if_unresolved, body_style),
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
            safe_url = escape(url, {'"': "&quot;"})
            safe_label = escape(url)
            story.append(Paragraph(
                f'<link href="{safe_url}" color="#1759a8">'
                f'{escape(reference_id)}: {safe_label}</link>',
                small_style,
            ))

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
    if coverage_manifest:
        coverage_pct = coverage_manifest.get("category_signal_coverage_pct")
        observed_count = coverage_manifest.get("categories_with_recorded_findings", 0)
        category_total = coverage_manifest.get("required_categories", 0)
        story.append(Paragraph("Audit category evidence coverage", base["Heading2"]))
        story.append(_p(
            f"Category-signal coverage: {coverage_pct}% ({observed_count} of {category_total} required categories had at least one recorded finding).",
            body_style,
        ))
        story.append(_p(
            str(coverage_manifest.get("important_note", "Coverage is a conservative summary of recorded signals, not proof that every check ran or passed.")),
            small_style,
        ))
        coverage_rows = [[_p("Audit category", body_style), _p("Evidence status", body_style), _p("Recorded findings", body_style)]]
        for item in [*coverage_manifest.get("observed_categories", []), *coverage_manifest.get("not_proven_categories", [])]:
            coverage_rows.append([
                _p(item.get("label", item.get("category", "Unknown")), small_style),
                _p(item.get("status", "not_proven").replace("_", " "), small_style),
                _p(str(item.get("findings_in_category", 0)), small_style),
            ])
        coverage_table = Table(coverage_rows, colWidths=[91 * mm, 43 * mm, 34 * mm], repeatRows=1, hAlign="LEFT")
        coverage_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EAF0F6")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D5DFE8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.extend([coverage_table, Spacer(1, 3 * mm)])
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
        # Restrained running header and footer keep multi-page client reports branded
        # without competing with the evidence or screenshots.
        canvas.setStrokeColor(colors.HexColor("#49D3C4"))
        canvas.setLineWidth(0.8)
        canvas.line(18 * mm, A4[1] - 15 * mm, A4[0] - 18 * mm, A4[1] - 15 * mm)
        canvas.setFillColor(colors.HexColor("#17365D"))
        canvas.setFont("Helvetica-Bold", 7)
        canvas.drawString(18 * mm, A4[1] - 11 * mm, "ECOMMERCE AUDIT AGENT")
        try:
            report_host = (urlsplit(result.target_url).hostname or "website").lower()
        except (ValueError, UnicodeError):
            report_host = "website"
        canvas.setFillColor(colors.HexColor("#2E83A6"))
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(A4[0] - 18 * mm, A4[1] - 11 * mm, f"CLIENT REPORT  •  {report_host[:48]}")
        canvas.setStrokeColor(colors.HexColor("#D5DCE5"))
        canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(18 * mm, 8 * mm, "Evidence-first website audit")
        canvas.drawRightString(A4[0] - 18 * mm, 8 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()