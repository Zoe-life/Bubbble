"""
Phase 4, Point 3 — Export Audit Reports as PDF

Generates a formatted, branded PDF audit report for a Bubbble threat event.
Reports are useful for:
  - Users who want to share evidence with social platforms (Instagram, TikTok)
  - Reporting attacks to law-enforcement or national CERTs (e.g. KE-CIRT/CC)
  - Internal record-keeping

Requires:
    pip install reportlab

Usage::

    from backend.audit.pdf_export import AuditReport, generate_pdf

    report = AuditReport(
        report_id="RPT-20260319-001",
        user_display_name="Zoe Creator",
        generated_at=datetime.utcnow(),
        blocked_url="https://evil-phish.example.com/login",
        threat_category="Phishing",
        origin_platform="Instagram DM",
        risk_score=92,
        redirect_chain=["https://bit.ly/xyz", "https://evil-phish.example.com/login"],
        domain_age_days=3,
        ssl_valid=False,
        phishtank_match=True,
        openphish_match=False,
        recommended_action="Change your Instagram password immediately ...",
    )
    pdf_bytes = generate_pdf(report)
    with open("audit_report.pdf", "wb") as f:
        f.write(pdf_bytes)
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Brand colours
# ---------------------------------------------------------------------------

BUBBBLE_BLUE = colors.HexColor("#3B82F6")
BUBBBLE_DARK = colors.HexColor("#1E1B4B")
DANGER_RED = colors.HexColor("#DC2626")
SAFE_GREEN = colors.HexColor("#16A34A")
LIGHT_GREY = colors.HexColor("#F3F4F6")
MID_GREY = colors.HexColor("#6B7280")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class AuditReport:
    """All data needed to generate a single PDF audit report."""

    # Identifiers
    report_id: str
    user_display_name: str
    generated_at: datetime

    # Threat details
    blocked_url: str
    threat_category: str            # e.g. "Phishing", "Malware", "Credential Harvesting"
    origin_platform: str            # e.g. "Instagram DM", "WhatsApp", "Email"
    risk_score: int                 # 0–100

    # Technical indicators
    redirect_chain: list[str] = field(default_factory=list)
    domain_age_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    phishtank_match: bool = False
    openphish_match: bool = False
    virus_total_detections: Optional[int] = None  # number of AV engines that flagged it

    # User guidance
    recommended_action: str = ""

    # Optional extra notes (appended verbatim)
    notes: str = ""


# ---------------------------------------------------------------------------
# PDF generator
# ---------------------------------------------------------------------------


def generate_pdf(report: AuditReport) -> bytes:
    """
    Generate a PDF audit report and return its raw bytes.

    :param report: Populated :class:`AuditReport` instance.
    :returns: PDF file content as ``bytes``.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Bubbble Audit Report – {report.report_id}",
        author="Bubbble Security",
        subject="Link Threat Audit Report",
    )

    styles = _build_styles()
    story = []

    _add_header(story, styles, report)
    _add_threat_summary(story, styles, report)
    _add_technical_indicators(story, styles, report)
    _add_redirect_chain(story, styles, report)
    _add_recommended_action(story, styles, report)
    if report.notes:
        _add_notes(story, styles, report)
    _add_footer(story, styles, report)

    doc.build(story)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _add_header(story: list, styles: dict, report: AuditReport) -> None:
    story.append(Paragraph("🫧 Bubbble", styles["brand"]))
    story.append(Paragraph("Link Threat Audit Report", styles["title"]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(HRFlowable(width="100%", thickness=2, color=BUBBBLE_BLUE))
    story.append(Spacer(1, 0.4 * cm))

    meta = [
        ["Report ID", report.report_id],
        ["Generated", report.generated_at.strftime("%Y-%m-%d %H:%M UTC")],
        ["Account", report.user_display_name],
    ]
    _add_key_value_table(story, meta, styles)
    story.append(Spacer(1, 0.5 * cm))


def _add_threat_summary(story: list, styles: dict, report: AuditReport) -> None:
    story.append(Paragraph("Threat Summary", styles["section_heading"]))
    story.append(Spacer(1, 0.2 * cm))

    score_label = f"Risk Score: {report.risk_score}/100"
    score_style_key = (
        "score_danger" if report.risk_score >= 70
        else ("score_warning" if report.risk_score >= 40 else "score_safe")
    )

    data = [
        ["Blocked URL", _safe_url(report.blocked_url)],
        ["Threat Category", report.threat_category],
        ["Origin Platform", report.origin_platform],
        [Paragraph(score_label, styles[score_style_key]), ""],
    ]
    _add_key_value_table(story, data, styles)
    story.append(Spacer(1, 0.5 * cm))


def _add_technical_indicators(story: list, styles: dict, report: AuditReport) -> None:
    story.append(Paragraph("Technical Indicators", styles["section_heading"]))
    story.append(Spacer(1, 0.2 * cm))

    rows: list[list] = []

    if report.domain_age_days is not None:
        age_text = (
            f"{report.domain_age_days} day(s) old ⚠️"
            if report.domain_age_days < 30
            else f"{report.domain_age_days} days old"
        )
        rows.append(["Domain Age", age_text])

    if report.ssl_valid is not None:
        ssl_text = "Valid ✓" if report.ssl_valid else "Missing or invalid ⚠️"
        rows.append(["SSL/TLS Certificate", ssl_text])

    if report.phishtank_match or report.openphish_match:
        feeds = []
        if report.phishtank_match:
            feeds.append("PhishTank ✓")
        if report.openphish_match:
            feeds.append("OpenPhish ✓")
        rows.append(["Phishing Feed Match", ", ".join(feeds)])

    if report.virus_total_detections is not None:
        rows.append(["VirusTotal Detections", f"{report.virus_total_detections} AV engine(s)"])

    if rows:
        _add_key_value_table(story, rows, styles)
    else:
        story.append(Paragraph("No additional technical indicators recorded.", styles["body"]))

    story.append(Spacer(1, 0.5 * cm))


def _add_redirect_chain(story: list, styles: dict, report: AuditReport) -> None:
    if not report.redirect_chain:
        return
    story.append(Paragraph("Redirect Chain", styles["section_heading"]))
    story.append(Spacer(1, 0.2 * cm))
    for i, hop in enumerate(report.redirect_chain, start=1):
        label = "→ " if i > 1 else ""
        story.append(Paragraph(
            f"<font color='#6B7280'>{label}Hop {i}:</font> {_safe_url(hop)}",
            styles["mono"],
        ))
    story.append(Spacer(1, 0.5 * cm))


def _add_recommended_action(story: list, styles: dict, report: AuditReport) -> None:
    story.append(Paragraph("Recommended Action", styles["section_heading"]))
    story.append(Spacer(1, 0.2 * cm))
    text = report.recommended_action or "No specific action required at this time."
    story.append(Paragraph(text, styles["body"]))
    story.append(Spacer(1, 0.5 * cm))


def _add_notes(story: list, styles: dict, report: AuditReport) -> None:
    story.append(Paragraph("Additional Notes", styles["section_heading"]))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(report.notes, styles["body"]))
    story.append(Spacer(1, 0.5 * cm))


def _add_footer(story: list, styles: dict, report: AuditReport) -> None:
    story.append(HRFlowable(width="100%", thickness=1, color=LIGHT_GREY))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        "Generated by Bubbble — protecting creators from link-based threats. "
        "bubbble.com | support@bubbble.com",
        styles["footer"],
    ))
    story.append(Paragraph(
        "This report is end-to-end encrypted in your Bubbble account and was "
        "decrypted locally to generate this PDF. Bubbble cannot read its contents.",
        styles["footer"],
    ))


# ---------------------------------------------------------------------------
# Style helpers
# ---------------------------------------------------------------------------


def _build_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "brand": ParagraphStyle(
            "brand",
            fontSize=22,
            fontName="Helvetica-Bold",
            textColor=BUBBBLE_BLUE,
            spaceAfter=4,
        ),
        "title": ParagraphStyle(
            "title",
            fontSize=16,
            fontName="Helvetica-Bold",
            textColor=BUBBBLE_DARK,
            spaceAfter=6,
        ),
        "section_heading": ParagraphStyle(
            "section_heading",
            fontSize=12,
            fontName="Helvetica-Bold",
            textColor=BUBBBLE_DARK,
            spaceBefore=6,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            fontSize=10,
            fontName="Helvetica",
            textColor=colors.black,
            leading=14,
        ),
        "mono": ParagraphStyle(
            "mono",
            fontSize=9,
            fontName="Courier",
            textColor=colors.black,
            leading=13,
        ),
        "score_danger": ParagraphStyle(
            "score_danger",
            textColor=DANGER_RED,
            fontSize=11,
            fontName="Helvetica-Bold",
        ),
        "score_warning": ParagraphStyle(
            "score_warning",
            textColor=colors.orange,
            fontSize=11,
            fontName="Helvetica-Bold",
        ),
        "score_safe": ParagraphStyle(
            "score_safe",
            textColor=SAFE_GREEN,
            fontSize=11,
            fontName="Helvetica-Bold",
        ),
            "footer",
            fontSize=8,
            fontName="Helvetica",
            textColor=MID_GREY,
            leading=11,
            spaceAfter=3,
        ),
    }


def _add_key_value_table(story: list, rows: list[list], styles: dict) -> None:
    """Render a two-column key/value table with Bubbble styling."""
    table = Table(rows, colWidths=["35%", "65%"])
    table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1), LIGHT_GREY),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",   (0, 0), (0, -1), BUBBBLE_DARK),
        ("TEXTCOLOR",   (1, 0), (1, -1), colors.black),
        ("ALIGN",       (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, LIGHT_GREY]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(table)


def _safe_url(url: str) -> str:
    """Truncate very long URLs for display in the PDF."""
    max_chars = 90
    return url if len(url) <= max_chars else url[:max_chars - 1] + "…"
