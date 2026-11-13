
from datetime import datetime
from pathlib import Path
import sys

# ============================================================
# PROJECT PATHS AND IMPORT CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Add project root so sibling packages can be imported.
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

REPORTS_DIR = PROJECT_ROOT / "reports"
PDF_FILE = REPORTS_DIR / "nid_tms_security_report.pdf"

# ============================================================
# REPORTLAB IMPORTS
# ============================================================

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# Import existing report data functions.
from reports.report_generator import (
    load_session_traffic,
    load_lifetime_traffic,
    load_alerts,
    TRAFFIC_KEYS,
)

# ============================================================
# COLORS
# ============================================================

NAVY = colors.HexColor("#142B45")
LIGHT_GREY = colors.HexColor("#F1F5F9")
DARK_GREY = colors.HexColor("#475569")
WHITE = colors.white

# ============================================================
# PAGE FOOTER
# ============================================================

def add_page_number(canvas, document):
    """Add a footer and page number to every PDF page."""

    canvas.saveState()

    page_width, _ = A4

    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.line(
        18 * mm,
        15 * mm,
        page_width - 18 * mm,
        15 * mm,
    )

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(DARK_GREY)

    canvas.drawString(
        18 * mm,
        10 * mm,
        "NID-TMS | Network Defense Center",
    )

    canvas.drawRightString(
        page_width - 18 * mm,
        10 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


# ============================================================
# PDF STYLES
# ============================================================

def create_styles():
    """Create consistent PDF text styles."""

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=26,
        textColor=NAVY,
        alignment=1,
        spaceAfter=8,
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=DARK_GREY,
        alignment=1,
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=NAVY,
        spaceBefore=12,
        spaceAfter=7,
    ))

    styles.add(ParagraphStyle(
        name="SmallText",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=DARK_GREY,
    ))

    styles.add(ParagraphStyle(
        name="TableText",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        wordWrap="CJK",
    ))

    return styles


# ============================================================
# TABLE HELPER
# ============================================================

def create_table(data, widths=None, header=True):
    """Create a consistently formatted PDF table."""

    table = Table(
        data,
        colWidths=widths,
        repeatRows=1 if header else 0,
        hAlign="LEFT",
    )

    commands = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]

    if header:
        commands.extend([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ])

        if len(data) > 1:
            commands.append(
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    WHITE,
                    LIGHT_GREY,
                ])
            )

    table.setStyle(TableStyle(commands))

    return table


# ============================================================
# TRAFFIC SECTION
# ============================================================

def add_traffic_section(story, title, traffic, styles):
    """Add traffic statistics to the PDF."""

    story.append(
        Paragraph(title, styles["SectionHeading"])
    )

    labels = {
        "total_packets": "Total Packets",
        "ipv4_packets": "IPv4 Packets",
        "ipv6_packets": "IPv6 Packets",
        "tcp_packets": "TCP Packets",
        "udp_packets": "UDP Packets",
        "icmp_packets": "ICMP Packets",
        "icmpv6_packets": "ICMPv6 Packets",
        "other_packets": "Other Packets",
        "total_bytes": "Total Bytes",
    }

    data = [[
        Paragraph("<b>Metric</b>", styles["TableText"]),
        Paragraph("<b>Value</b>", styles["TableText"]),
    ]]

    for key in TRAFFIC_KEYS:
        value = traffic.get(key, 0)

        if key == "total_bytes":
            value = f"{value:,}"

        data.append([
            Paragraph(labels[key], styles["TableText"]),
            Paragraph(str(value), styles["TableText"]),
        ])

    story.append(
        create_table(
            data,
            widths=[75 * mm, 75 * mm],
        )
    )

    story.append(Spacer(1, 5 * mm))


# ============================================================
# GENERATE PDF REPORT
# ============================================================

def generate_pdf_report():
    """Generate a PDF security report using project data."""

    session_traffic = load_session_traffic()
    lifetime_traffic = load_lifetime_traffic()
    alerts = load_alerts()

    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "CRITICAL": 0,
    }

    risk_values = []

    for alert in alerts:
        severity = alert["severity"]

        if severity in severity_counts:
            severity_counts[severity] += 1

        risk_values.append(float(alert["risk"]))

    total_alerts = len(alerts)

    average_risk = (
        round(sum(risk_values) / len(risk_values))
        if risk_values
        else 0
    )

    # --------------------------------------------------------
    # DOCUMENT SETUP
    # --------------------------------------------------------

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    document = SimpleDocTemplate(
        str(PDF_FILE),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=22 * mm,
        title="NID-TMS Security Report",
        author="NID-TMS",
    )

    styles = create_styles()
    story = []

    generated_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------------
    # 1. REPORT HEADER
    # --------------------------------------------------------

    story.append(Spacer(1, 12 * mm))

    story.append(
        Paragraph(
            "NID-TMS",
            styles["ReportTitle"],
        )
    )

    story.append(
        Paragraph(
            "NETWORK DEFENSE CENTER",
            styles["ReportSubtitle"],
        )
    )

    story.append(Spacer(1, 3 * mm))

    story.append(
        Paragraph(
            "Network Intrusion Detection &amp; "
            "Real-Time Traffic Monitoring System",
            styles["ReportSubtitle"],
        )
    )

    story.append(Spacer(1, 5 * mm))

    story.append(
        Paragraph(
            "SECURITY ANALYSIS REPORT",
            styles["SectionHeading"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Generated:</b> {generated_time}",
            styles["SmallText"],
        )
    )

    story.append(Spacer(1, 5 * mm))

    # --------------------------------------------------------
    # 2. SECURITY ALERT SUMMARY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "1. SECURITY ALERT SUMMARY",
            styles["SectionHeading"],
        )
    )

    summary_data = [
        ["Metric", "Value"],
        ["Total Alerts", str(total_alerts)],
        ["HIGH Severity", str(severity_counts["HIGH"])],
        ["MEDIUM Severity", str(severity_counts["MEDIUM"])],
        ["LOW Severity", str(severity_counts["LOW"])],
        ["CRITICAL Severity", str(severity_counts["CRITICAL"])],
        ["Average Alert Risk", f"{average_risk}/100"],
    ]

    story.append(
        create_table(
            summary_data,
            widths=[95 * mm, 55 * mm],
        )
    )

    # --------------------------------------------------------
    # 3. TRAFFIC STATISTICS
    # --------------------------------------------------------

    add_traffic_section(
        story,
        "2. CURRENT SESSION TRAFFIC",
        session_traffic,
        styles,
    )

    add_traffic_section(
        story,
        "3. LIFETIME TRAFFIC STATISTICS",
        lifetime_traffic,
        styles,
    )

    # --------------------------------------------------------
    # 4. ALERT TYPE SUMMARY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "4. ALERT TYPE SUMMARY",
            styles["SectionHeading"],
        )
    )

    alert_type_counts = {}

    for alert in alerts:
        alert_type = alert["alert_type"]

        alert_type_counts[alert_type] = (
            alert_type_counts.get(alert_type, 0) + 1
        )

    type_data = [["Alert Type", "Count"]]

    for alert_type, count in sorted(
        alert_type_counts.items(),
        key=lambda item: (-item[1], item[0].lower()),
    ):
        type_data.append([
            Paragraph(str(alert_type), styles["TableText"]),
            str(count),
        ])

    if len(type_data) == 1:
        type_data.append(["No alerts recorded", "0"])

    story.append(
        create_table(
            type_data,
            widths=[95 * mm, 55 * mm],
        )
    )

    # --------------------------------------------------------
    # 5. RECENT ALERTS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "5. TEN MOST RECENT ALERTS",
            styles["SectionHeading"],
        )
    )

    recent_data = [[
        "ID",
        "Severity",
        "Type",
        "Source IP",
        "Risk",
    ]]

    for alert in alerts[:10]:
        recent_data.append([
            str(alert["id"]),
            str(alert["severity"]),
            Paragraph(
                str(alert["alert_type"]),
                styles["TableText"],
            ),
            Paragraph(
                str(alert["source_ip"]),
                styles["TableText"],
            ),
            f'{alert["risk"]}/100',
        ])

    if len(recent_data) == 1:
        recent_data.append([
            "-",
            "-",
            "No alerts recorded",
            "-",
            "-",
        ])

    story.append(
        create_table(
            recent_data,
            widths=[
                12 * mm,
                25 * mm,
                48 * mm,
                43 * mm,
                22 * mm,
            ],
        )
    )

    # --------------------------------------------------------
    # 6. REPORT NOTES
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "6. REPORT NOTES",
            styles["SectionHeading"],
        )
    )

    notes = [
        "Current-session traffic represents the active or "
        "most recently saved capture session.",

        "Lifetime traffic is calculated from stored SQLite records.",

        "Alert risk scores are recalculated using the shared "
        "NID-TMS risk-scoring function.",

        "Test alerts are included in alert totals and averages.",

        "An alert indicates suspicious activity for investigation; "
        "it does not by itself prove that an attack occurred.",
    ]

    for note in notes:
        story.append(
            Paragraph(
                f"&bull; {note}",
                styles["SmallText"],
            )
        )

        story.append(Spacer(1, 2 * mm))

    # --------------------------------------------------------
    # BUILD PDF
    # --------------------------------------------------------

    document.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )

    print("=" * 55)
    print("NID-TMS PDF REPORT GENERATED")
    print("=" * 55)
    print(f"Total alerts: {total_alerts}")
    print(f"Average risk: {average_risk}/100")
    print(f"PDF saved to: {PDF_FILE}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    generate_pdf_report()
