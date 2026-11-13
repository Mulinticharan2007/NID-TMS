
from pathlib import Path

from pypdf import PdfReader

from reports import pdf_report_generator


def test_pdf_report_is_generated(tmp_path, monkeypatch):
    """Verify that the PDF report is created successfully."""

    pdf_file = tmp_path / "test_security_report.pdf"

    monkeypatch.setattr(
        pdf_report_generator,
        "PDF_FILE",
        pdf_file,
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "REPORTS_DIR",
        tmp_path,
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "load_session_traffic",
        lambda: {
            "total_packets": 100,
            "ipv4_packets": 70,
            "ipv6_packets": 30,
            "tcp_packets": 80,
            "udp_packets": 15,
            "icmp_packets": 5,
            "icmpv6_packets": 0,
            "other_packets": 0,
            "total_bytes": 50000,
        },
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "load_lifetime_traffic",
        lambda: {
            "total_packets": 500,
            "ipv4_packets": 350,
            "ipv6_packets": 150,
            "tcp_packets": 400,
            "udp_packets": 80,
            "icmp_packets": 20,
            "icmpv6_packets": 0,
            "other_packets": 0,
            "total_bytes": 250000,
        },
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "load_alerts",
        lambda: [
            {
                "id": 1,
                "timestamp": "2026-11-13 10:00:00",
                "severity": "HIGH",
                "alert_type": "Port Scan",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "description": "Multiple connection attempts",
                "risk": 85,
            },
            {
                "id": 2,
                "timestamp": "2026-11-13 10:05:00",
                "severity": "MEDIUM",
                "alert_type": "SYN Anomaly",
                "source_ip": "192.0.2.15",
                "destination_ip": "198.51.100.25",
                "description": "Unusual SYN activity",
                "risk": 60,
            },
        ],
    )

    pdf_report_generator.generate_pdf_report()

    assert pdf_file.exists()
    assert pdf_file.stat().st_size > 0


def test_pdf_report_contains_expected_sections(tmp_path, monkeypatch):
    """Verify that the generated PDF contains report sections."""

    pdf_file = tmp_path / "test_sections.pdf"

    monkeypatch.setattr(
        pdf_report_generator,
        "PDF_FILE",
        pdf_file,
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "REPORTS_DIR",
        tmp_path,
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "load_session_traffic",
        lambda: {},
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "load_lifetime_traffic",
        lambda: {},
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "load_alerts",
        lambda: [],
    )

    pdf_report_generator.generate_pdf_report()

    reader = PdfReader(str(pdf_file))

    extracted_text = "\n".join(
        page.extract_text() or ""
        for page in reader.pages
    )

    expected_sections = [
        "NID-TMS",
        "SECURITY ANALYSIS REPORT",
        "SECURITY ALERT SUMMARY",
        "CURRENT SESSION TRAFFIC",
        "LIFETIME TRAFFIC STATISTICS",
        "ALERT TYPE SUMMARY",
        "TEN MOST RECENT ALERTS",
        "REPORT NOTES",
    ]

    for section in expected_sections:
        assert section in extracted_text


def test_pdf_report_handles_empty_alerts(tmp_path, monkeypatch):
    """Verify that the PDF generator handles an empty alert list."""

    pdf_file = tmp_path / "empty_alerts.pdf"

    monkeypatch.setattr(
        pdf_report_generator,
        "PDF_FILE",
        pdf_file,
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "REPORTS_DIR",
        tmp_path,
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "load_session_traffic",
        lambda: {},
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "load_lifetime_traffic",
        lambda: {},
    )

    monkeypatch.setattr(
        pdf_report_generator,
        "load_alerts",
        lambda: [],
    )

    pdf_report_generator.generate_pdf_report()

    assert pdf_file.exists()

    reader = PdfReader(str(pdf_file))

    assert len(reader.pages) >= 1
