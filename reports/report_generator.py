
from collections import Counter
from datetime import datetime
from pathlib import Path
import sqlite3
import sys

# Add project root so sibling packages can be imported.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzer.risk_scoring import calculate_risk_score
from analyzer.traffic_stats import load_stats, get_stats
from config.settings import DATABASE_FILE


# ============================================================
# Project paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORT_FILE = REPORTS_DIR / "nid_tms_security_report.txt"

TRAFFIC_KEYS = (
    "total_packets",
    "ipv4_packets",
    "ipv6_packets",
    "tcp_packets",
    "udp_packets",
    "icmp_packets",
    "icmpv6_packets",
    "other_packets",
    "total_bytes",
)


# ============================================================
# Traffic statistics
# ============================================================

def load_session_traffic():
    """Load packet statistics for the current capture session."""

    try:
        stats = load_stats()
        return {
            key: int(stats.get(key, 0) or 0)
            for key in TRAFFIC_KEYS
        }

    except (OSError, ValueError, TypeError) as error:
        print(f"Warning: Could not load session traffic: {error}")
        return {key: 0 for key in TRAFFIC_KEYS}


def load_lifetime_traffic():
    """Load lifetime traffic statistics from SQLite."""

    try:
        stats = get_stats()
        return {
            key: int(stats.get(key, 0) or 0)
            for key in TRAFFIC_KEYS
        }

    except (sqlite3.Error, OSError, ValueError, TypeError) as error:
        print(f"Warning: Could not load lifetime traffic: {error}")
        return {key: 0 for key in TRAFFIC_KEYS}


# ============================================================
# Alert records
# ============================================================

def load_alerts():
    """Load alerts from SQLite and recalculate their risk scores."""

    if not DATABASE_FILE.exists():
        print("Warning: Alert database does not exist.")
        return []

    query = """
        SELECT
            id,
            timestamp,
            severity,
            alert_type,
            source_ip,
            destination_ip,
            description
        FROM alerts
        ORDER BY id DESC
    """

    try:
        database_uri = (
            f"file:{DATABASE_FILE.as_posix()}?mode=ro"
        )

        with sqlite3.connect(
            database_uri,
            uri=True,
            timeout=10
        ) as connection:

            rows = connection.execute(query).fetchall()

    except sqlite3.Error as error:
        print(f"Warning: Could not read alerts: {error}")
        return []

    alerts = []

    for row in rows:
        (
            alert_id,
            timestamp,
            severity,
            alert_type,
            source_ip,
            destination_ip,
            description,
        ) = row

        severity = str(severity or "LOW").upper()
        alert_type = str(alert_type or "UNKNOWN")
        description = str(description or "")

        # Use the same risk-scoring function as the dashboard.
        risk = calculate_risk_score(
            severity,
            alert_type,
            description,
        )

        alerts.append({
            "id": alert_id,
            "timestamp": timestamp or "",
            "severity": severity,
            "alert_type": alert_type,
            "source_ip": source_ip or "-",
            "destination_ip": destination_ip or "-",
            "description": description,
            "risk": risk,
        })

    return alerts


# ============================================================
# Formatting helpers
# ============================================================

def format_traffic_section(title, traffic):
    """Format one traffic-statistics section."""

    return f"""
{title}
{'-' * len(title)}

Total Packets : {traffic['total_packets']}
IPv4 Packets  : {traffic['ipv4_packets']}
IPv6 Packets  : {traffic['ipv6_packets']}
TCP Packets   : {traffic['tcp_packets']}
UDP Packets   : {traffic['udp_packets']}
ICMP Packets  : {traffic['icmp_packets']}
ICMPv6 Packets: {traffic['icmpv6_packets']}
Other Packets : {traffic['other_packets']}
Total Bytes   : {traffic['total_bytes']:,}
"""


# ============================================================
# Generate security report
# ============================================================

def generate_report():

    session_traffic = load_session_traffic()
    lifetime_traffic = load_lifetime_traffic()
    alerts = load_alerts()

    total_alerts = len(alerts)

    # Match the dashboard's severity-counting logic.
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

        try:
            risk_values.append(float(alert["risk"]))
        except (TypeError, ValueError, OverflowError):
            pass

    # Match the dashboard's average-risk calculation.
    average_risk = (
        round(sum(risk_values) / len(risk_values))
        if risk_values
        else 0
    )

    # Preserve original alert types from SQLite.
    alert_type_counts = Counter(
        alert["alert_type"]
        for alert in alerts
    )

    generated_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    report = f"""
============================================================
NID-TMS SECURITY REPORT
Network Intrusion Detection & Real-Time Traffic Monitoring
============================================================

Report Generated: {generated_time}


============================================================
1. CURRENT SESSION TRAFFIC STATISTICS
============================================================
"""

    report += format_traffic_section(
        "Current Capture Session",
        session_traffic,
    )

    report += """
============================================================
2. LIFETIME NETWORK TRAFFIC STATISTICS
============================================================
"""

    report += format_traffic_section(
        "Lifetime Database Statistics",
        lifetime_traffic,
    )

    report += f"""
============================================================
3. SECURITY ALERT SUMMARY
============================================================

Total Alerts       : {total_alerts}
HIGH Severity      : {severity_counts['HIGH']}
MEDIUM Severity    : {severity_counts['MEDIUM']}
LOW Severity       : {severity_counts['LOW']}
CRITICAL Severity  : {severity_counts['CRITICAL']}

Average Alert Risk : {average_risk}/100


============================================================
4. ALERT TYPE SUMMARY
============================================================

"""

    if alert_type_counts:
        for alert_type, count in sorted(
            alert_type_counts.items(),
            key=lambda item: (-item[1], item[0].lower()),
        ):
            report += f"{alert_type:<25}: {count}\n"
    else:
        report += "No alert types recorded.\n"

    report += """
============================================================
5. TEN MOST RECENT ALERTS
============================================================

"""

    recent_alerts = alerts[:10]

    if not recent_alerts:
        report += "No alerts recorded.\n"

    else:
        for index, alert in enumerate(
            recent_alerts,
            start=1,
        ):
            report += (
                f"{index}. Alert ID: {alert['id']}\n"
                f"   Timestamp   : {alert['timestamp']}\n"
                f"   Severity    : {alert['severity']}\n"
                f"   Alert Type  : {alert['alert_type']}\n"
                f"   Source IP   : {alert['source_ip']}\n"
                f"   Dest. IP    : {alert['destination_ip']}\n"
                f"   Risk Score  : {alert['risk']}/100\n"
                f"   Description : {alert['description']}\n\n"
            )

    report += """
============================================================
6. REPORT NOTES
============================================================

- Current-session traffic represents the active or most
  recently saved capture session.
- Lifetime traffic is calculated from stored SQLite records.
- Alert risk scores are recalculated using the shared
  NID-TMS risk-scoring function.
- Test alerts are included in alert totals and averages.
- An alert indicates suspicious activity for investigation;
  it does not by itself prove that an attack occurred.

============================================================
END OF REPORT
============================================================
"""

    # Save the generated report.
    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with REPORT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        file.write(report)

    print("=" * 60)
    print("NID-TMS SECURITY REPORT")
    print("=" * 60)
    print(report)
    print("Report saved to:")
    print(REPORT_FILE)


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    generate_report()

