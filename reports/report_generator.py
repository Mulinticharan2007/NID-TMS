from pathlib import Path
from datetime import datetime
import json
import re


# ============================================================
# Project paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TRAFFIC_STATS_FILE = (
    PROJECT_ROOT
    / "database"
    / "traffic_stats.json"
)

ALERTS_FILE = (
    PROJECT_ROOT
    / "alerts"
    / "security_alerts.log"
)

REPORTS_DIR = PROJECT_ROOT / "reports"


# ============================================================
# Read traffic statistics
# ============================================================

def load_traffic_stats():

    if not TRAFFIC_STATS_FILE.exists():

        return {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "total_bytes": 0
        }

    with open(
        TRAFFIC_STATS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# Read alerts
# ============================================================

def load_alerts():

    alerts = []

    if not ALERTS_FILE.exists():
        return alerts

    with open(
        ALERTS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        lines = [
            line.strip()
            for line in file
            if line.strip()
        ]

    for line in lines:

        match = re.match(
            r"\[(.*?)\]\s+\[(.*?)\]\s+(.*)",
            line
        )

        if not match:
            continue

        timestamp = match.group(1)
        severity = match.group(2).upper()
        description = match.group(3)

        if "Port Scan" in description:
            alert_type = "Port Scan"

        elif "SYN" in description:
            alert_type = "SYN Anomaly"

        elif "ICMP" in description:
            alert_type = "ICMP Traffic"

        elif "test" in description.lower():
            alert_type = "System Test"

        else:
            alert_type = "Other"

        alerts.append({
            "timestamp": timestamp,
            "severity": severity,
            "alert_type": alert_type,
            "description": description
        })

    return alerts


# ============================================================
# Generate report
# ============================================================

def generate_report():

    traffic = load_traffic_stats()
    alerts = load_alerts()

    total_alerts = len(alerts)

    high_alerts = sum(
        alert["severity"] == "HIGH"
        for alert in alerts
    )

    medium_alerts = sum(
        alert["severity"] == "MEDIUM"
        for alert in alerts
    )

    low_alerts = sum(
        alert["severity"] == "LOW"
        for alert in alerts
    )

    port_scan_alerts = sum(
        alert["alert_type"] == "Port Scan"
        for alert in alerts
    )

    syn_alerts = sum(
        alert["alert_type"] == "SYN Anomaly"
        for alert in alerts
    )

    icmp_alerts = sum(
        alert["alert_type"] == "ICMP Traffic"
        for alert in alerts
    )

    test_alerts = sum(
        alert["alert_type"] == "System Test"
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

Report Generated:
{generated_time}


------------------------------------------------------------
NETWORK TRAFFIC STATISTICS
------------------------------------------------------------

Total Packets : {traffic.get("total_packets", 0)}
TCP Packets   : {traffic.get("tcp_packets", 0)}
UDP Packets   : {traffic.get("udp_packets", 0)}
ICMP Packets  : {traffic.get("icmp_packets", 0)}
Total Bytes   : {traffic.get("total_bytes", 0)}


------------------------------------------------------------
SECURITY ALERT SUMMARY
------------------------------------------------------------

Total Alerts  : {total_alerts}

High Severity   : {high_alerts}
Medium Severity : {medium_alerts}
Low Severity    : {low_alerts}


------------------------------------------------------------
ALERT TYPE SUMMARY
------------------------------------------------------------

Port Scan Alerts  : {port_scan_alerts}
SYN Anomaly Alerts: {syn_alerts}
ICMP Alerts       : {icmp_alerts}
System Test Alerts: {test_alerts}


------------------------------------------------------------
RECENT ALERTS
------------------------------------------------------------

"""

    recent_alerts = alerts[-10:]

    if not recent_alerts:

        report += "No alerts recorded.\n"

    else:

        for index, alert in enumerate(
            recent_alerts,
            start=1
        ):

            report += (
                f"{index}. "
                f"[{alert['timestamp']}] "
                f"[{alert['severity']}] "
                f"{alert['alert_type']} - "
                f"{alert['description']}\n"
            )


    report += """

------------------------------------------------------------
END OF REPORT
------------------------------------------------------------
"""


    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report_file = (
        REPORTS_DIR
        / "nid_tms_security_report.txt"
    )

    with open(
        report_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(report)

    print("=" * 60)
    print("NID-TMS SECURITY REPORT")
    print("=" * 60)

    print()
    print(report)

    print(
        "Report saved to:"
    )

    print(report_file)


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    generate_report()