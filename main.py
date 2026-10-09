from fastapi import FastAPI
from fastapi.responses import FileResponse
from pathlib import Path
import json
import re

app = FastAPI(
    title="NID-TMS",
    description="Network Intrusion Detection & Real-Time Traffic Monitoring System"
)

BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_FILE = BASE_DIR / "dashboard" / "index.html"
TRAFFIC_STATS_FILE = BASE_DIR / "database" / "traffic_stats.json"
ALERTS_FILE = BASE_DIR / "alerts" / "security_alerts.log"


def read_alerts():
    alert_list = []

    if not ALERTS_FILE.exists():
        return alert_list

    with open(ALERTS_FILE, "r", encoding="utf-8") as file:
        lines = [line.strip() for line in file if line.strip()]

    for alert_id, line in enumerate(lines, start=1):

        match = re.match(
            r"\[(.*?)\]\s+\[(.*?)\]\s+(.*)",
            line
        )

        if not match:
            continue

        timestamp = match.group(1)
        severity = match.group(2).upper()
        description = match.group(3)

        # Determine alert type
        if "Port Scan" in description:
            alert_type = "Port Scan"
        elif "SYN" in description:
            alert_type = "SYN Anomaly"
        elif "ICMP" in description:
            alert_type = "ICMP Traffic"
        elif "integration test" in description.lower():
            alert_type = "System Test"
        elif "system test" in description.lower():
            alert_type = "System Test"
        elif "pipeline test" in description.lower():
            alert_type = "System Test"
        else:
            alert_type = "Alert"

        # Default values
        source_ip = "-"
        destination_ip = "-"
        risk = 10

        # Extract IP addresses from descriptions containing "A -> B"
        ip_match = re.search(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})",
            description
        )

        if ip_match:
            source_ip = ip_match.group(1)
            destination_ip = ip_match.group(2)

        # Risk based on severity
        if severity == "HIGH":
            risk = 100
        elif severity == "MEDIUM":
            risk = 50
        elif severity == "LOW":
            risk = 10

        alert_list.append({
            "id": alert_id,
            "timestamp": timestamp,
            "severity": severity,
            "alert_type": alert_type,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "description": description,
            "risk": risk
        })

    return alert_list


@app.get("/")
def dashboard():
    return FileResponse(DASHBOARD_FILE)


@app.get("/stats")
def stats():
    alerts = read_alerts()

    high_alerts = sum(
        alert["severity"] == "HIGH"
        for alert in alerts
    )

    medium_alerts = sum(
        alert["severity"] == "MEDIUM"
        for alert in alerts
    )

    risk_score = min((high_alerts * 10) + (medium_alerts * 5), 100)

    return {
        "total_alerts": len(alerts),
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "risk_score": risk_score
    }


@app.get("/traffic")
def traffic():
    if not TRAFFIC_STATS_FILE.exists():
        return {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "total_bytes": 0
        }

    with open(TRAFFIC_STATS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


@app.get("/alerts")
def alerts():
    return {
        "alerts": read_alerts()
    }


if __name__ == "__main__":
    print("======================================")
    print("NID-TMS")
    print("Network Intrusion Detection &")
    print("Real-Time Traffic Monitoring System")
    print("======================================")
    print("Project environment is working!")