
from pathlib import Path
import sys

from fastapi import FastAPI
from fastapi.responses import FileResponse

# Locate the NID-TMS project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.database_manager import get_alerts
from database.traffic_store import get_recent_packets
from analyzer.traffic_stats import get_stats


app = FastAPI(title="NID-TMS Professional Dashboard")

BASE_DIR = Path(__file__).resolve().parent


def alert_to_dict(row):
    """Convert an alert database row into a dashboard-friendly dictionary."""
    return {
        "id": row[0],
        "timestamp": row[1],
        "severity": row[2],
        "alert_type": row[3],
        "source_ip": row[4],
        "destination_ip": row[5],
        "description": row[6],
        "risk": row[7] if row[7] is not None else 0,
        "correlation_key": row[8] if len(row) > 8 else None,
    }


@app.get("/")
def dashboard():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/health")
def health():
    return {
        "status": "NID-TMS dashboard is running"
    }


@app.get("/alerts")
def alerts():
    rows = get_alerts()

    return {
        "alerts": [alert_to_dict(row) for row in rows]
    }


@app.get("/stats")
def statistics():
    rows = get_alerts()
    alerts_data = [alert_to_dict(row) for row in rows]

    high_alerts = sum(
        1 for alert in alerts_data
        if str(alert["severity"]).upper() == "HIGH"
    )

    medium_alerts = sum(
        1 for alert in alerts_data
        if str(alert["severity"]).upper() == "MEDIUM"
    )

    low_alerts = sum(
        1 for alert in alerts_data
        if str(alert["severity"]).upper() == "LOW"
    )

    risk_scores = [
        max(0, min(100, int(alert["risk"])))
        for alert in alerts_data
        if alert["risk"] is not None
    ]

    return {
        "total_alerts": len(alerts_data),
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "risk_score": max(risk_scores, default=0),
        "total_risk_score": sum(risk_scores),
    }


@app.get("/traffic")
def traffic_statistics():
    return {
        "stats": get_stats(),
        "traffic": get_recent_packets(100),
    }