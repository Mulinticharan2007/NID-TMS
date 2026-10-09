from fastapi import FastAPI
from fastapi.responses import FileResponse
from pathlib import Path
import sys

sys.path.append(
    str(Path(__file__).resolve().parent.parent)
)

from database.database_manager import get_alerts
from analyzer.traffic_stats import get_stats

app = FastAPI(
    title="NID-TMS Professional Dashboard"
)

BASE_DIR = Path(__file__).resolve().parent


@app.get("/")
def dashboard():
    return FileResponse(
        BASE_DIR / "index.html"
    )


@app.get("/alerts")
def alerts():
    return {
        "alerts": get_alerts()
    }


@app.get("/stats")
def statistics():

    alerts_data = get_alerts()

    total_alerts = len(alerts_data)

    high_alerts = sum(
        1
        for alert in alerts_data
        if alert[2] == "HIGH"
    )

    medium_alerts = sum(
        1
        for alert in alerts_data
        if alert[2] == "MEDIUM"
    )

    total_risk_score = sum(
        alert[7]
        for alert in alerts_data
        if len(alert) > 7 and alert[7] is not None
    )

    return {
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "risk_score": total_risk_score
    }


@app.get("/traffic")
def traffic_statistics():

    return get_stats()


@app.get("/health")
def health():

    return {
        "status": "NID-TMS dashboard is running"
    }
