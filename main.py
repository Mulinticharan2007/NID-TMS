
from pathlib import Path
import json
import sqlite3
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from database.traffic_store import get_recent_packets


# --------------------------------------------------
# NID-TMS - Network Intrusion Detection & Monitoring
# --------------------------------------------------

app = FastAPI(
    title="NID-TMS",
    description="Network Intrusion Detection and Real-Time Traffic Monitoring System",
    version="1.0.0",
)

BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_FILE = BASE_DIR / "dashboard" / "index.html"
DATABASE_DIR = BASE_DIR / "database"
TRAFFIC_STATS_FILE = DATABASE_DIR / "traffic_stats.json"


# --------------------------------------------------
# Database helpers
# --------------------------------------------------

def discover_databases() -> list[Path]:
    """Find SQLite database files without modifying them."""

    candidates = [
        BASE_DIR / "nid_tms.db",
        DATABASE_DIR / "nid_tms.db",
    ]

    if DATABASE_DIR.exists():
        candidates.extend(sorted(DATABASE_DIR.glob("*.db")))

    if BASE_DIR.exists():
        candidates.extend(sorted(BASE_DIR.glob("*.db")))

    result = []
    seen = set()

    for path in candidates:
        resolved = path.resolve()

        if resolved.is_file() and resolved not in seen:
            seen.add(resolved)
            result.append(resolved)

    return result


def get_database_rows(
    table_names: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Read rows from the first matching SQLite table."""

    for database_path in discover_databases():
        try:
            connection_uri = (
                f"{database_path.as_uri()}?mode=ro"
            )

            with sqlite3.connect(
                connection_uri,
                uri=True,
                timeout=3,
            ) as connection:
                connection.row_factory = sqlite3.Row

                tables = {
                    row["name"]
                    for row in connection.execute(
                        """
                        SELECT name
                        FROM sqlite_master
                        WHERE type = 'table'
                        """
                    ).fetchall()
                }

                for table_name in table_names:
                    if table_name not in tables:
                        continue

                    # Table names come only from this fixed allowlist.
                    rows = connection.execute(
                        f'SELECT * FROM "{table_name}"'
                    ).fetchall()

                    if rows:
                        return [dict(row) for row in rows]

        except (sqlite3.Error, OSError, ValueError):
            continue

    return []


# --------------------------------------------------
# Risk scoring
# --------------------------------------------------

def calculate_risk_score(
    severity: str,
    alert_type: str,
    description: str,
) -> int:
    """Calculate an explainable heuristic risk score."""

    severity_value = str(severity or "").upper()
    type_value = str(alert_type or "").upper()
    description_value = str(description or "").lower()

    # Known test alerts are not treated as real threats.
    if (
        type_value == "TEST"
        or "test" in description_value
    ):
        return 0

    base_scores = {
        "LOW": 25,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 90,
    }

    score = base_scores.get(severity_value, 20)

    # Add a single bonus for port-scan indicators.
    if (
        "port scan" in description_value
        or "port scan" in type_value.lower()
    ):
        score += 10

    # Add a bonus for repeated SYN activity or anomalies.
    if (
        "syn" in description_value
        and any(
            word in description_value
            for word in ("attempt", "flood", "anomaly")
        )
    ):
        score += 10

    if "brute force" in description_value:
        score += 15

    if "malware" in description_value:
        score += 15

    return min(score, 100)


# --------------------------------------------------
# Alert data
# --------------------------------------------------

def get_alerts() -> list[dict[str, Any]]:
    """Load alerts and calculate their current risk scores."""

    rows = get_database_rows(("alerts",))
    alerts = []

    for item in rows:
        severity = str(item.get("severity", "LOW")).upper()
        alert_type = str(
            item.get("alert_type", item.get("type", "UNKNOWN"))
        )
        description = str(item.get("description", ""))

        risk = calculate_risk_score(
            severity,
            alert_type,
            description,
        )

        alerts.append({
            "id": item.get("id"),
            "timestamp": item.get("timestamp", ""),
            "severity": severity,
            "alert_type": alert_type,
            "source_ip": item.get("source_ip", ""),
            "destination_ip": item.get("destination_ip", ""),
            "description": description,
            "risk": risk,
        })

    # Most recent/highest ID first when IDs are numeric.
    alerts.sort(
        key=lambda alert: (
            isinstance(alert.get("id"), int),
            alert.get("id") if isinstance(alert.get("id"), int) else 0,
        ),
        reverse=True,
    )

    return alerts


# --------------------------------------------------
# Traffic records
# --------------------------------------------------

def get_traffic() -> list[dict[str, Any]]:
    """Read any stored packet or traffic records."""

    return get_database_rows((
        "traffic",
        "network_traffic",
        "packets",
        "traffic_logs",
    ))


def load_traffic_stats() -> dict[str, int]:
    """Read totals saved by analyzer/traffic_stats.py."""

    stats = {
        "total_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "icmp_packets": 0,
        "total_bytes": 0,
    }

    if not TRAFFIC_STATS_FILE.is_file():
        return stats

    try:
        with TRAFFIC_STATS_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:
            saved = json.load(file)

        if not isinstance(saved, dict):
            return stats

        for key in stats:
            try:
                value = int(saved.get(key, 0))
                stats[key] = max(0, value)
            except (TypeError, ValueError, OverflowError):
                stats[key] = 0

    except (OSError, json.JSONDecodeError):
        pass

    return stats


# --------------------------------------------------
# Dashboard and health
# --------------------------------------------------

@app.get("/", include_in_schema=False)
def home():
    """Serve the dashboard page."""

    if not DASHBOARD_FILE.is_file():
        return JSONResponse(
            status_code=404,
            content={
                "status": "error",
                "message": "Dashboard file not found.",
                "expected_path": str(DASHBOARD_FILE),
            },
        )

    return FileResponse(DASHBOARD_FILE)


@app.get("/health")
def health():
    """Report API, dashboard, and database availability."""

    return {
        "status": "online",
        "application": "NID-TMS",
        "dashboard_found": DASHBOARD_FILE.is_file(),
        "database_files_found": len(discover_databases()),
    }


# --------------------------------------------------
# API endpoints
# --------------------------------------------------

@app.get("/alerts")
def alerts_endpoint():
    """Return alerts for the dashboard."""

    records = get_alerts()

    return {
        "total": len(records),
        "alerts": records,
    }


@app.get("/traffic")
def traffic_endpoint():
    """Return recent packet metadata and current capture totals."""

    records = get_recent_packets(100)

    return {
        "total": len(records),
        "traffic": records,
        "stats": load_traffic_stats(),
    }


@app.get("/stats")
def stats():
    """Return alert summaries and saved packet-capture totals."""

    alert_records = get_alerts()

    severity_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "critical": 0,
    }

    risk_values = []

    for alert in alert_records:
        severity = str(
            alert.get("severity", "")
        ).lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

        try:
            risk_values.append(float(alert.get("risk", 0)))
        except (TypeError, ValueError, OverflowError):
            pass

    average_risk = (
        round(sum(risk_values) / len(risk_values))
        if risk_values
        else 0
    )

    traffic_stats = load_traffic_stats()

    return {
        "total_alerts": len(alert_records),
        "high_alerts": severity_counts["high"],
        "medium_alerts": severity_counts["medium"],
        "low_alerts": severity_counts["low"],
        "critical_alerts": severity_counts["critical"],
        "risk_score": average_risk,
        **traffic_stats,
    }


# --------------------------------------------------
# Run with:
# python -m uvicorn main:app --host 127.0.0.1 --port 8001
# --------------------------------------------------
