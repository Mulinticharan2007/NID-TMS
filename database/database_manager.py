import sqlite3
from datetime import datetime

DATABASE_FILE = "database/nid_tms.db"


def create_database():

    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            description TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            correlation_key TEXT
        )
    """)

    connection.commit()
    connection.close()

    print("Database initialized successfully.")


def save_alert(
    severity,
    alert_type,
    source_ip,
    destination_ip,
    description,
    risk_score=0,
    correlation_key=None
):

    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO alerts
        (
            timestamp,
            severity,
            alert_type,
            source_ip,
            destination_ip,
            description,
            risk_score,
            correlation_key
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        severity,
        alert_type,
        source_ip,
        destination_ip,
        description,
        risk_score,
        correlation_key
    ))

    connection.commit()
    connection.close()

    print("Alert saved to database.")


def get_alerts():

    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            severity,
            alert_type,
            source_ip,
            destination_ip,
            description,
            risk_score,
            correlation_key
        FROM alerts
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts