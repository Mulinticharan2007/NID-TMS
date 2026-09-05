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
            description TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()

    print("Database created successfully.")


def save_alert(severity, alert_type, source_ip, destination_ip, description):
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO alerts
        (timestamp, severity, alert_type, source_ip, destination_ip, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        severity,
        alert_type,
        source_ip,
        destination_ip,
        description
    ))

    connection.commit()
    connection.close()

    print("Alert saved to database.")


def get_alerts():
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, timestamp, severity, alert_type,
               source_ip, destination_ip, description
        FROM alerts
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts


if __name__ == "__main__":
    create_database()

    save_alert(
        "MEDIUM",
        "TEST",
        "10.78.17.163",
        "162.159.198.2",
        "NID-TMS database integration test."
    )