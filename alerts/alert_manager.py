from datetime import datetime
import os

ALERT_FILE = "alerts/security_alerts.log"


def save_alert(severity, message):
    os.makedirs("alerts", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = f"[{timestamp}] [{severity}] {message}\n"

    with open(ALERT_FILE, "a", encoding="utf-8") as file:
        file.write(alert)

    print("Alert saved:", alert.strip())


if __name__ == "__main__":
    print("=" * 70)
    print("NID-TMS - ALERT MANAGER")
    print("=" * 70)

    save_alert(
        "LOW",
        "Alert manager test successful."
    )

    print("\nAlert file created successfully.")
    print("Location:", ALERT_FILE)