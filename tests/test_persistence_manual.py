from pathlib import Path
import sys
import sqlite3
import uuid

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from alerts.alert_manager import save_alert as save_log_alert
from database.database_manager import save_alert as save_db_alert

log_path = PROJECT_ROOT / "alerts" / "security_alerts.log"
db_path = PROJECT_ROOT / "database" / "nid_tms.db"

test_id = "PERSISTENCE_TEST_" + uuid.uuid4().hex
description = f"NID-TMS persistence verification: {test_id}"

db_row_id = None
test_passed = False

try:
    save_log_alert("LOW", description)

    save_db_alert(
        "LOW",
        "Persistence Test",
        "TEST_SOURCE",
        "TEST_DESTINATION",
        description,
        0,
        test_id
    )

    with log_path.open("r", encoding="utf-8-sig") as file:
        log_ok = description in file.read()

    with sqlite3.connect(db_path) as con:
        row = con.execute(
            """
            SELECT id, description, correlation_key
            FROM alerts
            WHERE correlation_key = ? AND description = ?
            ORDER BY id DESC LIMIT 1
            """,
            (test_id, description)
        ).fetchone()

        if row:
            db_row_id = row[0]
            db_ok = row[1] == description and row[2] == test_id
        else:
            db_ok = False

    print("Text log persistence:", "PASS" if log_ok else "FAIL")
    print("SQLite persistence:", "PASS" if db_ok else "FAIL")
    test_passed = log_ok and db_ok

finally:
    if db_row_id is not None:
        with sqlite3.connect(db_path) as con:
            con.execute(
                "DELETE FROM alerts WHERE id = ? AND correlation_key = ?",
                (db_row_id, test_id)
            )
        print("Temporary test database row cleaned up.")

print("Existing alerts preserved.")
print("Overall result:", "PASS" if test_passed else "FAIL")
