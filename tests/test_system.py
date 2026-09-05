from pathlib import Path
import sys
import sqlite3

# Add the NID-TMS project root to Python's path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from alerts.alert_manager import save_alert
from database.database_manager import create_database, get_alerts


print("=" * 70)
print("NID-TMS - SYSTEM TEST")
print("=" * 70)


# Test 1 - Database
print("\n[TEST 1] Database")

create_database()

database_file = Path("database/nid_tms.db")

if database_file.exists():
    print("PASS - Database exists")
else:
    print("FAIL - Database not found")


# Test 2 - Alerts Table
print("\n[TEST 2] Alerts Table")

connection = sqlite3.connect(database_file)
cursor = connection.cursor()

cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type='table'
    AND name='alerts'
""")

table = cursor.fetchone()

connection.close()

if table:
    print("PASS - Alerts table exists")
else:
    print("FAIL - Alerts table not found")


# Test 3 - Alert Manager
print("\n[TEST 3] Alert Manager")

save_alert(
    "LOW",
    "NID-TMS automated system test."
)

print("PASS - Alert manager executed")


# Test 4 - Read Alerts
print("\n[TEST 4] Reading Alerts")

alerts = get_alerts()

if len(alerts) > 0:
    print("PASS - Alerts retrieved")
    print("Total alerts:", len(alerts))
else:
    print("FAIL - No alerts found")


print("\n" + "=" * 70)
print("NID-TMS SYSTEM TEST COMPLETED")
print("=" * 70)