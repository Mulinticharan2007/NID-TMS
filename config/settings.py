from pathlib import Path


# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent


# Database
DATABASE_FILE = BASE_DIR / "database" / "nid_tms.db"


# Alert log
ALERT_FILE = BASE_DIR / "alerts" / "security_alerts.log"


# Monitoring
CAPTURE_TIMEOUT = 10


# Detection thresholds
PORT_SCAN_THRESHOLD = 10
ICMP_THRESHOLD = 20
SYN_THRESHOLD = 10
SUSPICIOUS_CONNECTION_THRESHOLD = 10
PORT_SCAN_WINDOW_SECONDS = 10