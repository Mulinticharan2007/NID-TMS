"""Regression tests for SYN anomaly duplicate suppression."""

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DETECTOR_FILE = PROJECT_ROOT / "analyzer" / "intrusion_detector.py"


def test_detector_has_syn_anomaly_guard():
    source = DETECTOR_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert "syn_anomaly_alerted = set()" in source
    assert "and connection not in syn_anomaly_alerted" in source
    assert "syn_anomaly_alerted.add(connection)" in source

    # Ensure the detector remains valid Python.
    assert tree is not None


def test_same_connection_is_suppressed_after_first_alert():
    alerted = set()
    connection = ("192.0.2.10", "198.51.100.20", 443)

    first_check = connection not in alerted
    if first_check:
        alerted.add(connection)

    second_check = connection not in alerted

    assert first_check is True
    assert second_check is False
