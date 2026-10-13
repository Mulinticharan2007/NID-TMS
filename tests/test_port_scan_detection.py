
from collections import defaultdict, deque

from scapy.all import IP, TCP

from analyzer import intrusion_detector as detector


def test_port_scan_generates_one_high_alert(monkeypatch):
    # Isolate this test from the detector's existing tracking state.
    monkeypatch.setattr(
        detector, "port_scan_tracker", defaultdict(deque)
    )
    monkeypatch.setattr(detector, "port_scan_alerted", set())

    generated_alerts = []

    # Capture the alert instead of writing to the real log or database.
    monkeypatch.setattr(
        detector,
        "create_alert",
        lambda *args: generated_alerts.append(args),
    )

    source_ip = "192.0.2.10"
    destination_ip = "198.51.100.20"

    # Synthetic packets are analyzed locally; none are transmitted.
    for port in range(
        2000, 2000 + detector.PORT_SCAN_THRESHOLD
    ):
        packet = (
            IP(src=source_ip, dst=destination_ip)
            / TCP(sport=40000, dport=port, flags="S")
        )
        detector.detect_suspicious(packet)

    assert len(generated_alerts) == 1

    severity, message, source, destination, alert_type = (
        generated_alerts[0]
    )

    assert severity == "HIGH"
    assert "Possible Port Scan detected" in message
    assert source == source_ip
    assert destination == destination_ip
    assert alert_type == "Port Scan"

    # More ports for the same pair must not create duplicate alerts.
    extra_packet = (
        IP(src=source_ip, dst=destination_ip)
        / TCP(sport=40000, dport=65000, flags="S")
    )
    detector.detect_suspicious(extra_packet)

    assert len(generated_alerts) == 1