
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import IP, TCP

from analyzer import intrusion_detector as detector


def test_port_scan_generates_one_high_alert(monkeypatch):
    # Isolate the test from existing detector tracking state.
    monkeypatch.setattr(
        detector, "port_scan_tracker", defaultdict(deque)
    )
    monkeypatch.setattr(detector, "port_scan_alerted", set())

    generated_alerts = []

    # Capture alerts instead of writing to logs or the database.
    monkeypatch.setattr(
        detector,
        "create_alert",
        lambda *args: generated_alerts.append(args),
    )

    source_ip = "192.0.2.10"
    destination_ip = "198.51.100.20"

    # Create synthetic packets locally; none are transmitted.
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

    # Additional unique ports within the same window should not
    # generate duplicate alerts.
    extra_packet = (
        IP(src=source_ip, dst=destination_ip)
        / TCP(sport=40000, dport=65000, flags="S")
    )
    detector.detect_suspicious(extra_packet)

    assert len(generated_alerts) == 1


def test_new_scan_after_window_can_alert_again(monkeypatch):
    # Isolate detector state.
    monkeypatch.setattr(
        detector, "port_scan_tracker", defaultdict(deque)
    )
    monkeypatch.setattr(detector, "port_scan_alerted", set())

    generated_alerts = []

    monkeypatch.setattr(
        detector,
        "create_alert",
        lambda *args: generated_alerts.append(args),
    )

    # Use a controllable clock instead of waiting in real time.
    fake_time = [datetime(2026, 1, 1, 12, 0, 0)]

    class FakeDateTime:
        @staticmethod
        def now():
            return fake_time[0]

    monkeypatch.setattr(detector, "datetime", FakeDateTime)

    source_ip = "192.0.2.11"
    destination_ip = "198.51.100.21"

    def send_scan(start_port):
        for port in range(
            start_port,
            start_port + detector.PORT_SCAN_THRESHOLD,
        ):
            packet = (
                IP(src=source_ip, dst=destination_ip)
                / TCP(sport=41000, dport=port, flags="S")
            )
            detector.detect_suspicious(packet)

    # First scan should generate one alert.
    send_scan(3000)
    assert len(generated_alerts) == 1

    # Advance beyond the configured observation window.
    fake_time[0] += timedelta(
        seconds=detector.PORT_SCAN_WINDOW_SECONDS + 1
    )

    # The detector should expire old observations and alert again.
    send_scan(4000)

    assert len(generated_alerts) == 2

def test_ack_and_syn_ack_do_not_trigger_port_scan(monkeypatch):
    monkeypatch.setattr(
        detector, "port_scan_tracker", defaultdict(deque)
    )
    monkeypatch.setattr(detector, "port_scan_alerted", set())

    generated_alerts = []
    monkeypatch.setattr(
        detector,
        "create_alert",
        lambda *args: generated_alerts.append(args),
    )

    for port in range(
        2000, 2000 + detector.PORT_SCAN_THRESHOLD
    ):
        for flags in ("A", "SA"):
            packet = (
                IP(src="192.0.2.30", dst="198.51.100.30")
                / TCP(sport=40000, dport=port, flags=flags)
            )
            detector.detect_suspicious(packet)

    assert not any(
        alert[4] == "Port Scan" for alert in generated_alerts
    )


def test_repeated_syn_to_same_port_does_not_trigger_port_scan(
    monkeypatch,
):
    monkeypatch.setattr(
        detector, "port_scan_tracker", defaultdict(deque)
    )
    monkeypatch.setattr(detector, "port_scan_alerted", set())

    generated_alerts = []
    monkeypatch.setattr(
        detector,
        "create_alert",
        lambda *args: generated_alerts.append(args),
    )

    for _ in range(detector.PORT_SCAN_THRESHOLD):
        packet = (
            IP(src="192.0.2.40", dst="198.51.100.40")
            / TCP(sport=40000, dport=443, flags="S")
        )
        detector.detect_suspicious(packet)

    assert not any(
        alert[4] == "Port Scan" for alert in generated_alerts
    )
