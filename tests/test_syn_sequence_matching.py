from collections import defaultdict, deque
from datetime import datetime

from scapy.all import IP, TCP

from analyzer import intrusion_detector as detector


def prepare_detector(monkeypatch):
    fake_time = [datetime(2026, 1, 1, 12, 0, 0)]
    captured_alerts = []

    class FakeDateTime:
        @staticmethod
        def now():
            return fake_time[0]

    monkeypatch.setattr(detector, "datetime", FakeDateTime)
    monkeypatch.setattr(detector, "syn_attempts", defaultdict(deque))
    monkeypatch.setattr(detector, "syn_ack_responses", defaultdict(deque))
    monkeypatch.setattr(detector, "syn_anomaly_alerted", set())
    monkeypatch.setattr(detector, "port_scan_tracker", defaultdict(deque))
    monkeypatch.setattr(detector, "port_scan_alerted", set())
    monkeypatch.setattr(
        detector,
        "create_alert",
        lambda *args: captured_alerts.append(args),
    )

    return captured_alerts


def make_syn(source_port, sequence):
    return (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=source_port, dport=443, flags="S", seq=sequence)
    )


def make_syn_ack(destination_port, acknowledgement):
    return (
        IP(src="198.51.100.20", dst="192.0.2.10")
        / TCP(
            sport=443,
            dport=destination_port,
            flags="SA",
            seq=5000,
            ack=acknowledgement,
        )
    )


def test_correct_syn_ack_responses_are_matched(monkeypatch):
    captured_alerts = prepare_detector(monkeypatch)

    for index in range(10):
        sequence = 1000 + (index * 100)

        detector.detect_suspicious(make_syn(40000, sequence))
        detector.detect_suspicious(make_syn_ack(40000, sequence + 1))

    detector.analyze_syn_anomalies()

    assert not captured_alerts


def test_incorrect_syn_ack_acknowledgements_are_not_matched(monkeypatch):
    captured_alerts = prepare_detector(monkeypatch)

    for index in range(10):
        sequence = 2000 + (index * 100)

        detector.detect_suspicious(make_syn(41000, sequence))
        detector.detect_suspicious(make_syn_ack(41000, sequence + 2))

    detector.analyze_syn_anomalies()

    assert len(captured_alerts) == 1
    assert captured_alerts[0][0] == "MEDIUM"
    assert captured_alerts[0][4] == "SYN Anomaly"


def test_duplicate_syn_ack_is_counted_only_once(monkeypatch):
    captured_alerts = prepare_detector(monkeypatch)

    first_sequence = 3000

    for index in range(11):
        sequence = 3000 + (index * 100)
        detector.detect_suspicious(make_syn(42000, sequence))

    for _ in range(10):
        detector.detect_suspicious(
            make_syn_ack(42000, first_sequence + 1)
        )

    detector.analyze_syn_anomalies()

    assert len(captured_alerts) == 1
    assert captured_alerts[0][4] == "SYN Anomaly"


def test_retransmitted_syn_with_same_sequence_is_counted_once(monkeypatch):
    captured_alerts = prepare_detector(monkeypatch)

    packet = make_syn(43000, 4000)

    for _ in range(10):
        detector.detect_suspicious(packet)

    detector.analyze_syn_anomalies()

    assert not captured_alerts
