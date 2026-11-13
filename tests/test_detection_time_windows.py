
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import IP, TCP, ICMP

from analyzer import intrusion_detector as detector


def test_icmp_observations_expire_after_window(monkeypatch):
    fake_time = [datetime(2026, 1, 1, 12, 0, 0)]

    class FakeDateTime:
        @staticmethod
        def now():
            return fake_time[0]

    monkeypatch.setattr(detector, "datetime", FakeDateTime)
    monkeypatch.setattr(detector, "icmp_packets", defaultdict(deque))

    observations = detector.icmp_packets["192.0.2.10"]
    observations.append(fake_time[0] - timedelta(seconds=11))
    observations.append(fake_time[0])

    detector.remove_expired(
        observations,
        fake_time[0] - timedelta(seconds=detector.ICMP_WINDOW_SECONDS),
    )

    assert len(observations) == 1


def test_syn_observations_expire_after_window(monkeypatch):
    fake_time = [datetime(2026, 1, 1, 12, 0, 0)]

    class FakeDateTime:
        @staticmethod
        def now():
            return fake_time[0]

    monkeypatch.setattr(detector, "datetime", FakeDateTime)
    monkeypatch.setattr(detector, "syn_attempts", defaultdict(deque))

    connection = ("192.0.2.10", "198.51.100.20", 443)
    observations = detector.syn_attempts[connection]

    observations.append(fake_time[0] - timedelta(seconds=11))
    observations.append(fake_time[0])

    detector.remove_expired(
        observations,
        fake_time[0] - timedelta(seconds=detector.SYN_WINDOW_SECONDS),
    )

    assert len(observations) == 1

def test_port_scan_observations_are_cleaned_during_finalization(monkeypatch):
    fake_time = [datetime(2026, 1, 1, 12, 0, 0)]

    class FakeDateTime:
        @staticmethod
        def now():
            return fake_time[0]

    monkeypatch.setattr(detector, "datetime", FakeDateTime)

    monkeypatch.setattr(
        detector,
        "analyze_syn_anomalies",
        lambda: None,
    )

    monkeypatch.setattr(
        detector,
        "port_scan_tracker",
        defaultdict(
            deque,
            {
                ("192.0.2.10", "198.51.100.20"): deque([
                    (
                        fake_time[0]
                        - timedelta(
                            seconds=detector.PORT_SCAN_WINDOW_SECONDS + 1
                        ),
                        443,
                    )
                ]),
                ("192.0.2.11", "198.51.100.21"): deque([
                    (fake_time[0], 80)
                ]),
            },
        ),
    )

    expired_key = ("192.0.2.10", "198.51.100.20")
    active_key = ("192.0.2.11", "198.51.100.21")

    monkeypatch.setattr(
        detector,
        "port_scan_alerted",
        {expired_key, active_key},
    )

    monkeypatch.setattr(detector, "syn_attempts", defaultdict(deque))
    monkeypatch.setattr(detector, "syn_ack_responses", defaultdict(deque))
    monkeypatch.setattr(detector, "icmp_packets", defaultdict(deque))
    monkeypatch.setattr(detector, "icmp_alerted", set())

    detector.finalize_detection()

    assert expired_key not in detector.port_scan_tracker
    assert expired_key not in detector.port_scan_alerted

    assert active_key in detector.port_scan_tracker
    assert active_key in detector.port_scan_alerted