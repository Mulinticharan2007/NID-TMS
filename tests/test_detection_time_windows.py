
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
