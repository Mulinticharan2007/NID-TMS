
from datetime import datetime, timedelta

import pytest
from scapy.all import IP, TCP, UDP, Ether, ARP

import analyzer.ip_behavior as ip_behavior
from analyzer.ip_behavior import IPBehaviorAnalyzer


@pytest.fixture
def analyzer(monkeypatch):
    # Prevent tests from writing to the real alert log or database.
    monkeypatch.setattr(
        ip_behavior,
        "save_log_alert",
        lambda severity, message: None,
    )
    monkeypatch.setattr(
        ip_behavior,
        "save_database_alert",
        lambda *args, **kwargs: None,
    )

    return IPBehaviorAnalyzer(
        window_seconds=10,
        packet_rate_threshold=3,
        unique_port_threshold=3,
        unique_destination_threshold=3,
        cooldown_seconds=30,
    )


def test_non_ip_packet_is_ignored(analyzer):
    packet = Ether() / ARP()

    result = analyzer.process_packet(packet)

    assert result == []
    assert len(analyzer.generated_alerts) == 0


def test_normal_packet_does_not_trigger_alert(analyzer):
    packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
        dport=80
    )

    result = analyzer.process_packet(packet)

    assert result == []
    assert len(analyzer.generated_alerts) == 0


def test_high_packet_rate_triggers_alert(analyzer):
    now = datetime(2026, 1, 1, 12, 0, 0)

    for _ in range(3):
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
            dport=80
        )
        result = analyzer.process_packet(packet, current_time=now)

    assert any(
        alert["alert_type"] == "High Packet Rate"
        for alert in analyzer.generated_alerts
    )


def test_multiple_ports_trigger_port_scan_alert(analyzer):
    now = datetime(2026, 1, 1, 12, 0, 0)

    for port in (22, 80, 443):
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
            dport=port
        )
        analyzer.process_packet(packet, current_time=now)

    assert any(
        alert["alert_type"] == "Port Scan Behaviour"
        for alert in analyzer.generated_alerts
    )


def test_multiple_destinations_trigger_host_scan_alert(analyzer):
    now = datetime(2026, 1, 1, 12, 0, 0)

    for destination in (
        "192.168.1.20",
        "192.168.1.21",
        "192.168.1.22",
    ):
        packet = IP(
            src="192.168.1.10",
            dst=destination,
        ) / UDP(dport=53)

        analyzer.process_packet(packet, current_time=now)

    assert any(
        alert["alert_type"] == "Host Scan Behaviour"
        for alert in analyzer.generated_alerts
    )


def test_cooldown_prevents_repeated_alerts(analyzer):
    now = datetime(2026, 1, 1, 12, 0, 0)

    for _ in range(3):
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
            dport=80
        )
        analyzer.process_packet(packet, current_time=now)

    first_count = sum(
        alert["alert_type"] == "High Packet Rate"
        for alert in analyzer.generated_alerts
    )

    for _ in range(3):
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
            dport=80
        )
        analyzer.process_packet(
            packet,
            current_time=now + timedelta(seconds=5),
        )

    second_count = sum(
        alert["alert_type"] == "High Packet Rate"
        for alert in analyzer.generated_alerts
    )

    assert first_count == 1
    assert second_count == 1


def test_expired_packets_are_removed(analyzer):
    now = datetime(2026, 1, 1, 12, 0, 0)

    first_packet = IP(
        src="192.168.1.10",
        dst="192.168.1.20",
    ) / TCP(dport=80)

    analyzer.process_packet(first_packet, current_time=now)

    later_packet = IP(
        src="192.168.1.10",
        dst="192.168.1.21",
    ) / TCP(dport=443)

    analyzer.process_packet(
        later_packet,
        current_time=now + timedelta(seconds=11),
    )

    stats = analyzer.get_source_statistics("192.168.1.10")

    assert stats["packet_count"] == 1
    assert stats["unique_destination_ips"] == 1
    assert stats["unique_destination_ports"] == 1
