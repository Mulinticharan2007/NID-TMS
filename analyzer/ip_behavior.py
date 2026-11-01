
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import IP, TCP, UDP

from config.settings import (
    IP_BEHAVIOR_WINDOW_SECONDS,
    IP_PACKET_RATE_THRESHOLD,
    IP_UNIQUE_PORT_THRESHOLD,
    IP_UNIQUE_DESTINATION_THRESHOLD,
    IP_BEHAVIOR_ALERT_COOLDOWN_SECONDS,
)

from alerts.alert_manager import save_alert as save_log_alert
from database.database_manager import save_alert as save_database_alert


class IPBehaviorAnalyzer:
    """Detect unusual packet rates, port scans and host scans by source IP."""

    def __init__(
        self,
        window_seconds=IP_BEHAVIOR_WINDOW_SECONDS,
        packet_rate_threshold=IP_PACKET_RATE_THRESHOLD,
        unique_port_threshold=IP_UNIQUE_PORT_THRESHOLD,
        unique_destination_threshold=IP_UNIQUE_DESTINATION_THRESHOLD,
        cooldown_seconds=IP_BEHAVIOR_ALERT_COOLDOWN_SECONDS,
    ):
        self.window_seconds = window_seconds
        self.packet_rate_threshold = packet_rate_threshold
        self.unique_port_threshold = unique_port_threshold
        self.unique_destination_threshold = unique_destination_threshold
        self.cooldown_seconds = cooldown_seconds

        # Each observation: (timestamp, destination IP, destination port)
        self.observations = defaultdict(deque)

        # Last alert time for each (source IP, alert type).
        self.last_alert_times = {}

        # Keep generated alerts available for inspection.
        self.generated_alerts = []

    def _remove_expired(self, source_ip, current_time):
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        events = self.observations[source_ip]

        while events and events[0][0] < cutoff:
            events.popleft()

        if not events:
            self.observations.pop(source_ip, None)

    def _get_destination_port(self, packet):
        if TCP in packet:
            return int(packet[TCP].dport)

        if UDP in packet:
            return int(packet[UDP].dport)

        return None

    def _send_alert(
        self,
        severity,
        alert_type,
        source_ip,
        destination_ip,
        description,
        risk_score,
        current_time,
    ):
        key = (source_ip, alert_type)
        last_alert = self.last_alert_times.get(key)

        if last_alert is not None:
            elapsed = (current_time - last_alert).total_seconds()

            if elapsed < self.cooldown_seconds:
                return False

        self.last_alert_times[key] = current_time

        alert_data = {
            "severity": severity,
            "alert_type": alert_type,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "description": description,
            "risk_score": risk_score,
        }
        self.generated_alerts.append(alert_data)

        save_log_alert(severity, description)

        save_database_alert(
            severity,
            alert_type,
            source_ip,
            destination_ip,
            description,
            risk_score,
            f"{alert_type}:{source_ip}",
        )

        return True

    def process_packet(self, packet, current_time=None):
        """Analyse one Scapy packet. Returns the alerts generated for it."""

        if IP not in packet:
            return []

        if current_time is None:
            current_time = datetime.now()

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        destination_port = self._get_destination_port(packet)

        self._remove_expired(source_ip, current_time)

        self.observations[source_ip].append(
            (current_time, destination_ip, destination_port)
        )

        events = self.observations[source_ip]

        packet_count = len(events)
        unique_ports = {
            port for _, _, port in events if port is not None
        }
        unique_destinations = {
            destination for _, destination, _ in events
        }

        generated_before = len(self.generated_alerts)

        # 1. High packet-rate detection.
        if packet_count >= self.packet_rate_threshold:
            self._send_alert(
                "HIGH",
                "High Packet Rate",
                source_ip,
                destination_ip,
                (
                    f"High packet rate detected from {source_ip}: "
                    f"{packet_count} packets within "
                    f"{self.window_seconds} seconds"
                ),
                30,
                current_time,
            )

        # 2. Unique destination-port detection.
        if len(unique_ports) >= self.unique_port_threshold:
            self._send_alert(
                "HIGH",
                "Port Scan Behaviour",
                source_ip,
                destination_ip,
                (
                    f"Possible port scanning detected from {source_ip}: "
                    f"{len(unique_ports)} unique destination ports "
                    f"within {self.window_seconds} seconds"
                ),
                40,
                current_time,
            )

        # 3. Unique destination-IP detection.
        if len(unique_destinations) >= self.unique_destination_threshold:
            self._send_alert(
                "MEDIUM",
                "Host Scan Behaviour",
                source_ip,
                destination_ip,
                (
                    f"Possible host scanning detected from {source_ip}: "
                    f"{len(unique_destinations)} unique destination IPs "
                    f"within {self.window_seconds} seconds"
                ),
                30,
                current_time,
            )

        return self.generated_alerts[generated_before:]

    def get_source_statistics(self, source_ip):
        """Return current statistics for a source IP."""

        events = self.observations.get(source_ip, deque())

        return {
            "source_ip": source_ip,
            "packet_count": len(events),
            "unique_destination_ports": len({
                port for _, _, port in events if port is not None
            }),
            "unique_destination_ips": len({
                destination for _, destination, _ in events
            }),
        }
