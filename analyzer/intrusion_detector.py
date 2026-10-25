
from pathlib import Path
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import IP, TCP, ICMP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from config.settings import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    ICMP_THRESHOLD,
    SYN_THRESHOLD,
)

from alerts.alert_manager import save_alert
from database.database_manager import save_alert as save_database_alert


# ============================================================
# Detection tracking
# ============================================================

syn_attempts = Counter()
syn_ack_responses = Counter()
syn_anomaly_alerted = set()

port_scan_tracker = defaultdict(deque)
port_scan_alerted = set()

icmp_packets = Counter()
icmp_alerted = set()

alerts = []
risk_score = 0
correlated_alerts = {}


# ============================================================
# Alert creation
# ============================================================

def create_alert(
    severity,
    message,
    source_ip="Unknown",
    destination_ip="Unknown",
    alert_type="IDS_ALERT",
):
    global risk_score

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = f"[{timestamp}] [{severity}] {message}"
    alerts.append(alert)

    correlation_key = message.split(" detected")[0]
    correlated_alerts[correlation_key] = (
        correlated_alerts.get(correlation_key, 0) + 1
    )

    if severity == "HIGH":
        risk_score += 10
    elif severity == "MEDIUM":
        risk_score += 5
    else:
        risk_score += 1

    print()
    print("ALERT:", alert)

    # Save to the security alert log.
    save_alert(severity, message)

    # Save to SQLite. Existing database and history are preserved.
    save_database_alert(
        severity,
        alert_type,
        source_ip,
        destination_ip,
        message,
        risk_score,
        correlation_key,
    )


# ============================================================
# Packet analysis
# ============================================================

def detect_suspicious(packet):
    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    # ========================================================
    # TCP and port-scan detection
    # ========================================================

    if TCP in packet:
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
        flags = int(packet[TCP].flags)

        # Initial connection attempt: SYN set, ACK unset.
        # Ignore SYN-ACK replies and ordinary TCP traffic.
        is_initial_syn = bool(flags & 0x02) and not bool(flags & 0x10)

        if is_initial_syn:
            scan_target = (source_ip, destination_ip)
            current_time = datetime.now()

            observations = port_scan_tracker[scan_target]
            cutoff_time = current_time - timedelta(
                seconds=PORT_SCAN_WINDOW_SECONDS
            )

            # Expire observations outside the rolling time window.
            while observations and observations[0][0] < cutoff_time:
                observations.popleft()

            # Record destination ports from initial SYN packets only.
            observations.append((current_time, destination_port))

            unique_ports = len({
                port for timestamp, port in observations
            })

            # Permit a future alert after the count falls below threshold.
            if unique_ports < PORT_SCAN_THRESHOLD:
                port_scan_alerted.discard(scan_target)

            if (
                unique_ports >= PORT_SCAN_THRESHOLD
                and scan_target not in port_scan_alerted
            ):
                port_scan_alerted.add(scan_target)

                create_alert(
                    "HIGH",
                    f"Possible Port Scan detected: "
                    f"{source_ip} -> {destination_ip} "
                    f"({unique_ports} unique destination ports "
                    f"within {PORT_SCAN_WINDOW_SECONDS} seconds)",
                    source_ip,
                    destination_ip,
                    "Port Scan",
                )

        # ====================================================
        # SYN detection
        # ====================================================

        # Count initial SYN attempts for SYN-anomaly analysis.
        if flags & 0x02 and not (flags & 0x10):
            connection = (
                source_ip,
                destination_ip,
                destination_port,
            )
            syn_attempts[connection] += 1

        # Match SYN-ACK responses with their original connection.
        elif (flags & 0x02) and (flags & 0x10):
            original_connection = (
                destination_ip,
                source_ip,
                source_port,
            )
            syn_ack_responses[original_connection] += 1

    # ========================================================
    # ICMP detection
    # ========================================================

    elif ICMP in packet:
        icmp_packets[source_ip] += 1
        count = icmp_packets[source_ip]

        # Alert once per source when the threshold is reached.
        if (
            count >= ICMP_THRESHOLD
            and source_ip not in icmp_alerted
        ):
            icmp_alerted.add(source_ip)

            create_alert(
                "MEDIUM",
                f"High ICMP traffic detected from "
                f"{source_ip} ({count} ICMP packets)",
                source_ip,
                destination_ip,
                "ICMP Traffic",
            )


# ============================================================
# SYN anomaly analysis
# ============================================================

def analyze_syn_anomalies():
    for connection, syn_count in syn_attempts.items():
        if syn_count < SYN_THRESHOLD:
            continue

        response_count = syn_ack_responses.get(connection, 0)
        unanswered_syns = max(syn_count - response_count, 0)

        response_ratio = (
            response_count / syn_count
            if syn_count > 0
            else 0
        )

        if (
            unanswered_syns >= SYN_THRESHOLD
            and response_ratio < 0.50
            and connection not in syn_anomaly_alerted
        ):
            syn_anomaly_alerted.add(connection)

            source_ip, destination_ip, destination_port = connection

            create_alert(
                "MEDIUM",
                f"SYN anomaly detected: "
                f"{source_ip} -> "
                f"{destination_ip}:{destination_port} | "
                f"SYN attempts: {syn_count}, "
                f"SYN-ACK responses: {response_count}, "
                f"unanswered: {unanswered_syns}",
                source_ip,
                destination_ip,
                "SYN Anomaly",
            )


# ============================================================
# Final analysis
# ============================================================

def finalize_detection():
    print()
    print("Finalizing intrusion detection analysis...")

    analyze_syn_anomalies()

    print()
    print("Detection summary:")
    print(f"Tracked TCP connections: {len(port_scan_tracker)}")
    print(f"SYN connections: {len(syn_attempts)}")
    print(f"ICMP sources: {len(icmp_packets)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Detector risk score: {risk_score}")
