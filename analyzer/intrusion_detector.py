
from pathlib import Path
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import IP, TCP, ICMP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from config.settings import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    ICMP_THRESHOLD,
    ICMP_WINDOW_SECONDS,
    SYN_THRESHOLD,
    SYN_WINDOW_SECONDS,
)

from alerts.alert_manager import save_alert
from database.database_manager import save_alert as save_database_alert
from analyzer.risk_scoring import calculate_risk_score


# ============================================================
# Detection tracking
# ============================================================

# Store SYN attempts and SYN-ACK responses as:
# (timestamp, sequence_number)
# (timestamp, acknowledgement_number)
#
# Connection key:
# (client_ip, server_ip, client_source_port, server_destination_port)

syn_attempts = defaultdict(deque)
syn_ack_responses = defaultdict(deque)
syn_anomaly_alerted = set()

# Port scan observations: (timestamp, destination_port)
port_scan_tracker = defaultdict(deque)
port_scan_alerted = set()

# ICMP packet timestamps per source IP.
icmp_packets = defaultdict(deque)
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

    # Maintain cumulative detector risk score.
    if severity == "HIGH":
        risk_score += 10
    elif severity == "MEDIUM":
        risk_score += 5
    else:
        risk_score += 1

    # Calculate individual alert risk score.
    individual_risk = calculate_risk_score(
        severity,
        alert_type,
        message,
    )

    print()
    print("ALERT:", alert)

    # Save alert to log file.
    save_alert(severity, message)

    # Save alert to SQLite.
    save_database_alert(
        severity,
        alert_type,
        source_ip,
        destination_ip,
        message,
        individual_risk,
        correlation_key,
    )


# ============================================================
# Time-window helpers
# ============================================================

def remove_expired(observations, cutoff_time):
    """Remove timestamp observations older than the configured window."""
    while observations and observations[0] < cutoff_time:
        observations.popleft()


def remove_expired_sequence_observations(
    observations,
    cutoff_time,
):
    """Remove expired (timestamp, sequence_number) observations."""
    while (
        observations
        and observations[0][0] < cutoff_time
    ):
        observations.popleft()


# ============================================================
# Packet analysis
# ============================================================

def detect_suspicious(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    current_time = datetime.now()

    # ========================================================
    # TCP and port-scan detection
    # ========================================================

    if TCP in packet:

        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
        flags = int(packet[TCP].flags)

        # Initial SYN: SYN set and ACK unset.
        is_initial_syn = (
            bool(flags & 0x02)
            and not bool(flags & 0x10)
        )

        if is_initial_syn:

            scan_target = (source_ip, destination_ip)
            observations = port_scan_tracker[scan_target]

            cutoff_time = current_time - timedelta(
                seconds=PORT_SCAN_WINDOW_SECONDS
            )

            # Remove observations outside the rolling window.
            while (
                observations
                and observations[0][0] < cutoff_time
            ):
                observations.popleft()

            existing_ports = {
                port for timestamp, port in observations
            }

            # Record only unique destination ports.
            if destination_port not in existing_ports:
                observations.append(
                    (current_time, destination_port)
                )

            unique_ports = len({
                port for timestamp, port in observations
            })

            # Re-arm alert when count falls below threshold.
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
        # SYN attempt tracking
        # ====================================================

        if is_initial_syn:

            connection = (
                source_ip,
                destination_ip,
                source_port,
                destination_port,
            )

            sequence_number = (
                int(packet[TCP].seq) & 0xFFFFFFFF
            )

            attempts = syn_attempts[connection]

            cutoff_time = current_time - timedelta(
                seconds=SYN_WINDOW_SECONDS
            )

            # Remove expired SYN attempts.
            remove_expired_sequence_observations(
                attempts,
                cutoff_time,
            )

            # Prevent retransmissions from being counted twice.
            existing_sequences = {
                sequence
                for timestamp, sequence in attempts
            }

            if sequence_number not in existing_sequences:
                attempts.append(
                    (current_time, sequence_number)
                )

        # ====================================================
        # SYN-ACK response tracking
        # ====================================================

        elif (flags & 0x02) and (flags & 0x10):

            # Reverse packet direction to obtain the original
            # client-to-server connection key.
            original_connection = (
                destination_ip,
                source_ip,
                destination_port,
                source_port,
            )

            acknowledgement_number = (
                int(packet[TCP].ack) & 0xFFFFFFFF
            )

            responses = syn_ack_responses[original_connection]

            cutoff_time = current_time - timedelta(
                seconds=SYN_WINDOW_SECONDS
            )

            # Remove expired SYN-ACK responses.
            remove_expired_sequence_observations(
                responses,
                cutoff_time,
            )

            # Prevent duplicate SYN-ACKs from being counted twice.
            existing_acknowledgements = {
                acknowledgement
                for timestamp, acknowledgement in responses
            }

            if (
                acknowledgement_number
                not in existing_acknowledgements
            ):
                responses.append(
                    (current_time, acknowledgement_number)
                )

    # ========================================================
    # ICMP detection
    # ========================================================

    elif ICMP in packet:

        observations = icmp_packets[source_ip]

        cutoff_time = current_time - timedelta(
            seconds=ICMP_WINDOW_SECONDS
        )

        remove_expired(observations, cutoff_time)

        observations.append(current_time)

        count = len(observations)

        # Re-arm alert when traffic drops below threshold.
        if count < ICMP_THRESHOLD:
            icmp_alerted.discard(source_ip)

        if (
            count >= ICMP_THRESHOLD
            and source_ip not in icmp_alerted
        ):
            icmp_alerted.add(source_ip)

            create_alert(
                "MEDIUM",
                f"High ICMP traffic detected from "
                f"{source_ip} ({count} ICMP packets within "
                f"{ICMP_WINDOW_SECONDS} seconds)",
                source_ip,
                destination_ip,
                "ICMP Traffic",
            )


# ============================================================
# SYN anomaly analysis
# ============================================================

def analyze_syn_anomalies():

    current_time = datetime.now()

    cutoff_time = current_time - timedelta(
        seconds=SYN_WINDOW_SECONDS
    )

    for connection, attempts in list(syn_attempts.items()):

        # Remove expired SYN attempts.
        remove_expired_sequence_observations(
            attempts,
            cutoff_time,
        )

        # Remove expired SYN-ACK responses.
        responses = syn_ack_responses[connection]

        remove_expired_sequence_observations(
            responses,
            cutoff_time,
        )

        # If all attempts expired, clear tracking state.
        if not attempts:

            syn_attempts.pop(connection, None)
            syn_ack_responses.pop(connection, None)
            syn_anomaly_alerted.discard(connection)

            continue

        # Each unique sequence number represents one SYN attempt.
        attempt_sequences = {
            sequence
            for timestamp, sequence in attempts
        }

        syn_count = len(attempt_sequences)

        # Match SYN-ACK acknowledgements to original SYN sequence
        # numbers. TCP sequence numbers wrap around at 2**32.
        matched_sequences = set()

        for timestamp, acknowledgement in responses:

            acknowledged_sequence = (
                acknowledgement - 1
            ) % (2 ** 32)

            if acknowledged_sequence in attempt_sequences:
                matched_sequences.add(acknowledged_sequence)

        response_count = len(matched_sequences)

        if syn_count < SYN_THRESHOLD:
            syn_anomaly_alerted.discard(connection)
            continue

        unanswered_syns = max(
            syn_count - response_count,
            0,
        )

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

            (
                source_ip,
                destination_ip,
                source_port,
                destination_port,
            ) = connection

            create_alert(
                "MEDIUM",
                f"SYN anomaly detected: "
                f"{source_ip}:{source_port} -> "
                f"{destination_ip}:{destination_port} | "
                f"SYN attempts: {syn_count}, "
                f"SYN-ACK responses: {response_count}, "
                f"unanswered: {unanswered_syns}",
                source_ip,
                destination_ip,
                "SYN Anomaly",
            )

    # Remove response entries without active SYN attempts.
    for connection in list(syn_ack_responses):

        if connection not in syn_attempts:
            syn_ack_responses.pop(connection, None)


# ============================================================
# Final analysis
# ============================================================

def finalize_detection():

    print()
    print("Finalizing intrusion detection analysis...")

    # Analyse SYN behaviour.
    analyze_syn_anomalies()

    current_time = datetime.now()

    # --------------------------------------------------------
    # Expire old port-scan observations.
    # --------------------------------------------------------

    port_scan_cutoff = current_time - timedelta(
        seconds=PORT_SCAN_WINDOW_SECONDS
    )

    for connection, observations in list(port_scan_tracker.items()):

        while (
            observations
            and observations[0][0] < port_scan_cutoff
        ):
            observations.popleft()

        if not observations:
            port_scan_tracker.pop(connection, None)
            port_scan_alerted.discard(connection)

    # --------------------------------------------------------
    # Expire old ICMP observations.
    # --------------------------------------------------------

    icmp_cutoff = current_time - timedelta(
        seconds=ICMP_WINDOW_SECONDS
    )

    for source_ip, observations in list(icmp_packets.items()):

        remove_expired(observations, icmp_cutoff)

        if not observations:
            icmp_packets.pop(source_ip, None)
            icmp_alerted.discard(source_ip)

    # --------------------------------------------------------
    # Print detection summary.
    # --------------------------------------------------------

    print()
    print("Detection summary:")
    print(f"Tracked TCP connections: {len(port_scan_tracker)}")
    print(f"SYN connections: {len(syn_attempts)}")
    print(f"ICMP sources: {len(icmp_packets)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Detector risk score: {risk_score}")
