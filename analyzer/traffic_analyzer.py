from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter, defaultdict
from datetime import datetime
import sys
from pathlib import Path
import time


# Add project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from config.settings import CAPTURE_TIMEOUT, SUSPICIOUS_CONNECTION_THRESHOLD


total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0
other_packets = 0
total_bytes = 0


# Connection tracking
connections = defaultdict(
    lambda: {
        "packets": 0,
        "bytes": 0,
        "first_seen": None,
        "last_seen": None
    }
)

ip_packets = Counter()
suspicious_connections = []

start_time = time.time()


def analyze_packet(packet):

    global total_packets
    global tcp_packets
    global udp_packets
    global icmp_packets
    global other_packets
    global total_bytes

    if IP not in packet:
        return

    total_packets += 1
    packet_size = len(packet)
    total_bytes += packet_size

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    ip_packets[source_ip] += 1
    ip_packets[destination_ip] += 1

    protocol = "OTHER"
    source_port = "-"
    destination_port = "-"

    if TCP in packet:

        tcp_packets += 1
        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:

        udp_packets += 1
        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:

        icmp_packets += 1
        protocol = "ICMP"

    else:

        other_packets += 1

    connection = (
        source_ip,
        str(source_port),
        destination_ip,
        str(destination_port),
        protocol
    )

    current_time = datetime.now().strftime("%H:%M:%S")

    connections[connection]["packets"] += 1
    connections[connection]["bytes"] += packet_size

    if connections[connection]["first_seen"] is None:
        connections[connection]["first_seen"] = current_time

    connections[connection]["last_seen"] = current_time

    print(
        f"{current_time} | "
        f"{source_ip:15} -> {destination_ip:15} | "
        f"{protocol:5} | "
        f"{str(source_port):5} -> "
        f"{str(destination_port):5} | "
        f"{packet_size} bytes"
    )

def detect_suspicious_connections():

    print("\n")
    print("=" * 100)
    print("SUSPICIOUS CONNECTION ANALYSIS")
    print("=" * 100)

    suspicious_count = 0

    for connection, data in connections.items():

        source_ip, source_port, destination_ip, destination_port, protocol = connection

        if data["packets"] >= SUSPICIOUS_CONNECTION_THRESHOLD:

            suspicious_count += 1

            print(
                f"SUSPICIOUS: "
                f"{source_ip}:{source_port} -> "
                f"{destination_ip}:{destination_port} | "
                f"{protocol} | "
                f"Packets: {data['packets']}"
            )

    if suspicious_count == 0:
        print("No suspicious connections detected.")

    print("=" * 100)

def show_statistics():

    duration = time.time() - start_time

    if duration > 0:

        packets_per_second = total_packets / duration
        bytes_per_second = total_bytes / duration

    else:

        packets_per_second = 0
        bytes_per_second = 0

    print("\n")
    print("=" * 100)
    print("NID-TMS TRAFFIC STATISTICS")
    print("=" * 100)

    print("Total Packets :", total_packets)
    print("TCP Packets   :", tcp_packets)
    print("UDP Packets   :", udp_packets)
    print("ICMP Packets  :", icmp_packets)
    print("Other Packets :", other_packets)
    print("Total Bytes   :", total_bytes)

    print("\nTRAFFIC RATE")
    print("-" * 100)

    print("Capture Time  :", round(duration, 2), "seconds")
    print("Packets/Sec   :", round(packets_per_second, 2))
    print("Bytes/Sec     :", round(bytes_per_second, 2))

    print("\nCONNECTION STATISTICS")
    print("-" * 100)

    if connections:

        for connection, data in sorted(
            connections.items(),
            key=lambda item: item[1]["packets"],
            reverse=True
        ):

            source_ip, source_port, destination_ip, destination_port, protocol = connection

            print(
                f"{source_ip}:{source_port} -> "
                f"{destination_ip}:{destination_port} | "
                f"{protocol} | "
                f"Packets: {data['packets']} | "
                f"Bytes: {data['bytes']} | "
                f"First: {data['first_seen']} | "
                f"Last: {data['last_seen']}"
            )

    else:

        print("No connections detected.")

    print("\nTOP IP STATISTICS")
    print("-" * 100)

    for ip, count in ip_packets.most_common(10):

        print(
            f"{ip:15} | "
            f"Packets: {count}"
        )

    print("=" * 100)


print("=" * 100)
print("NID-TMS - REAL-TIME TRAFFIC ANALYZER")
print("=" * 100)
print(f"Capture timeout: {CAPTURE_TIMEOUT} seconds")
print("Analyzing network traffic...")
print("Press Ctrl+C to stop.")
print()

try:

    sniff(
        prn=analyze_packet,
        timeout=CAPTURE_TIMEOUT
    )

except KeyboardInterrupt:

    print("\nTraffic analysis stopped by user.")

except Exception as error:

    print("\nAnalysis error:", error)
finally:

    show_statistics()
    detect_suspicious_connections()

    print()
    print("NID-TMS traffic analyzer completed.")