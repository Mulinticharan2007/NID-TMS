from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter
import time

total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0
other_packets = 0
total_bytes = 0

connections = Counter()
ip_packets = Counter()

start_time = time.time()


def analyze_packet(packet):
    global total_packets, tcp_packets, udp_packets
    global icmp_packets, other_packets, total_bytes

    if IP not in packet:
        return

    total_packets += 1
    total_bytes += len(packet)

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

    connections[connection] += 1

    print(
        f"{source_ip:15} -> {destination_ip:15} | "
        f"{protocol:5} | "
        f"{str(source_port):5} -> {str(destination_port):5} | "
        f"{len(packet)} bytes"
    )


def show_statistics():
    duration = time.time() - start_time

    if duration > 0:
        packets_per_second = total_packets / duration
        bytes_per_second = total_bytes / duration
    else:
        packets_per_second = 0
        bytes_per_second = 0

    print("\n")
    print("=" * 70)
    print("NID-TMS TRAFFIC STATISTICS")
    print("=" * 70)

    print("Total Packets :", total_packets)
    print("TCP Packets   :", tcp_packets)
    print("UDP Packets   :", udp_packets)
    print("ICMP Packets  :", icmp_packets)
    print("Other Packets :", other_packets)
    print("Total Bytes   :", total_bytes)

    print("\nTRAFFIC RATE")
    print("-" * 70)
    print("Capture Time  :", round(duration, 2), "seconds")
    print("Packets/Sec   :", round(packets_per_second, 2))
    print("Bytes/Sec     :", round(bytes_per_second, 2))

    print("\nCONNECTION STATISTICS")
    print("-" * 70)

    for connection, count in connections.most_common():
        source_ip, source_port, destination_ip, destination_port, protocol = connection

        print(
            f"{source_ip}:{source_port} -> "
            f"{destination_ip}:{destination_port} | "
            f"{protocol} | Packets: {count}"
        )

    print("\nTOP IP STATISTICS")
    print("-" * 70)

    for ip, count in ip_packets.most_common():
        print(f"{ip:15} | Packets: {count}")

    print("=" * 70)


print("=" * 85)
print("NID-TMS - TRAFFIC ANALYZER")
print("=" * 85)
print("Analyzing network traffic...")
print("Press Ctrl+C to stop and view statistics.")
print()

try:
    sniff(prn=analyze_packet)

except KeyboardInterrupt:
    pass

finally:
    show_statistics()
    print("\nTraffic analysis stopped.")
    print("NID-TMS analyzer completed.")