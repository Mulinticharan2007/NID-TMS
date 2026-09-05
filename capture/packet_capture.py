from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime


def show_packet(packet):
    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%H:%M:%S")

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_length = len(packet)

    protocol = "OTHER"
    source_port = "-"
    destination_port = "-"

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    print(
        f"{timestamp} | "
        f"{source_ip:15} -> {destination_ip:15} | "
        f"{protocol:5} | "
        f"{source_port:5} -> {destination_port:5} | "
        f"{packet_length} bytes"
    )


print("=" * 90)
print("NID-TMS - REAL-TIME PACKET MONITOR")
print("=" * 90)
print("Time     | Source IP       -> Destination IP  | Proto | Ports         | Size")
print("-" * 90)
print("Monitoring network traffic... Press Ctrl+C to stop.")
print()

try:
    sniff(prn=show_packet)

except KeyboardInterrupt:
    print("\n")
    print("Packet monitoring stopped.")
    print("NID-TMS capture module completed.")
