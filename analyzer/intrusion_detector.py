from pathlib import Path
import sys
from collections import Counter
from datetime import datetime

from scapy.all import sniff, IP, TCP, ICMP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from alerts.alert_manager import save_alert
from database.database_manager import save_alert as save_database_alert


connection_attempts = Counter()
icmp_packets = Counter()
connection_counts = Counter()
alerts = []


def create_alert(severity, message):

    timestamp = datetime.now().strftime("%H:%M:%S")

    alert = f"[{timestamp}] [{severity}] {message}"

    alerts.append(alert)

    print("\nALERT:", alert)

    save_alert(severity, message)

    save_database_alert(
        severity,
        "IDS_ALERT",
        "Unknown",
        "Unknown",
        message
    )


def detect_suspicious(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    if TCP in packet:

        destination_port = packet[TCP].dport

        # Count SYN packets
        if packet[TCP].flags == "S":

            connection = (
                source_ip,
                destination_ip,
                destination_port
            )

            connection_attempts[connection] += 1

            count = connection_attempts[connection]

            if count == 10:

                create_alert(
                    "HIGH",
                    f"Possible Port Scan: "
                    f"{source_ip} -> "
                    f"{destination_ip}:{destination_port} "
                    f"({count} SYN attempts)"
                )

    elif ICMP in packet:

        icmp_packets[source_ip] += 1

        count = icmp_packets[source_ip]

        if count == 20:

            create_alert(
                "MEDIUM",
                f"High ICMP traffic detected from "
                f"{source_ip} "
                f"({count} ICMP packets)"
            )


print("=" * 80)
print("NID-TMS - INTRUSION DETECTION")
print("=" * 80)
print("Monitoring network traffic for 10 seconds...")
print()

try:

    packets = sniff(
        prn=detect_suspicious,
        timeout=10
    )

    print()
    print("Capture completed.")
    print("Packets captured:", len(packets))

except Exception as error:

    print()
    print("Capture error:", error)


print()
print("=" * 80)
print("INTRUSION DETECTION SUMMARY")
print("=" * 80)

print("\nICMP TRAFFIC")
print("-" * 80)

if icmp_packets:

    for ip, count in icmp_packets.most_common():

        print(
            f"{ip:15} | "
            f"ICMP Packets: {count}"
        )

else:

    print("No ICMP packets detected.")


print("\nTCP SYN ATTEMPTS")
print("-" * 80)

if connection_attempts:

    for connection, count in connection_attempts.most_common():

        source_ip, destination_ip, destination_port = connection

        print(
            f"{source_ip} -> "
            f"{destination_ip}:"
            f"{destination_port} | "
            f"SYN Attempts: {count}"
        )

else:

    print("No TCP SYN packets detected.")


print("\nSECURITY ALERTS")
print("-" * 80)

if alerts:

    for alert in alerts:

        print(alert)

else:

    print("No suspicious activity detected.")


print("=" * 80)
print("NID-TMS intrusion detection completed.")