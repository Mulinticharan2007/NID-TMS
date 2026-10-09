from pathlib import Path
import json

from scapy.all import IP, TCP, UDP, ICMP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATS_FILE = PROJECT_ROOT / "database" / "traffic_stats.json"

traffic_stats = {
    "total_packets": 0,
    "tcp_packets": 0,
    "udp_packets": 0,
    "icmp_packets": 0,
    "total_bytes": 0
}


def reset_stats():
    traffic_stats["total_packets"] = 0
    traffic_stats["tcp_packets"] = 0
    traffic_stats["udp_packets"] = 0
    traffic_stats["icmp_packets"] = 0
    traffic_stats["total_bytes"] = 0


def process_packet(packet):
    traffic_stats["total_packets"] += 1
    traffic_stats["total_bytes"] += len(packet)

    if TCP in packet:
        traffic_stats["tcp_packets"] += 1

    elif UDP in packet:
        traffic_stats["udp_packets"] += 1

    elif ICMP in packet:
        traffic_stats["icmp_packets"] += 1


def save_stats():
    STATS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        STATS_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            traffic_stats,
            file,
            indent=4
        )


def load_stats():

    if not STATS_FILE.exists():

        return {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "total_bytes": 0
        }

    with open(
        STATS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def get_stats():
    return load_stats()
