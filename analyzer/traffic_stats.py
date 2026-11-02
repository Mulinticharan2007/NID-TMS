import sqlite3
from pathlib import Path
import json

from scapy.all import IP, IPv6, TCP, UDP, ICMP

PROJECT_ROOT = Path(__file__).resolve().parent.parent

STATS_FILE = PROJECT_ROOT / "database" / "traffic_stats.json"
DB_FILE = PROJECT_ROOT / "database" / "nid_tms.db"

traffic_stats = {
    "total_packets": 0,
    "ipv4_packets": 0,
    "ipv6_packets": 0,
    "tcp_packets": 0,
    "udp_packets": 0,
    "icmp_packets": 0,
    "icmpv6_packets": 0,
    "other_packets": 0,
    "total_bytes": 0,
}


def reset_stats():
    for key in traffic_stats:
        traffic_stats[key] = 0


def process_packet(packet):
    traffic_stats["total_packets"] += 1
    traffic_stats["total_bytes"] += len(packet)

    if IP in packet:
        traffic_stats["ipv4_packets"] += 1
    elif IPv6 in packet:
        traffic_stats["ipv6_packets"] += 1

    if TCP in packet:
        traffic_stats["tcp_packets"] += 1

    elif UDP in packet:
        traffic_stats["udp_packets"] += 1

    elif ICMP in packet:
        traffic_stats["icmp_packets"] += 1

    elif any(
        layer.__name__.startswith("ICMPv6")
        for layer in packet.layers()
    ):
        traffic_stats["icmp_packets"] += 1
        traffic_stats["icmpv6_packets"] += 1

    else:
        traffic_stats["other_packets"] += 1


def save_stats():
    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with STATS_FILE.open("w", encoding="utf-8") as file:
        json.dump(traffic_stats, file, indent=4)


def load_stats():
    defaults = traffic_stats.copy()

    if not STATS_FILE.exists():
        return defaults

    with STATS_FILE.open("r", encoding="utf-8") as file:
        saved = json.load(file)

    return {**defaults, **saved}


def get_stats():
    defaults = traffic_stats.copy()

    if not DB_FILE.exists():
        return defaults

    query = """
        SELECT
            COUNT(*) AS total_packets,

            COALESCE(SUM(
                CASE
                    WHEN source_ip IS NOT NULL
                     AND instr(source_ip, ':') = 0
                    THEN 1 ELSE 0
                END
            ), 0) AS ipv4_packets,

            COALESCE(SUM(
                CASE
                    WHEN instr(source_ip, ':') > 0
                    THEN 1 ELSE 0
                END
            ), 0) AS ipv6_packets,

            COALESCE(SUM(
                CASE WHEN UPPER(protocol) = 'TCP'
                THEN 1 ELSE 0 END
            ), 0) AS tcp_packets,

            COALESCE(SUM(
                CASE WHEN UPPER(protocol) = 'UDP'
                THEN 1 ELSE 0 END
            ), 0) AS udp_packets,

            COALESCE(SUM(
                CASE WHEN UPPER(protocol) IN ('ICMP', 'ICMPV6')
                THEN 1 ELSE 0 END
            ), 0) AS icmp_packets,

            COALESCE(SUM(
                CASE WHEN UPPER(protocol) = 'ICMPV6'
                THEN 1 ELSE 0 END
            ), 0) AS icmpv6_packets,

            COALESCE(SUM(
                CASE
                    WHEN protocol IS NULL
                      OR UPPER(protocol) NOT IN (
                          'TCP', 'UDP', 'ICMP', 'ICMPV6'
                      )
                    THEN 1 ELSE 0
                END
            ), 0) AS other_packets,

            COALESCE(SUM(packet_size), 0) AS total_bytes

        FROM traffic
    """

    try:
        with sqlite3.connect(DB_FILE, timeout=10) as connection:
            row = connection.execute(query).fetchone()

        keys = list(defaults.keys())
        return dict(zip(keys, row))

    except sqlite3.Error as error:
        print(f"Error reading traffic statistics: {error}")
        return defaults.copy()
