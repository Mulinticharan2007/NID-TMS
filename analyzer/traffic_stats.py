
import sqlite3
from pathlib import Path
import json

from scapy.all import TCP, UDP, ICMP


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATS_FILE = PROJECT_ROOT / "database" / "traffic_stats.json"
DB_FILE = PROJECT_ROOT / "database" / "nid_tms.db"


# In-memory traffic counters
traffic_stats = {
    "total_packets": 0,
    "tcp_packets": 0,
    "udp_packets": 0,
    "icmp_packets": 0,
    "other_packets": 0,
    "total_bytes": 0,
}


def reset_stats():
    """Reset all in-memory traffic counters."""
    for key in traffic_stats:
        traffic_stats[key] = 0


def process_packet(packet):
    """Count packets by protocol and track total bytes."""
    traffic_stats["total_packets"] += 1
    traffic_stats["total_bytes"] += len(packet)

    if TCP in packet:
        traffic_stats["tcp_packets"] += 1
    elif UDP in packet:
        traffic_stats["udp_packets"] += 1
    elif ICMP in packet:
        traffic_stats["icmp_packets"] += 1
    else:
        traffic_stats["other_packets"] += 1


def save_stats():
    """Save in-memory traffic statistics to a JSON file."""
    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with STATS_FILE.open("w", encoding="utf-8") as file:
        json.dump(traffic_stats, file, indent=4)


def load_stats():
    """Load saved JSON statistics and support older files."""
    defaults = {
        "total_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "icmp_packets": 0,
        "other_packets": 0,
        "total_bytes": 0,
    }

    if not STATS_FILE.exists():
        return defaults.copy()

    with STATS_FILE.open("r", encoding="utf-8") as file:
        saved = json.load(file)

    stats = {**defaults, **saved}

    # Infer OTHER packets for older JSON files.
    if "other_packets" not in saved:
        known_packets = (
            stats["tcp_packets"]
            + stats["udp_packets"]
            + stats["icmp_packets"]
        )
        stats["other_packets"] = max(
            0, stats["total_packets"] - known_packets
        )

    return stats


def get_stats():
    """Calculate traffic statistics directly from SQLite."""

    defaults = {
        "total_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "icmp_packets": 0,
        "other_packets": 0,
        "total_bytes": 0,
    }

    if not DB_FILE.exists():
        return defaults.copy()

    query = """
        SELECT
            COUNT(*) AS total_packets,
            COALESCE(SUM(
                CASE WHEN UPPER(protocol) = 'TCP'
                THEN 1 ELSE 0 END
            ), 0) AS tcp_packets,
            COALESCE(SUM(
                CASE WHEN UPPER(protocol) = 'UDP'
                THEN 1 ELSE 0 END
            ), 0) AS udp_packets,
            COALESCE(SUM(
                CASE WHEN UPPER(protocol) = 'ICMP'
                THEN 1 ELSE 0 END
            ), 0) AS icmp_packets,
            COALESCE(SUM(
                CASE
                    WHEN protocol IS NULL
                      OR UPPER(protocol) NOT IN ('TCP', 'UDP', 'ICMP')
                    THEN 1
                    ELSE 0
                END
            ), 0) AS other_packets,
            COALESCE(SUM(packet_size), 0) AS total_bytes
        FROM traffic
    """

    try:
        with sqlite3.connect(DB_FILE) as conn:
            row = conn.execute(query).fetchone()

        keys = list(defaults.keys())
        return dict(zip(keys, row))

    except sqlite3.Error as error:
        print(f"Error reading traffic statistics from SQLite: {error}")
        return defaults.copy()
