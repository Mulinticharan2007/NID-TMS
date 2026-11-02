import sqlite3
from pathlib import Path
from datetime import datetime

from scapy.all import IP, IPv6, TCP, UDP, ICMP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "database" / "nid_tms.db"


def initialize_traffic_table():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH, timeout=10) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                packet_size INTEGER NOT NULL
            )
        """)
        connection.commit()


def save_packet(packet):
    if IP in packet:
        network_layer = packet[IP]
    elif IPv6 in packet:
        network_layer = packet[IPv6]
    else:
        return

    source_ip = network_layer.src
    destination_ip = network_layer.dst

    source_port = None
    destination_port = None
    protocol = "OTHER"

    if TCP in packet:
        protocol = "TCP"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)

    elif UDP in packet:
        protocol = "UDP"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)

    elif ICMP in packet:
        protocol = "ICMP"

    elif any(
        layer.__name__.startswith("ICMPv6")
        for layer in packet.layers()
    ):
        protocol = "ICMPv6"

    with sqlite3.connect(DB_PATH, timeout=10) as connection:
        connection.execute("""
            INSERT INTO traffic (
                timestamp,
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                packet_size
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(timespec="seconds"),
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            len(packet)
        ))
        connection.commit()


def get_recent_packets(limit=100):
    initialize_traffic_table()

    with sqlite3.connect(DB_PATH, timeout=10) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT
                id,
                timestamp,
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                packet_size
            FROM traffic
            ORDER BY id DESC
            LIMIT ?
        """, (max(1, min(int(limit), 500)),)).fetchall()

        return [dict(row) for row in rows]
