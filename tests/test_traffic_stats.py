from pathlib import Path
import sys
import unittest
from scapy.all import IP, TCP, UDP, ICMP, Raw

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analyzer.traffic_stats import traffic_stats, reset_stats, process_packet


class TestTrafficStats(unittest.TestCase):
    def setUp(self):
        reset_stats()

    def tearDown(self):
        reset_stats()

    def test_tcp_packet_count(self):
        process_packet(IP() / TCP(dport=80))
        self.assertEqual(traffic_stats["total_packets"], 1)
        self.assertEqual(traffic_stats["tcp_packets"], 1)

    def test_udp_packet_count(self):
        process_packet(IP() / UDP(dport=53))
        self.assertEqual(traffic_stats["total_packets"], 1)
        self.assertEqual(traffic_stats["udp_packets"], 1)

    def test_icmp_packet_count(self):
        process_packet(IP() / ICMP())
        self.assertEqual(traffic_stats["total_packets"], 1)
        self.assertEqual(traffic_stats["icmp_packets"], 1)

    def test_total_bytes(self):
        packet = IP() / TCP(dport=80) / Raw(load=b"Hello NID-TMS")
        process_packet(packet)
        self.assertEqual(traffic_stats["total_bytes"], len(packet))

    def test_multiple_packets(self):
        packets = [
            IP() / TCP(dport=80),
            IP() / TCP(dport=443),
            IP() / UDP(dport=53),
            IP() / ICMP(),
        ]
        for packet in packets:
            process_packet(packet)

        self.assertEqual(traffic_stats["total_packets"], 4)
        self.assertEqual(traffic_stats["tcp_packets"], 2)
        self.assertEqual(traffic_stats["udp_packets"], 1)
        self.assertEqual(traffic_stats["icmp_packets"], 1)
        self.assertEqual(
            traffic_stats["total_bytes"],
            sum(len(packet) for packet in packets),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
