from scapy.all import IP, TCP
from database.traffic_store import initialize_traffic_table, save_packet, get_recent_packets

initialize_traffic_table()

test_packet = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=12345, dport=443)

save_packet(test_packet)

print("Latest traffic record:")
print(get_recent_packets(1)[0])
