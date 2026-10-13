from scapy.all import sniff
from datetime import datetime
from pathlib import Path
import sys
import time
import msvcrt

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from analyzer.traffic_stats import process_packet, save_stats
from analyzer.intrusion_detector import detect_suspicious, finalize_detection
from database.traffic_store import initialize_traffic_table, save_packet

SAVE_INTERVAL = 5
last_save_time = time.time()


def show_packet(packet):
    global last_save_time

    # Update aggregate traffic statistics
    process_packet(packet)

    # Save packet metadata for the dashboard
    try:
        save_packet(packet)
    except Exception as error:
        print(f"Traffic record save error: {error}")

    # Run existing intrusion detection
    detect_suspicious(packet)

    timestamp = datetime.now().strftime("%H:%M:%S")

    print(
        f"[{timestamp}] "
        f"{packet.summary()} "
        f"| Size: {len(packet)} bytes"
    )

    current_time = time.time()

    if current_time - last_save_time >= SAVE_INTERVAL:
        save_stats()
        last_save_time = current_time

        print(f"[{timestamp}] Traffic statistics updated.")


print("=" * 80)
print("NID-TMS - REAL-TIME NETWORK MONITOR")
print("=" * 80)

try:
    initialize_traffic_table()
    print("Traffic record storage: enabled")
except Exception as error:
    print("Traffic storage initialization error:", error)
    raise

print("Starting continuous network monitoring...")
print("Traffic statistics: every 5 seconds")
print("Intrusion detection: enabled")
print("Press Q to stop monitoring.")
print()

try:
    while True:
        sniff(
            prn=show_packet,
            timeout=1
        )

        if msvcrt.kbhit():
            key = msvcrt.getwch()

            if key.lower() == "q":
                print()
                print("Stop requested by user.")
                break

except KeyboardInterrupt:
    print()
    print("Ctrl+C received.")

except Exception as error:
    print()
    print("Monitoring error:", error)

finally:
    finalize_detection()
    save_stats()

    print()
    print("=" * 80)
    print("Network monitoring stopped.")
    print("Final traffic statistics saved.")
    print("=" * 80)
