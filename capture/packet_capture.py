
from scapy.all import sniff
from datetime import datetime
from pathlib import Path
import sys
import time
import msvcrt

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from config.settings import NETWORK_INTERFACE
from analyzer.traffic_stats import process_packet, save_stats

from analyzer.intrusion_detector import (
    detect_suspicious,
    analyze_syn_anomalies,
    finalize_detection,
)

from analyzer.ip_behavior import IPBehaviorAnalyzer
from database.traffic_store import initialize_traffic_table, save_packet


# ============================================================
# Configuration
# ============================================================

SAVE_INTERVAL = 5
SYN_ANALYSIS_INTERVAL = 1

last_save_time = time.time()
last_syn_analysis_time = time.time()


# ============================================================
# Initialize IP behaviour analyzer
# ============================================================

ip_behavior_analyzer = IPBehaviorAnalyzer()


# ============================================================
# Packet processing callback
# ============================================================

def show_packet(packet):
    global last_save_time

    # 1. Update aggregate traffic statistics.
    process_packet(packet)

    # 2. Save packet metadata for the dashboard.
    try:
        save_packet(packet)

    except Exception as error:
        print(f"Traffic record save error: {error}")

    # 3. Run existing intrusion detection.
    detect_suspicious(packet)

    # 4. Run IP-based behaviour analysis.
    try:
        new_alerts = ip_behavior_analyzer.process_packet(packet)

        for alert in new_alerts:
            print(
                f"[IP BEHAVIOUR ALERT] "
                f"[{alert['severity']}] "
                f"{alert['alert_type']} | "
                f"Source: {alert['source_ip']} | "
                f"{alert['description']}"
            )

    except Exception as error:
        print(f"IP behaviour analysis error: {error}")

    # 5. Display captured packet information.
    timestamp = datetime.now().strftime("%H:%M:%S")

    print(
        f"[{timestamp}] "
        f"{packet.summary()} "
        f"| Size: {len(packet)} bytes"
    )

    # 6. Save traffic statistics every 5 seconds.
    current_time = time.time()

    if current_time - last_save_time >= SAVE_INTERVAL:
        save_stats()
        last_save_time = current_time

        print(
            f"[{timestamp}] "
            "Traffic statistics updated."
        )


# ============================================================
# Start monitoring application
# ============================================================

print("=" * 80)
print("NID-TMS - REAL-TIME NETWORK MONITOR")
print("=" * 80)


# ============================================================
# Initialize database
# ============================================================

try:
    initialize_traffic_table()

    print("Traffic record storage: enabled")

except Exception as error:
    print("Traffic storage initialization error:", error)
    raise


# ============================================================
# Monitoring information
# ============================================================

print("Starting continuous network monitoring...")
print(f"Network interface: {NETWORK_INTERFACE}")
print("Traffic statistics: every 5 seconds")
print("Intrusion detection: enabled")
print("IP behaviour analysis: enabled")
print("SYN anomaly analysis: approximately every 1 second")
print("Press Q to stop monitoring.")
print()


# ============================================================
# Main monitoring loop
# ============================================================

try:
    while True:

        # Capture packets for one second.
        sniff(
            iface=NETWORK_INTERFACE,
            prn=show_packet,
            timeout=1
        )

        # Evaluate SYN anomalies periodically.
        current_time = time.time()

        if (
            current_time - last_syn_analysis_time
            >= SYN_ANALYSIS_INTERVAL
        ):
            analyze_syn_anomalies()
            last_syn_analysis_time = current_time

        # Check whether the user pressed Q.
        if msvcrt.kbhit():
            key = msvcrt.getwch()

            if key.lower() == "q":
                print()
                print("Stop requested by user.")
                break


# ============================================================
# Keyboard interruption
# ============================================================

except KeyboardInterrupt:
    print()
    print("Ctrl+C received.")


# ============================================================
# Monitoring error handling
# ============================================================

except Exception as error:
    print()
    print("Monitoring error:", error)


# ============================================================
# Final cleanup
# ============================================================

finally:

    # Perform final SYN anomaly analysis.
    finalize_detection()

    # Save final traffic statistics.
    save_stats()

    print()
    print("=" * 80)
    print("Network monitoring stopped.")
    print("Final traffic statistics saved.")
    print("=" * 80)
