import subprocess
import time


SCAN_INTERVAL = 10


def run_monitor():

    print("=" * 45)
    print("        LINUX SOC SECURITY MONITOR")
    print("=" * 45)
    print()

    while True:

        print("🔍 Starting security scan...")
        print()

        print("[1] Authentication monitoring")
        subprocess.run(
            ["python3", "monitor.py"]
        )

        print()
        print("[2] Process monitoring")
        subprocess.run(
            ["python3", "process_detector.py"]
        )

        print()
        print("[3] Network monitoring")
        subprocess.run(
            ["python3", "network_monitor.py"]
        )

        print()
        print("✅ Scan complete.")
        print(
            f"Next scan in {SCAN_INTERVAL} seconds..."
        )

        print("-" * 45)

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":

    try:

        run_monitor()

    except KeyboardInterrupt:

        print()
        print("🛑 SOC Monitor stopped.")
