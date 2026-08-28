import psutil
import time


ALERT_LOG = "alerts.log"

# Ports commonly associated with suspicious activity
SUSPICIOUS_PORTS = [
    4444,
    5555,
    6666,
    1337,
    31337
]


def check_connections():

    connections = psutil.net_connections(
        kind="inet"
    )

    alerts = 0

    for conn in connections:

        # We only care about established connections
        if conn.status != "ESTABLISHED":
            continue

        if not conn.raddr:
            continue

        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port

        pid = conn.pid

        score = 0
        reasons = []

        # -------------------------
        # Suspicious remote port
        # -------------------------

        if remote_port in SUSPICIOUS_PORTS:

            score += 3

            reasons.append(
                f"Suspicious remote port: {remote_port}"
            )

        # -------------------------
        # Get process information
        # -------------------------

        process_name = "unknown"

        if pid:

            try:

                process = psutil.Process(pid)

                process_name = process.name()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied
            ):

                pass

        # -------------------------
        # Generate alert
        # -------------------------

        if score >= 3:

            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            message = (
                f"{timestamp} | NETWORK_ALERT | "
                f"process={process_name} | "
                f"pid={pid} | "
                f"remote_ip={remote_ip} | "
                f"remote_port={remote_port} | "
                f"score={score} | "
                f"reasons={'; '.join(reasons)}\n"
            )

            with open(ALERT_LOG, "a") as file:

                file.write(message)

            print("🚨 NETWORK ALERT")
            print("Process:", process_name)
            print("PID:", pid)
            print("Remote IP:", remote_ip)
            print("Remote Port:", remote_port)
            print("Risk Score:", score)
            print("Reasons:", ", ".join(reasons))
            print()

            alerts += 1

    return alerts


print("=== Network Monitoring ===")
print()

alerts = check_connections()

print("Network scan completed.")
print()

if alerts == 0:

    print("No suspicious network connections detected.")

else:

    print(
        f"Suspicious connections detected: {alerts}"
    )

