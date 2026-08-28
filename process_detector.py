import psutil
import json
import os
import time


BASELINE_FILE = "process_baseline.json"
ALERT_LOG = "alerts.log"
SEEN_ALERTS_FILE = "seen_process_alerts.json"

ALERT_THRESHOLD = 3

SUSPICIOUS_PATHS = [
    "/tmp",
    "/dev/shm"
]


# --------------------------------------------------
# Load baseline
# --------------------------------------------------

def load_baseline():

    if not os.path.exists(BASELINE_FILE):
        return set()

    try:

        with open(BASELINE_FILE, "r") as file:
            data = json.load(file)

        baseline = set()

        for process in data:

            name = process[0]
            exe = process[1]
            username = process[2]

            baseline.add(
                (name, exe, username)
            )

        return baseline

    except Exception:
        return set()


# --------------------------------------------------
# Load previously alerted processes
# --------------------------------------------------

def load_seen_alerts():

    if not os.path.exists(SEEN_ALERTS_FILE):
        return set()

    try:

        with open(SEEN_ALERTS_FILE, "r") as file:
            return set(json.load(file))

    except Exception:
        return set()


# --------------------------------------------------
# Save alerted processes
# --------------------------------------------------

def save_seen_alerts(seen_alerts):

    with open(SEEN_ALERTS_FILE, "w") as file:
        json.dump(list(seen_alerts), file)


# --------------------------------------------------
# Get process information
# --------------------------------------------------

def get_process_info(process):

    try:

        info = process.info

        return {
            "pid": info["pid"],
            "name": info["name"] or "unknown",
            "username": info["username"] or "unknown",
            "exe": info["exe"] or "",
            "cmdline": info["cmdline"] or []
        }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess
    ):

        return None


# --------------------------------------------------
# Calculate risk score
# --------------------------------------------------

def calculate_score(info, baseline):

    score = 0
    reasons = []

    process_identity = (
        info["name"],
        info["exe"],
        info["username"]
    )

    # --------------------------------------------------
    # 1. New process
    # --------------------------------------------------

    if process_identity not in baseline:

        score += 1
        reasons.append("New process")


    # --------------------------------------------------
    # 2. Suspicious executable path
    # --------------------------------------------------

    exe = info["exe"]

    if exe:

        for path in SUSPICIOUS_PATHS:

            if exe.startswith(path):

                score += 3

                reasons.append(
                    f"Executable from suspicious path: {path}"
                )

                break


    # --------------------------------------------------
    # 3. Suspicious command line
    # --------------------------------------------------

    cmdline = info.get("cmdline") or []

    command = " ".join(cmdline)

    for path in SUSPICIOUS_PATHS:

        if path in command:

            score += 3

            reasons.append(
                f"Command line references suspicious path: {path}"
            )

            break


    # --------------------------------------------------
    # 4. Running as root
    # --------------------------------------------------

    if info["username"] == "root":

        score += 1
        reasons.append("Running as root")


    # --------------------------------------------------
    # 5. High CPU usage
    # --------------------------------------------------

    try:

        process = psutil.Process(info["pid"])

        cpu = process.cpu_percent(interval=0.1)

        if cpu > 80:

            score += 1

            reasons.append(
                f"High CPU usage ({cpu:.1f}%)"
            )

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied
    ):

        pass


    return score, reasons


# --------------------------------------------------
# Write alert
# --------------------------------------------------

def write_alert(info, score, reasons):

    timestamp = time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    command = " ".join(
        info.get("cmdline") or []
    )

    message = (
        f"{timestamp} | PROCESS_ALERT | "
        f"process={info['name']} | "
        f"pid={info['pid']} | "
        f"user={info['username']} | "
        f"command={command} | "
        f"score={score} | "
        f"reasons={'; '.join(reasons)}\n"
    )

    with open(ALERT_LOG, "a") as file:

        file.write(message)


# --------------------------------------------------
# Main detection
# --------------------------------------------------

def main():

    print("=== Process Detection ===")
    print()

    baseline = load_baseline()

    seen_alerts = load_seen_alerts()

    current_alerts = set()

    suspicious_count = 0


    for process in psutil.process_iter(
        [
            "pid",
            "name",
            "username",
            "exe",
            "cmdline"
        ]
    ):

        info = get_process_info(process)

        if info is None:
            continue


        score, reasons = calculate_score(
            info,
            baseline
        )


        # Unique ID for THIS running process
        #
        # PID makes sure that if the process disappears
        # and starts again, we can generate a new alert.

        alert_id = (
            f"{info['pid']}|"
            f"{info['name']}|"
            f"{' '.join(info['cmdline'])}"
        )


        # Remember that this process currently exists

        if score >= ALERT_THRESHOLD:

            current_alerts.add(alert_id)


            # Don't repeatedly alert for the same process

            if alert_id not in seen_alerts:

                write_alert(
                    info,
                    score,
                    reasons
                )

                print("🚨 PROCESS ALERT")
                print("Process:", info["name"])
                print("PID:", info["pid"])
                print("User:", info["username"])
                print(
                    "Command:",
                    " ".join(info["cmdline"])
                )
                print("Risk Score:", score)
                print("Reasons:")

                for reason in reasons:

                    print(" -", reason)

                print()

                suspicious_count += 1

                seen_alerts.add(alert_id)


    # Remove processes that no longer exist
    #
    # This means if the same process starts again later,
    # it can generate a fresh alert.

    seen_alerts = seen_alerts.intersection(
        current_alerts
    )

    save_seen_alerts(seen_alerts)


    print("Process scan completed.")
    print()

    print("=== Detection Summary ===")

    if suspicious_count == 0:

        print(
            "No NEW suspicious processes detected."
        )

    else:

        print(
            f"New suspicious processes detected: "
            f"{suspicious_count}"
        )


# --------------------------------------------------
# Start
# --------------------------------------------------

if __name__ == "__main__":

    main()
