import psutil
import json
import os
import time


# =========================
# CONFIGURATION
# =========================

BASELINE_FILE = "process_baseline.json"
ALERT_LOG = "alerts.log"

# Score required to generate an alert
ALERT_THRESHOLD = 3

# Paths that are commonly worth investigating
SUSPICIOUS_PATHS = [
    "/tmp",
    "/dev/shm"
]


# =========================
# LOAD BASELINE
# =========================

def load_baseline():

    if not os.path.exists(BASELINE_FILE):
        return set()

    with open(BASELINE_FILE, "r") as file:
        data = json.load(file)

    baseline = set()

    for item in data:
        baseline.add(tuple(item))

    return baseline


# =========================
# GET CURRENT PROCESSES
# =========================

def get_processes():

    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "username", "exe", "cmdline"]
    ):

        try:

            info = process.info

            processes.append(info)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied
        ):
            continue

    return processes


# =========================
# CREATE PROCESS IDENTITY
# =========================

def process_identity(info):

    return (
        info["name"],
        info["exe"],
        info["username"]
    )


# =========================
# DETECT SUSPICIOUS BEHAVIOR
# =========================

def analyze_process(info, baseline):

    score = 0
    reasons = []

    name = info["name"] or "unknown"
    exe = info["exe"] or ""
    username = info["username"] or "unknown"

    # -------------------------
    # 1. New process
    # -------------------------

    identity = process_identity(info)

    if identity not in baseline:

        score += 1

        reasons.append(
            "Process not present in baseline"
        )

    # -------------------------
    # 2. Executable from
    #    suspicious path
    # -------------------------

    for path in SUSPICIOUS_PATHS:

        if exe.startswith(path):

            score += 3

            reasons.append(
                f"Executable from suspicious path: {path}"
            )

            break

    # -------------------------
    # 3. Suspicious command line
    # -------------------------

    cmdline = info.get("cmdline") or []

    command = " ".join(cmdline)

    for path in SUSPICIOUS_PATHS:

        if path in command:

            score += 3

            reasons.append(
                f"Command line references suspicious path: {path}"
            )

            break

    # -------------------------
    # 4. Running as root
    # -------------------------

    if username == "root":

        score += 1

        reasons.append(
            "Running as root"
        )

    # -------------------------
    # 5. High CPU
    # -------------------------

    try:

        process = psutil.Process(info["pid"])

        cpu = process.cpu_percent(interval=0.1)

        if cpu > 80:

            score += 1

            reasons.append(
                f"High CPU usage: {cpu:.1f}%"
            )

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied
    ):

        pass

    return score, reasons


# =========================
# WRITE ALERT
# =========================

def write_alert(info, score, reasons):

    timestamp = time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    name = info["name"] or "unknown"
    pid = info["pid"]
    username = info["username"] or "unknown"

    command = " ".join(
        info.get("cmdline") or []
    )

    with open(ALERT_LOG, "a") as file:

        file.write(
            f"{timestamp} | PROCESS_ALERT | "
            f"process={name} | "
            f"pid={pid} | "
            f"user={username} | "
            f"score={score} | "
            f"command={command} | "
            f"reasons={'; '.join(reasons)}\n"
        )

    print("🚨 PROCESS ALERT")
    print("Process:", name)
    print("PID:", pid)
    print("User:", username)
    print("Command:", command)
    print("Risk Score:", score)

    print("Reasons:")

    for reason in reasons:

        print(" -", reason)

    print()


# =========================
# MAIN DETECTION
# =========================

def main():

    print("=== Process Detection ===")
    print()

    baseline = load_baseline()

    processes = get_processes()

    alerts = 0

    for info in processes:

        score, reasons = analyze_process(
            info,
            baseline
        )

        if score >= ALERT_THRESHOLD:

            write_alert(
                info,
                score,
                reasons
            )

            alerts += 1

    print("Process scan completed.")
    print()

    print("=== Detection Summary ===")

    if alerts == 0:

        print("No suspicious processes detected.")

    else:

        print(
            f"Suspicious processes detected: {alerts}"
        )


# =========================
# START PROGRAM
# =========================

if __name__ == "__main__":
    main()
