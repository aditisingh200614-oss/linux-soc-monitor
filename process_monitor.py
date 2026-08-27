import psutil

print("=== Running Processes ===")

for process in psutil.process_iter(["pid", "name", "username", "cpu_percent"]):

    try:
        info = process.info

        print(
            "PID:", info["pid"],
            "| Process:", info["name"],
            "| User:", info["username"],
            "| CPU:", info["cpu_percent"], "%"
        )

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue
