from collections import defaultdict
from datetime import datetime, timedelta

failed_attempts = defaultdict(list)
suspicious_users = set()

TIME_WINDOW = timedelta(minutes=5)
THRESHOLD = 3
ALERT_LOG = "alerts.log"

with open("/var/log/auth.log", "r") as file:

    for line in file:

        lower_line = line.lower()

        # Get timestamp
        parts = line.split()
        timestamp = parts[0]

        try:
            event_time = datetime.fromisoformat(timestamp)
        except ValueError:
            continue

        # Get username
        user = "unknown"

        for part in parts:
            if part.startswith("user="):
                user = part.split("=")[1]

            elif part.startswith("ruser="):
                user = part.split("=")[1]

        attempts = 0

        # Case 1: Linux explicitly tells us how many
        # incorrect password attempts happened
        if "incorrect password attempts" in lower_line:

            for part in parts:
                if part.isdigit():
                    attempts = int(part)
                    break

            print("🚨 Failed Authentication")
            print("Time:", timestamp)
            print("User:", user)
            print("Failed Password Attempts:", attempts)

        # Case 2: Linux only reports an authentication failure
        elif "authentication failure" in lower_line:

            attempts = 1

            print("🚨 Authentication Failure")
            print("Time:", timestamp)
            print("User:", user)
            print("Failed Password Attempts:", attempts)

        else:
            continue

        # Add every failed password attempt
        for _ in range(attempts):
            failed_attempts[user].append(event_time)

        # Keep only attempts from the last 5 minutes
        cutoff = event_time - TIME_WINDOW

        failed_attempts[user] = [
            time for time in failed_attempts[user]
            if time >= cutoff
        ]

        attempt_count = len(failed_attempts[user])

        print("Total failures in last 5 minutes:", attempt_count)

        # Detection rule
        if attempt_count >= THRESHOLD:

            suspicious_users.add(user)

            alert_message = (
                f"{timestamp} | BRUTE_FORCE | "
                f"user={user} | attempts={attempt_count}\n"
            )

            print("⚠️ ALERT: Possible Brute Force Attack!")
            print("User added to suspicious list:", user)

            with open(ALERT_LOG, "a") as alert_file:
                alert_file.write(alert_message)

        print()


print("=== Detection Summary ===")

if suspicious_users:

    print("🚨 Suspicious Users:")

    for user in suspicious_users:
        print("-", user)

else:

    print("No suspicious users detected.")
