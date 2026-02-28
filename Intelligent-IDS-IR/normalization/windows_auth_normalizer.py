from datetime import datetime

INPUT_FILE = "auth_logs.txt"
OUTPUT_FILE = "normalized_auth.log"

# Accounts that should be ignored (Windows noise)
SYSTEM_ACCOUNTS = {
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE"
}


def is_noise_account(username):
    """
    Returns True if the account is a known system/service account.
    """
    if not username:
        return True

    if username in SYSTEM_ACCOUNTS:
        return True

    if username.endswith("$"):
        return True

    if username.startswith("DWM-"):
        return True

    if username.startswith("UMFD-"):
        return True

    return False


def normalize_windows_auth_logs():
    normalized_events = []

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    current_event = {}

    for line in lines:
        line = line.strip()

        # Start of a new event block
        if line.startswith("Event["):
            current_event = {}

        # Extract Event ID
        if line.startswith("Event ID:"):
            current_event["event_id"] = line.split("Event ID:")[1].strip()

        # Extract timestamp (ISO format)
        if line.startswith("Date:"):
            date_str = line.split("Date:")[1].strip()
            try:
                current_event["timestamp"] = datetime.fromisoformat(date_str)
            except ValueError:
                continue

        # Extract username
        if line.startswith("Account Name:"):
            current_event["user"] = line.split("Account Name:")[1].strip()

        # Normalize once all fields are present
        if (
            "event_id" in current_event
            and "timestamp" in current_event
            and "user" in current_event
        ):
            event_id = current_event["event_id"]
            user = current_event["user"]

            if event_id == "4625":
                status = "failed"
            elif event_id == "4624":
                status = "success"
            else:
                continue

            # Filter noise ONLY for successful logins
            if status == "success" and is_noise_account(user):
                current_event = {}
                continue

            normalized_line = (
                f"{current_event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} | "
                f"user={user} | "
                f"action=login | "
                f"status={status}"
            )

            normalized_events.append(normalized_line)
            current_event = {}

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        for event in normalized_events:
            out.write(event + "\n")

    print("[+] Normalization complete")
    print(f"[+] Output written to: {OUTPUT_FILE}")
    print(f"[+] Total events normalized: {len(normalized_events)}")


if __name__ == "__main__":
    normalize_windows_auth_logs()
