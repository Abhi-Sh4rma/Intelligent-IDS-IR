from datetime import datetime

def parse_auth_log(file_path):
    """
    Reads normalized authentication logs and converts each line
    into a structured event dictionary.
    """
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            parts = line.split(" | ")

            event = {
                "timestamp": datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S")
            }

            for part in parts[1:]:
                key, value = part.split("=")
                event[key] = value

            events.append(event)

    return events
