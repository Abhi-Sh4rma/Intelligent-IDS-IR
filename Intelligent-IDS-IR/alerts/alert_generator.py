import json
import uuid
from datetime import datetime


def is_machine_account(entity):
    """
    Determines if the entity is a Windows machine account.
    """
    return entity.endswith("$")


def generate_alerts(detections, output_file="alerts/alerts.json"):
    """
    Converts detections into SOC-style alerts.
    Suppresses alerts for known benign machine accounts.
    """
    alerts = []
    suppressed = 0

    for detection in detections:
        entity = detection["entity"]

        # Suppress machine accounts at alerting stage
        if is_machine_account(entity):
            suppressed += 1
            continue

        alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "rule": detection["rule"],
            "entity_type": detection["entity_type"],
            "entity": entity,
            "details": {
                "failed_attempts": detection["failed_attempts"],
                "time_window_minutes": detection["time_window_minutes"]
            },
            "status": "open"
        }

        alerts.append(alert)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=4)

    print(f"[+] Alerts generated: {len(alerts)}")
    print(f"[+] Alerts suppressed (machine accounts): {suppressed}")

    return alerts
