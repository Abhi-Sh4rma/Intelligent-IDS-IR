import json
import os
from datetime import datetime

from parser.log_parser import parse_auth_log
from detection.failed_login_time_window import detect_failed_logins_time_window
from alerts.alert_generator import generate_alerts
from scoring.risk_scorer import assign_risk
from response.response_engine import add_response_recommendations

ALERT_OUTPUT_FILE = "alerts/alerts.json"


def normalize_timestamp(ts):
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, str):
        return datetime.fromisoformat(ts)
    return None


def check_success_after_failures(events, alert):
    user = alert["entity"]

    failed_times = []
    success_times = []

    for e in events:
        if e.get("user") != user:
            continue

        ts = normalize_timestamp(e.get("timestamp"))
        if not ts:
            continue

        if e.get("status") == "failed":
            failed_times.append(ts)
        elif e.get("status") == "success":
            success_times.append(ts)

    if not failed_times or not success_times:
        return False

    return max(success_times) > max(failed_times)


def get_last_activity_time(events, alert):
    user = alert["entity"]
    times = []

    for e in events:
        if e.get("user") != user:
            continue

        ts = normalize_timestamp(e.get("timestamp"))
        if ts:
            times.append(ts)

    if not times:
        return "No recent activity"

    return max(times).strftime("%Y-%m-%d %H:%M:%S")


def load_existing_alerts():
    if not os.path.exists(ALERT_OUTPUT_FILE):
        return []

    try:
        with open(ALERT_OUTPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except:
        return []


def main():
    log_file = "shared/normalized_auth.log"

    # 1. Parse logs
    events = parse_auth_log(log_file)

    # 2. Detection (for alert creation only)
    detections = detect_failed_logins_time_window(events)

    # 3. Load existing alerts
    existing_alerts = load_existing_alerts()

    # 4. Alert lifecycle logic
    if detections:
        alerts = generate_alerts(detections)
    elif existing_alerts:
        alerts = existing_alerts
    else:
        alerts = []

    # 5. Real-time enrichment
    for alert in alerts:
        alert["details"]["post_compromise_login"] = check_success_after_failures(events, alert)
        alert["details"]["last_activity_time"] = get_last_activity_time(events, alert)
        alert["status"] = "open"

    # 6. Risk scoring
    alerts = assign_risk(alerts)

    # 7. Response recommendations
    alerts = add_response_recommendations(alerts)

    # 8. Persist alerts
    if alerts:
        with open(ALERT_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=4)

    print("\n=== FINAL SOC ALERTS (WITH LIVE CONTEXT) ===\n")
    print(f"[+] Alerts active: {len(alerts)}")
    for alert in alerts:
        print(alert)
        print("-" * 60)


if __name__ == "__main__":
    main()
