def detect_failed_logins(events, threshold=5):
    """
    Detects users with excessive failed login attempts.
    Returns a list of detection findings.
    """
    failed_counts = {}
    detections = []

    for event in events:
        if event.get("action") == "login" and event.get("status") == "failed":
            user = event.get("user")

            if user not in failed_counts:
                failed_counts[user] = 0

            failed_counts[user] += 1

    for user, count in failed_counts.items():
        if count >= threshold:
            detection = {
                "rule": "Multiple Failed Login Attempts",
                "entity_type": "user",
                "entity": user,
                "failed_attempts": count
            }
            detections.append(detection)

    return detections
