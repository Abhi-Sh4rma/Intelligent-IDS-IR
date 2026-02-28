from datetime import timedelta

def detect_failed_logins_time_window(events, threshold=5, window_minutes=10):
    """
    Detects multiple failed login attempts within a time window per user.
    """
    user_failures = {}
    detections = []

    for event in events:
        if event.get("action") == "login" and event.get("status") == "failed":
            user = event.get("user")
            timestamp = event.get("timestamp")

            if user not in user_failures:
                user_failures[user] = []

            user_failures[user].append(timestamp)

    for user, timestamps in user_failures.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(minutes=window_minutes)

            count = sum(
                1 for t in timestamps if window_start <= t <= window_end
            )

            if count >= threshold:
                detections.append({
                    "rule": "Multiple Failed Logins in Time Window",
                    "entity_type": "user",
                    "entity": user,
                    "failed_attempts": count,
                    "time_window_minutes": window_minutes
                })
                break

    return detections
