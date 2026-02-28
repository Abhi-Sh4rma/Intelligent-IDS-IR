def assign_risk(alerts):
    for alert in alerts:
        failed_attempts = alert["details"].get("failed_attempts", 0)
        post_compromise = alert["details"].get("post_compromise_login", False)

        # DEFAULT VALUES
        severity = "Low"
        risk_score = 20

        # BASED ON FAILED ATTEMPTS
        if failed_attempts >= 10:
            severity = "Critical"
            risk_score = 90
        elif failed_attempts >= 8:
            severity = "High"
            risk_score = 70
        elif failed_attempts >= 5:
            severity = "Medium"
            risk_score = 50

        # 🔥 SOC ESCALATION RULE (NEW)
        # Success after failures = possible credential compromise
        if post_compromise:
            severity = "Critical"
            risk_score = 90

        alert["severity"] = severity
        alert["risk_score"] = risk_score

    return alerts
