def add_response_recommendations(alerts):
    """
    Adds SOC-style response recommendations based on severity.
    """
    for alert in alerts:
        severity = alert.get("severity")

        if severity == "Medium":
            response = [
                "Monitor further login attempts",
                "Verify user credential issues"
            ]

        elif severity == "High":
            response = [
                "Investigate source IP address",
                "Check for similar attempts on other accounts",
                "Notify SOC Tier-2 if activity continues"
            ]

        elif severity == "Critical":
            response = [
                "Immediate investigation required",
                "Consider temporary account lock",
                "Escalate to security incident response team"
            ]

        else:
            response = ["No action required"]

        alert["recommended_response"] = response

    return alerts
