from flask import Flask, render_template
import json
import os

app = Flask(__name__)

ALERT_FILE = os.path.join("..", "alerts", "alerts.json")


def load_alerts():
    if not os.path.exists(ALERT_FILE):
        return []

    with open(ALERT_FILE, "r", encoding="utf-8") as f:
        alerts = json.load(f)

    # Sort by risk score (highest first)
    alerts.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return alerts


@app.route("/")
def index():
    alerts = load_alerts()
    return render_template("index.html", alerts=alerts)


if __name__ == "__main__":
    app.run(debug=True)
