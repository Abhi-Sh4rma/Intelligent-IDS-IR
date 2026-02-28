import time
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

SHARED_LOG_FILE = r"\\vmware-host\Shared Folders\shared_logs\normalized_auth.log"
POLL_INTERVAL = 10
FETCH_COUNT = 5


def fetch_failed_logons():
    cmd = [
        "wevtutil",
        "qe",
        "Security",
        "/q:*[System[(EventID=4625)]]",
        "/f:xml",
        f"/c:{FETCH_COUNT}"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="ignore"
    )

    return result.stdout


def parse_and_append(xml_data):
    if not xml_data.strip():
        return

    # 🔥 THIS IS THE FIX
    wrapped_xml = "<Events>" + xml_data + "</Events>"

    try:
        root = ET.fromstring(wrapped_xml)
    except Exception as e:
        print("XML parse error:", e)
        return

    with open(SHARED_LOG_FILE, "a", encoding="utf-8") as f:
        for event in root.findall("Event"):
            system = event.find("System")
            eventdata = event.find("EventData")
            if system is None or eventdata is None:
                continue

            time_created = system.find("TimeCreated").attrib["SystemTime"]

            username = "UNKNOWN"
            for data in eventdata.findall("Data"):
                if data.attrib.get("Name") == "TargetUserName":
                    username = (data.text or "UNKNOWN").strip()
                    break

            ts = datetime.fromisoformat(time_created.replace("Z", ""))
            line = (
                f"{ts.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"user={username} | action=login | status=failed"
            )

            f.write(line + "\n")


def main():
    print("[*] Live Auth Collector started (XML WRAPPED – FINAL)")
    while True:
        xml_data = fetch_failed_logons()
        parse_and_append(xml_data)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
