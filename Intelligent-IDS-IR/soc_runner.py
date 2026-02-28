import time
import subprocess

print("[*] SOC Engine Auto-Runner started")

while True:
    try:
        subprocess.run(["python", "main.py"], check=True)
    except Exception as e:
        print("SOC engine error:", e)

    time.sleep(10)   # run detection every 10 seconds
