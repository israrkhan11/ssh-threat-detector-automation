import time

from config import LOG_FILE
from config import FAILED_THRESHOLD
from config import ALERT_FILE
from config import REPORT_FILE

from analyzer import parse_failed_logins
from analyzer import detect_threats


def read_logs():

    try:

        with open(LOG_FILE, "r") as file:
            return file.readlines()

    except PermissionError:
        print("[ERROR] Run script with sudo!")
        return []


def write_alert(message):

    with open(ALERT_FILE, "a") as file:
        file.write(message + "\n")


def generate_report(threats):

    with open(REPORT_FILE, "w") as file:

        file.write("=== INCIDENT REPORT ===\n\n")

        for ip, count in threats.items():

            file.write(f"Threat IP: {ip}\n")
            file.write(f"Failed Attempts: {count}\n")
            file.write("Attack Type: SSH Brute Force\n")
            file.write("MITRE ATT&CK: T1110\n")
            file.write("Status: DETECTED\n")
            file.write("------------------------\n")


def monitor():

    print("[INFO] Monitoring started...")

    logs = read_logs()

    ip_counts = parse_failed_logins(logs)

    threats = detect_threats(ip_counts, FAILED_THRESHOLD)

    if threats:

        print("[ALERT] Threat detected!")

        for ip, count in threats.items():

            message = f"[ALERT] IP: {ip} | Failed Attempts: {count}"

            print(message)

            write_alert(message)

        generate_report(threats)

    else:
        print("[OK] No suspicious activity.")


if __name__ == "__main__":

    while True:

        monitor()

        time.sleep(60)
