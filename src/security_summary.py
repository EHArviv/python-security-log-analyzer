from pathlib import Path
import re
import csv
import sys
from collections import defaultdict, Counter


def detect_event_type(line):
    if "Failed login attempt" in line:
        return "Failed login"
    elif "logged in successfully" in line:
        return "Login success"
    elif "Service nginx is not responding" in line:
        return "Service down"
    elif "Disk usage is above" in line:
        return "High disk usage"
    elif "CPU usage is above" in line:
        return "High CPU usage"
    else:
        return "Other"


def detect_severity(event_type, count):
    if event_type == "Failed login" and count >= 3:
        return "High"
    elif event_type == "Failed login" and count == 2:
        return "Medium"
    elif event_type == "Failed login" and count == 1:
        return "Low"
    elif event_type in ["Service down", "High disk usage", "High CPU usage"]:
        return "Medium"
    elif event_type == "Login success":
        return "Info"
    else:
        return "Low"


def analyze_log(log_file):
    events = defaultdict(int)
    all_ips = []

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            found_ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)

            if found_ips:
                event_type = detect_event_type(line)

                for ip in found_ips:
                    events[(ip, event_type)] += 1
                    all_ips.append(ip)

    return events, all_ips


def create_reports(log_file, events, all_ips):
    reports_folder = Path("reports")
    reports_folder.mkdir(parents=True, exist_ok=True)

    csv_report_file = reports_folder / "advanced_security_report.csv"
    summary_report_file = reports_folder / "security_summary_report.txt"

    severity_counter = Counter()

    for (ip, event_type), count in events.items():
        severity = detect_severity(event_type, count)
        severity_counter[severity] += 1

    with csv_report_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["ip_address", "count", "event_type", "severity"])

        for (ip, event_type), count in events.items():
            severity = detect_severity(event_type, count)
            writer.writerow([ip, count, event_type, severity])

    failed_login_ips = {
        ip: count
        for (ip, event_type), count in events.items()
        if event_type == "Failed login"
    }

    if failed_login_ips:
        most_suspicious_ip = max(failed_login_ips, key=failed_login_ips.get)
        most_suspicious_count = failed_login_ips[most_suspicious_ip]
        suspicious_reason = f"Failed login appeared {most_suspicious_count} times"
    else:
        most_suspicious_ip = "None"
        suspicious_reason = "No failed login events found"

    with summary_report_file.open("w", encoding="utf-8") as file:
        file.write("Security Summary Report\n")
        file.write("-----------------------\n")
        file.write(f"Log file analyzed: {log_file}\n")
        file.write(f"Total unique IPs found: {len(set(all_ips))}\n")
        file.write(f"Total IP appearances: {len(all_ips)}\n")
        file.write("\n")

        file.write("Severity Summary\n")
        file.write("----------------\n")
        file.write(f"High severity events: {severity_counter.get('High', 0)}\n")
        file.write(f"Medium severity events: {severity_counter.get('Medium', 0)}\n")
        file.write(f"Low severity events: {severity_counter.get('Low', 0)}\n")
        file.write(f"Info events: {severity_counter.get('Info', 0)}\n")
        file.write("\n")

        file.write("Most Suspicious IP\n")
        file.write("------------------\n")
        file.write(f"IP address: {most_suspicious_ip}\n")
        file.write(f"Reason: {suspicious_reason}\n")
        file.write("\n")

        file.write("Detailed Events\n")
        file.write("---------------\n")

        for (ip, event_type), count in events.items():
            severity = detect_severity(event_type, count)
            file.write(f"{ip} | {count} times | {event_type} | {severity}\n")

    print("Reports created successfully!")
    print(f"CSV report: {csv_report_file}")
    print(f"Summary report: {summary_report_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("python security_summary.py <path_to_log_file>")
        print()
        print("Example:")
        print(
            "python security_summary.py it_automation_practice/it_automation_practice/logs/system.log"
        )
        return

    log_file = Path(sys.argv[1])

    if not log_file.exists():
        print(f"Error: Log file not found: {log_file}")
        return

    if not log_file.is_file():
        print(f"Error: This path is not a file: {log_file}")
        return

    events, all_ips = analyze_log(log_file)

    if not events:
        print("No IP-based events found in the log file.")
        return

    create_reports(log_file, events, all_ips)


if __name__ == "__main__":
    main()
