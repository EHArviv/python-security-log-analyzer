from pathlib import Path
import re
import csv
import sys
import json
from collections import defaultdict, Counter


FAILED_LOGIN_BLOCK_THRESHOLD = 2


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


def extract_ips(line):
    return re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)


def analyze_log(log_file):
    events = defaultdict(int)
    all_ips = []

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            found_ips = extract_ips(line)

            if found_ips:
                event_type = detect_event_type(line)

                for ip in found_ips:
                    events[(ip, event_type)] += 1
                    all_ips.append(ip)

    return events, all_ips


def build_report_rows(events):
    rows = []

    for (ip, event_type), count in events.items():
        severity = detect_severity(event_type, count)

        rows.append(
            {
                "ip_address": ip,
                "count": count,
                "event_type": event_type,
                "severity": severity,
            }
        )

    return rows


def find_most_suspicious_ip(events):
    failed_login_ips = {
        ip: count
        for (ip, event_type), count in events.items()
        if event_type == "Failed login"
    }

    if not failed_login_ips:
        return "None", "No failed login events found"

    most_suspicious_ip = max(failed_login_ips, key=lambda ip: failed_login_ips[ip])
    most_suspicious_count = failed_login_ips[most_suspicious_ip]
    reason = f"Failed login appeared {most_suspicious_count} times"

    return most_suspicious_ip, reason


def create_csv_report(report_rows, csv_report_file):
    with csv_report_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["ip_address", "count", "event_type", "severity"])

        for row in report_rows:
            writer.writerow(
                [
                    row["ip_address"],
                    row["count"],
                    row["event_type"],
                    row["severity"],
                ]
            )


def create_json_report(log_file, report_rows, all_ips, json_report_file):
    data = {
        "log_file_analyzed": str(log_file),
        "total_unique_ips": len(set(all_ips)),
        "total_ip_appearances": len(all_ips),
        "events": report_rows,
    }

    with json_report_file.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def create_blocklist(events, blocklist_file):
    blocked_ips = []

    for (ip, event_type), count in events.items():
        if event_type == "Failed login" and count >= FAILED_LOGIN_BLOCK_THRESHOLD:
            blocked_ips.append(ip)

    with blocklist_file.open("w", encoding="utf-8") as file:
        for ip in blocked_ips:
            file.write(f"{ip}\n")

    return blocked_ips


def create_summary_report(
    log_file,
    report_rows,
    all_ips,
    summary_report_file,
    most_suspicious_ip,
    suspicious_reason,
    blocked_ips,
):
    severity_counter = Counter(row["severity"] for row in report_rows)

    with summary_report_file.open("w", encoding="utf-8") as file:
        file.write("Security Summary Report - V2\n")
        file.write("----------------------------\n")
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

        file.write("Blocklist\n")
        file.write("---------\n")

        if blocked_ips:
            for ip in blocked_ips:
                file.write(f"{ip}\n")
        else:
            file.write("No IPs added to blocklist\n")

        file.write("\n")
        file.write("Detailed Events\n")
        file.write("---------------\n")

        for row in report_rows:
            file.write(
                f"{row['ip_address']} | "
                f"{row['count']} times | "
                f"{row['event_type']} | "
                f"{row['severity']}\n"
            )


def create_reports(log_file, events, all_ips):
    reports_folder = Path("reports")
    reports_folder.mkdir(parents=True, exist_ok=True)

    csv_report_file = reports_folder / "advanced_security_report.csv"
    txt_report_file = reports_folder / "security_summary_report.txt"
    json_report_file = reports_folder / "security_report.json"
    blocklist_file = reports_folder / "blocklist.txt"

    report_rows = build_report_rows(events)
    most_suspicious_ip, suspicious_reason = find_most_suspicious_ip(events)

    create_csv_report(report_rows, csv_report_file)
    create_json_report(log_file, report_rows, all_ips, json_report_file)
    blocked_ips = create_blocklist(events, blocklist_file)

    create_summary_report(
        log_file=log_file,
        report_rows=report_rows,
        all_ips=all_ips,
        summary_report_file=txt_report_file,
        most_suspicious_ip=most_suspicious_ip,
        suspicious_reason=suspicious_reason,
        blocked_ips=blocked_ips,
    )

    print("Reports created successfully!")
    print(f"CSV report: {csv_report_file}")
    print(f"TXT summary report: {txt_report_file}")
    print(f"JSON report: {json_report_file}")
    print(f"Blocklist: {blocklist_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("python src/security_summary_v2.py <path_to_log_file>")
        print()
        print("Example:")
        print("python src/security_summary_v2.py sample_logs/system.log")
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
