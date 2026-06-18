# Python Security Log Analyzer

A Python security automation tool that analyzes log files, extracts IP addresses, classifies security events, assigns severity levels, and generates multiple report formats for IT, Security, SOC, and SIEM workflows.

## Features

* Parse security log files
* Extract IP addresses using Regex
* Detect security event types
* Count event appearances
* Assign severity levels
* Generate CSV reports
* Generate TXT summary reports
* Generate JSON reports
* Generate SOC-style alerts
* Generate NDJSON events for SIEM-style ingestion
* Create a suspicious IP blocklist
* Create an IOC list
* Run from the command line

## Project Structure

```text
python-security-log-analyzer/
├── src/
│   ├── security_summary.py
│   └── security_summary_v2.py
├── sample_logs/
│   ├── system.log
│   └── security.log
├── reports/
│   └── .gitkeep
├── README.md
├── requirements.txt
└── .gitignore
```

## Script Versions

This project includes two script versions:

### V1 - `security_summary.py`

The first version analyzes a log file, extracts IP addresses, classifies security events, assigns severity levels, and generates CSV and TXT summary reports.

V1 is useful for understanding the basic automation workflow:

```text
Log file → Python analysis → CSV/TXT reports
```

### V2 - `security_summary_v2.py`

The second version includes all V1 capabilities and adds more advanced reporting and SOC/SIEM-friendly output formats.

V2 adds:

* JSON report generation
* SOC-style `alerts.json`
* SIEM-style `events.ndjson`
* Suspicious IP `blocklist.txt`
* IOC list generation with `iocs.txt`
* Blocklist threshold logic
* Cleaner function-based structure

V2 is the recommended version to run.

## Usage

Run the V2 script from the project root:

```bash
python src/security_summary_v2.py sample_logs/system.log
```

You can also analyze another sample log:

```bash
python src/security_summary_v2.py sample_logs/security.log
```

## Generated Reports

The V2 script generates the following files locally inside the `reports/` folder:

```text
advanced_security_report.csv
security_summary_report.txt
security_report.json
alerts.json
events.ndjson
blocklist.txt
iocs.txt
```

These generated report files are ignored by Git and should not be committed to the repository.

## Report Types

### CSV Report

```text
advanced_security_report.csv
```

Used for spreadsheet-based analysis, filtering, sorting, and manual review.

### TXT Summary

```text
security_summary_report.txt
```

Used for a human-readable summary of the analyzed log file.

### JSON Report

```text
security_report.json
```

Used for automation, dashboards, APIs, or integration with other tools.

### Alerts JSON

```text
alerts.json
```

Used to represent SOC-style alerts in a structured format.

Example alert:

```json
{
  "alert_name": "Repeated Failed Login",
  "severity": "Medium",
  "source_ip": "10.0.0.45",
  "event_type": "Failed login",
  "count": 2,
  "generated_at": "2026-06-18T13:00:00+00:00",
  "recommendation": "Review authentication logs and consider blocking or monitoring this IP."
}
```

### NDJSON Events

```text
events.ndjson
```

Used for SIEM-style log ingestion.

Each line is a separate JSON event.

Example event:

```json
{"timestamp":"2026-06-18T13:00:00+00:00","event_type":"Failed login","source_ip":"10.0.0.45","count":2,"severity":"Medium","message":"Failed login detected for 10.0.0.45 2 time(s)."}
```

### Blocklist

```text
blocklist.txt
```

Used for suspicious IP blocking workflows.

### IOC List

```text
iocs.txt
```

Used for Indicators of Compromise documentation and investigation workflows.

## Example Summary Output

```text
Security Summary Report - V2
----------------------------
Log file analyzed: sample_logs/system.log
Total unique IPs found: 3
Total IP appearances: 4
Total alerts generated: 1

Severity Summary
----------------
High severity events: 0
Medium severity events: 1
Low severity events: 1
Info events: 1

Most Suspicious IP
------------------
IP address: 10.0.0.45
Reason: Failed login appeared 2 times

Blocklist / IOCs
----------------
10.0.0.45
```

## Blocklist Logic

The V2 script creates a `blocklist.txt` file and an `iocs.txt` file for suspicious IP addresses.

By default, an IP address is added when it has at least 2 failed login attempts.

```python
FAILED_LOGIN_BLOCK_THRESHOLD = 2
```

If an IP address meets or exceeds this threshold, it is added to:

```text
reports/blocklist.txt
reports/iocs.txt
```

## V1 vs V2 Comparison

| Feature                        | V1: `security_summary.py` | V2: `security_summary_v2.py` |
| ------------------------------ | ------------------------- | ---------------------------- |
| Read log file                  | Yes                       | Yes                          |
| Extract IP addresses           | Yes                       | Yes                          |
| Detect event types             | Yes                       | Yes                          |
| Assign severity levels         | Yes                       | Yes                          |
| Generate CSV report            | Yes                       | Yes                          |
| Generate TXT summary report    | Yes                       | Yes                          |
| Generate JSON report           | No                        | Yes                          |
| Generate SOC alerts            | No                        | Yes                          |
| Generate NDJSON events         | No                        | Yes                          |
| Create suspicious IP blocklist | No                        | Yes                          |
| Create IOC list                | No                        | Yes                          |
| Block threshold logic          | No                        | Yes                          |
| Recommended version            | No                        | Yes                          |

## SOC / SIEM Outputs

This project generates multiple output formats commonly used in security operations:

* CSV for spreadsheet-based review
* TXT for human-readable summaries
* JSON for automation, dashboards, and APIs
* `alerts.json` for SOC-style alert records
* `events.ndjson` for SIEM/log ingestion workflows
* `blocklist.txt` for suspicious IP blocking workflows
* `iocs.txt` for Indicators of Compromise

## Requirements

No external dependencies are required.

This project uses only Python standard library modules:

* pathlib
* re
* csv
* sys
* json
* datetime
* collections

## Skills Demonstrated

* Python automation
* File handling
* Log parsing
* Regex
* CSV report generation
* TXT summary generation
* JSON report generation
* NDJSON event generation
* SOC-style alert generation
* IOC extraction
* Suspicious IP detection
* Command-line arguments
* Basic security event analysis
* SOC/SIEM-friendly output formats
* IT/Security automation workflow

## Example Resume Description

Built a Python security automation tool that parses log files, extracts IP addresses, classifies event types, assigns severity levels, generates CSV/TXT/JSON/NDJSON reports, creates SOC-style alerts, and exports suspicious IP blocklists and IOC lists for security monitoring workflows.
