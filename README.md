# Python Security Log Analyzer

A Python IT automation project that analyzes security log files, extracts IP addresses, classifies security events, assigns severity levels, and generates CSV, TXT, JSON, and blocklist reports.

## Features

* Parse security log files
* Extract IP addresses using Regex
* Detect security event types
* Count event appearances
* Assign severity levels
* Generate CSV reports
* Generate TXT summary reports
* Generate JSON reports
* Create a suspicious IP blocklist
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

The script generates the following files locally inside the `reports/` folder:

```text
advanced_security_report.csv
security_summary_report.txt
security_report.json
blocklist.txt
```

These generated report files are ignored by Git and should not be committed to the repository.

## Example Summary Output

```text
Security Summary Report - V2
----------------------------
Total unique IPs found: 3
Total IP appearances: 4

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

Blocklist
---------
10.0.0.45
```

## Blocklist Logic

The V2 script creates a `blocklist.txt` file for suspicious IP addresses.

By default, an IP address is added to the blocklist when it has at least 2 failed login attempts.

```python
FAILED_LOGIN_BLOCK_THRESHOLD = 2
```

## Requirements

No external dependencies are required.

This project uses only Python standard library modules:

* pathlib
* re
* csv
* sys
* json
* collections

## Skills Demonstrated

* Python automation
* File handling
* Log parsing
* Regex
* CSV report generation
* JSON report generation
* TXT summary generation
* Command-line arguments
* Basic security event analysis
* Suspicious IP detection
* IT automation workflow

## Example Resume Description

Built a Python security automation tool that parses log files, extracts IP addresses, classifies event types, assigns severity levels, generates CSV/TXT/JSON reports, and creates a suspicious IP blocklist.
