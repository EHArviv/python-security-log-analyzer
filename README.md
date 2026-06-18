# Python Security Log Analyzer

A Python IT automation project that analyzes security log files, extracts IP addresses, classifies security events, assigns severity levels, and generates CSV, TXT, JSON, and blocklist reports.

## Features

- Parse security log files
- Extract IP addresses using Regex
- Detect security event types
- Count event appearances
- Assign severity levels
- Generate CSV reports
- Generate TXT summary reports
- Generate JSON reports
- Create a suspicious IP blocklist
- Run from the command line

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