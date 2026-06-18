# Python Security Log Analyzer

A Python IT automation project that analyzes security log files, extracts IP addresses, classifies event types, assigns severity levels, and exports CSV and TXT reports.

## Features

- Parse log files
- Extract IP addresses
- Detect security event types
- Count event appearances
- Assign severity levels
- Generate CSV reports
- Generate TXT summary reports
- Run from the command line

## Project Structure

```text
python-security-log-analyzer/
│
├── src/
│   └── security_summary.py
│
├── sample_logs/
│   ├── system.log
│   └── security.log
│
├── reports/
│   └── .gitkeep
│
├── README.md
├── requirements.txt
└── .gitignore