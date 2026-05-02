# SignalForge

SignalForge is a detection engineering simulator that converts raw security logs into explainable, high-confidence alerts.

The goal of this project is to demonstrate how detection engineers think through log analysis, signal quality, alert severity, false positives, MITRE ATT&CK mapping, and security automation without requiring a full enterprise lab.

## What SignalForge Does

SignalForge currently analyzes three types of simulated security logs:

- Authentication logs
- Identity and access management logs
- Endpoint process execution logs

It then runs detection rules against those logs and generates structured alerts.

## Current Detections

| Detection | Log Source | MITRE ATT&CK | Severity |
|---|---|---|---|
| Brute Force Login Attempt | Authentication | T1110 - Brute Force | High |
| Suspicious Admin Account Creation | Identity | T1136 - Create Account | Critical |
| Suspicious Process Execution | Endpoint | T1059 - Command and Scripting Interpreter | High |

## Project Structure

```text
SignalForge/
│
├── data/
│   ├── auth_logs.json
│   ├── endpoint_logs.json
│   └── identity_logs.json
│
├── detections/
│   ├── brute_force.py
│   ├── suspicious_admin_creation.py
│   └── suspicious_process_execution.py
│
├── engine/
│   ├── loader.py
│   ├── output.py
│   └── rule_engine.py
│
├── output/
│   └── alerts.json
│
├── main.py
└── README.md