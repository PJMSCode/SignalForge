from typing import Any


# Processes that are commonly abused by attackers.
# These are not malicious by default, but their context matters.
HIGH_RISK_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

# File paths that are commonly abused for suspicious execution.
# Normal software usually runs from Program Files or Windows directories.
SUSPICIOUS_PATH_KEYWORDS = {
    "downloads",
    "temp",
    "appdata",
}

# Parent processes that can be suspicious when launching scripting tools.
SUSPICIOUS_PARENT_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
}


def detect_suspicious_process_execution(
    endpoint_logs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Detection Logic:
    Flags suspicious process execution based on process name, file path,
    and parent-child process relationship.

    Why this matters:
    Endpoint attacks often rely on legitimate tools being launched from unusual
    locations or chained together in suspicious ways.
    """
    alerts = []

    for log in endpoint_logs:
        process_name = log.get("process_name", "").lower()
        path = log.get("path", "").lower()
        parent_process = log.get("parent_process", "").lower()

        reasons = []

        # Check if a commonly abused process is being executed.
        if process_name in HIGH_RISK_PROCESSES:
            reasons.append(f"high-risk process '{process_name}' was executed")

        # Check if the process is running from a suspicious user-writable path.
        if any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS):
            reasons.append(f"process executed from suspicious path '{log.get('path')}'")

        # Check for suspicious parent-child process chaining.
        if parent_process in SUSPICIOUS_PARENT_PROCESSES:
            reasons.append(
                f"process was launched by suspicious parent '{parent_process}'"
            )

        # Generate an alert only if suspicious indicators exist.
        if reasons:
            alerts.append({
                "alert_name": "Suspicious Process Execution",
                "severity": "high",
                "hostname": log.get("hostname"),
                "user": log.get("user"),
                "process_name": log.get("process_name"),
                "path": log.get("path"),
                "parent_process": log.get("parent_process"),
                "timestamp": log.get("timestamp"),
                "mitre_attack": {
                    "technique": "T1059",
                    "name": "Command and Scripting Interpreter"
                },
                "reason": "; ".join(reasons)
            })

    return alerts