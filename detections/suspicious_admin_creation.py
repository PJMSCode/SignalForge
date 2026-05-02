from datetime import datetime, time
from typing import Any


# Business hours used to determine "normal" behavior
BUSINESS_HOURS_START = time(7, 0)
BUSINESS_HOURS_END = time(20, 0)

# Actors that should NOT normally create admin accounts
HIGH_RISK_CREATORS = {"svc_account", "unknown", "temp_user"}


def parse_timestamp(timestamp: str) -> datetime:
    """
    Converts ISO timestamp string into a datetime object.
    This allows us to compare times for behavioral analysis.
    """
    return datetime.fromisoformat(timestamp)


def is_outside_business_hours(timestamp: str) -> bool:
    """
    Determines whether an event occurred outside normal working hours.
    
    Why this matters:
    Admin actions outside business hours are often suspicious and may indicate
    unauthorized activity or compromised accounts.
    """
    event_time = parse_timestamp(timestamp).time()
    return event_time < BUSINESS_HOURS_START or event_time > BUSINESS_HOURS_END


def detect_suspicious_admin_creation(
    identity_logs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Detection Logic:
    Flags admin account creation events that exhibit suspicious behavior.

    Suspicious indicators:
    - Admin account created outside business hours
    - Admin account created by a high-risk or unusual actor

    This simulates identity-based threat detection used in real environments.
    """
    alerts = []

    # Iterate through all identity-related logs
    for log in identity_logs:
        action = log.get("action")
        role_assigned = log.get("role_assigned")
        performed_by = log.get("performed_by")
        timestamp = log.get("timestamp")

        # We only care about account creation events
        if action != "create_user":
            continue

        # Only flag accounts with elevated privileges
        if role_assigned != "admin":
            continue

        reasons = []

        # Check for time-based anomaly
        if timestamp and is_outside_business_hours(timestamp):
            reasons.append("admin account was created outside business hours")

        # Check for suspicious actor behavior
        if performed_by in HIGH_RISK_CREATORS:
            reasons.append(f"account was created by high-risk actor '{performed_by}'")

        # If any suspicious conditions are met, generate an alert
        if reasons:
            alerts.append({
                "alert_name": "Suspicious Admin Account Creation",
                "severity": "critical",
                "target_user": log.get("target_user"),
                "performed_by": performed_by,
                "role_assigned": role_assigned,
                "source_ip": log.get("source_ip"),
                "timestamp": timestamp,

                # Mapping to MITRE ATT&CK for industry alignment
                "mitre_attack": {
                    "technique": "T1136",
                    "name": "Create Account"
                },

                # Human-readable explanation (very important for interviews)
                "reason": "; ".join(reasons)
            })

    return alerts