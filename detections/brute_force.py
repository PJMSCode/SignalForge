from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any


FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5


def parse_timestamp(timestamp: str) -> datetime:
    """
    Converts ISO timestamp string into a datetime object.

    This allows us to perform time-based comparisons,
    which is critical for detecting burst activity like brute force attacks.
    """
    return datetime.fromisoformat(timestamp)


def detect_brute_force(auth_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Detection Logic:
    Identifies potential brute force login attempts by detecting multiple
    failed login attempts against the same user within a short time window.

    Why this matters:
    Brute force attacks typically involve repeated failed logins
    followed by a successful login if credentials are guessed correctly.

    This detection simulates real-world authentication monitoring systems.
    """
    alerts = []

    # Group failed login attempts by user
    failed_logins_by_user = defaultdict(list)

    for log in auth_logs:
        # Only consider failed login attempts
        if log.get("status") == "failed":
            failed_logins_by_user[log["user"]].append(log)

    # Analyze each user's failed login activity
    for user, failed_logs in failed_logins_by_user.items():

        # Sort events chronologically to analyze time windows correctly
        failed_logs.sort(key=lambda event: parse_timestamp(event["timestamp"]))

        # Iterate through each failed login as a potential starting point
        for index in range(len(failed_logs)):

            # Define the start and end of the time window
            window_start = parse_timestamp(failed_logs[index]["timestamp"])
            window_end = window_start + timedelta(minutes=TIME_WINDOW_MINUTES)

            # Collect all failed events within the time window
            events_in_window = [
                event for event in failed_logs
                if window_start <= parse_timestamp(event["timestamp"]) <= window_end
            ]

            # If the number of failed attempts exceeds the threshold, flag it
            if len(events_in_window) >= FAILED_LOGIN_THRESHOLD:

                alerts.append({
                    "alert_name": "Potential Brute Force Login Attempt",
                    "severity": "high",
                    "user": user,
                    "source_ip": events_in_window[0].get("source_ip"),

                    # Track the timeframe of the suspicious activity
                    "first_seen": events_in_window[0]["timestamp"],
                    "last_seen": events_in_window[-1]["timestamp"],
                    "event_count": len(events_in_window),

                    # Map detection to MITRE ATT&CK for industry alignment
                    "mitre_attack": {
                        "technique": "T1110",
                        "name": "Brute Force"
                    },

                    # Human-readable explanation of why the alert fired
                    "reason": (
                        f"{len(events_in_window)} failed login attempts detected "
                        f"for user '{user}' within {TIME_WINDOW_MINUTES} minutes."
                    )
                })

                # Break to avoid duplicate alerts for the same user
                break

    return alerts