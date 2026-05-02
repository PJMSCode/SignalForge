from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any


FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5


def parse_timestamp(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp)


def detect_brute_force(auth_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Detects multiple failed login attempts against the same user
    within a short time window.
    """
    alerts = []
    failed_logins_by_user = defaultdict(list)

    for log in auth_logs:
        if log.get("status") == "failed":
            failed_logins_by_user[log["user"]].append(log)

    for user, failed_logs in failed_logins_by_user.items():
        failed_logs.sort(key=lambda event: parse_timestamp(event["timestamp"]))

        for index in range(len(failed_logs)):
            window_start = parse_timestamp(failed_logs[index]["timestamp"])
            window_end = window_start + timedelta(minutes=TIME_WINDOW_MINUTES)

            events_in_window = [
                event for event in failed_logs
                if window_start <= parse_timestamp(event["timestamp"]) <= window_end
            ]

            if len(events_in_window) >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "alert_name": "Potential Brute Force Login Attempt",
                    "severity": "high",
                    "user": user,
                    "source_ip": events_in_window[0].get("source_ip"),
                    "first_seen": events_in_window[0]["timestamp"],
                    "last_seen": events_in_window[-1]["timestamp"],
                    "event_count": len(events_in_window),
                    "mitre_attack": {
                        "technique": "T1110",
                        "name": "Brute Force"
                    },
                    "reason": (
                        f"{len(events_in_window)} failed login attempts detected "
                        f"for user '{user}' within {TIME_WINDOW_MINUTES} minutes."
                    )
                })
                break

    return alerts