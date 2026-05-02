from typing import Any, Callable


# A detection rule is a function that:
# - takes in logs
# - returns a list of alerts
DetectionRule = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]


class RuleEngine:
    """
    The RuleEngine is responsible for:
    - Registering detection rules
    - Executing those rules against log data
    - Aggregating alerts

    Why this matters:
    In real systems, detection logic is modular and extensible.
    This design allows us to easily add new detections without modifying core logic.
    """

    def __init__(self) -> None:
        # Stores rules grouped by log type (auth, identity, endpoint)
        self.rules: dict[str, list[DetectionRule]] = {}

    def register_rule(self, log_type: str, rule: DetectionRule) -> None:
        """
        Registers a detection rule for a specific log type.

        Args:
            log_type: Type of logs the rule applies to (e.g., "auth")
            rule: Detection function

        Why this matters:
        This allows separation between:
        - data ingestion
        - detection logic
        making the system scalable and maintainable
        """
        if log_type not in self.rules:
            self.rules[log_type] = []

        self.rules[log_type].append(rule)

    def run(self, logs: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        """
        Executes all registered detection rules against the provided logs.

        Args:
            logs: Dictionary of log data grouped by type

        Returns:
            A combined list of all generated alerts

        How it works:
        - Iterates through each log type
        - Applies all relevant rules
        - Collects and returns alerts
        """
        alerts = []

        for log_type, log_records in logs.items():

            # Retrieve rules associated with this log type
            for rule in self.rules.get(log_type, []):

                # Run detection rule and collect alerts
                rule_alerts = rule(log_records)

                alerts.extend(rule_alerts)

        return alerts