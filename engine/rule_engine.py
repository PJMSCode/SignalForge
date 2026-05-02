from typing import Any, Callable


DetectionRule = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]


class RuleEngine:
    def __init__(self) -> None:
        self.rules: dict[str, list[DetectionRule]] = {}

    def register_rule(self, log_type: str, rule: DetectionRule) -> None:
        if log_type not in self.rules:
            self.rules[log_type] = []

        self.rules[log_type].append(rule)

    def run(self, logs: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        alerts = []

        for log_type, log_records in logs.items():
            for rule in self.rules.get(log_type, []):
                rule_alerts = rule(log_records)
                alerts.extend(rule_alerts)

        return alerts