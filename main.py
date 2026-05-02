from engine.loader import load_all_logs
from engine.output import save_alerts
from engine.rule_engine import RuleEngine
from detections.brute_force import detect_brute_force
from detections.suspicious_admin_creation import detect_suspicious_admin_creation
from detections.suspicious_process_execution import detect_suspicious_process_execution

def main() -> None:
    logs = load_all_logs()

    
    #for log_type, records in logs.items():
    #    print(f"{log_type}: {len(records)} records loaded")
    
    # brute_force_alerts = detect_brute_force(logs["auth"])

    engine = RuleEngine()
    engine.register_rule("auth", detect_brute_force)
    engine.register_rule("identity", detect_suspicious_admin_creation)
    engine.register_rule("endpoint", detect_suspicious_process_execution)

    alerts = engine.run(logs)


    #print("Generated Alerts:")
    #for alert in alerts:
    #    print(alert)

    save_alerts(alerts) 

    print(f"Generated {len(alerts)} alerts.")
    print("Alerts saved to output/alerts.json")


if __name__ == "__main__":
    main()