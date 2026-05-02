from engine.loader import load_all_logs
from engine.rule_engine import RuleEngine
from detections.brute_force import detect_brute_force
from detections.suspicious_admin_creation import detect_suspicious_admin_creation

def main() -> None:
    logs = load_all_logs()

    
    #for log_type, records in logs.items():
    #    print(f"{log_type}: {len(records)} records loaded")
    
    # brute_force_alerts = detect_brute_force(logs["auth"])

    engine = RuleEngine()
    engine.register_rule("auth", detect_brute_force)
    engine.register_rule("identity", detect_suspicious_admin_creation)

    alerts = engine.run(logs)


    print("Generated Alerts:")
    for alert in alerts:
        print(alert)

if __name__ == "__main__":
    main()