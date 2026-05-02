from engine.loader import load_all_logs
from engine.rule_engine import RuleEngine
from detections.brute_force import detect_brute_force

def main() -> None:
    logs = load_all_logs()

    
    #for log_type, records in logs.items():
    #    print(f"{log_type}: {len(records)} records loaded")
    
    # brute_force_alerts = detect_brute_force(logs["auth"])

    engine = RuleEngine()
    engine.register_rule("auth", detect_brute_force)

    alerts = engine.run(logs)


    print("Generated Alerts:")
    for alert in alerts:
        print(alert)

if __name__ == "__main__":
    main()