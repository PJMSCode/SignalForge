from engine.loader import load_all_logs
from detections.brute_force import detect_brute_force


def main() -> None:
    logs = load_all_logs()

    '''
    for log_type, records in logs.items():
        print(f"{log_type}: {len(records)} records loaded")
    '''


    brute_force_alerts = detect_brute_force(logs["auth"])

    print("Generated Alerts:")
    for alert in brute_force_alerts:
        print(alert)

if __name__ == "__main__":
    main()