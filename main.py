from engine.loader import load_all_logs


def main() -> None:
    logs = load_all_logs()

    for log_type, records in logs.items():
        print(f"{log_type}: {len(records)} records loaded")


if __name__ == "__main__":
    main()