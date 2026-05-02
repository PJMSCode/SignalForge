import json
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


def load_json_file(file_name: str) -> list[dict[str, Any]]:
    """
    Loads a JSON log file from the data directory.

    Args:
        file_name: Name of the JSON file to load.

    Returns:
        A list of log records.

    Raises:
        FileNotFoundError: If the log file does not exist.
        ValueError: If the file does not contain a JSON list.
    """
    file_path = DATA_DIR / file_name

    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(f"{file_name} must contain a JSON array of log records.")

    return data


def load_auth_logs() -> list[dict[str, Any]]:
    return load_json_file("auth_logs.json")


def load_identity_logs() -> list[dict[str, Any]]:
    return load_json_file("identity_logs.json")


def load_endpoint_logs() -> list[dict[str, Any]]:
    return load_json_file("endpoint_logs.json")


def load_all_logs() -> dict[str, list[dict[str, Any]]]:
    return {
        "auth": load_auth_logs(),
        "identity": load_identity_logs(),
        "endpoint": load_endpoint_logs(),
    }

from engine.loader import load_all_logs


def main() -> None:
    logs = load_all_logs()

    for log_type, records in logs.items():
        print(f"{log_type}: {len(records)} records loaded")


if __name__ == "__main__":
    main()