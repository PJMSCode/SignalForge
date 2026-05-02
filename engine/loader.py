import json
from pathlib import Path
from typing import Any


# Resolve base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Path to the folder containing all log data
DATA_DIR = BASE_DIR / "data"


def load_json_file(file_name: str) -> list[dict[str, Any]]:
    """
    Loads a JSON log file from the data directory.

    Why this exists:
    In real security systems, logs come from multiple sources (SIEM, EDR, IAM).
    This function simulates centralized log ingestion.

    Args:
        file_name: Name of the JSON file to load

    Returns:
        A list of log records (each record is a dictionary)

    Raises:
        FileNotFoundError: If the file does not exist
        ValueError: If the file is not structured as a list
    """
    file_path = DATA_DIR / file_name

    # Ensure the file exists before attempting to load
    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    # Load JSON data from file
    with file_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    # Validate that the data is a list of records
    if not isinstance(data, list):
        raise ValueError(f"{file_name} must contain a JSON array of log records.")

    return data


def load_auth_logs() -> list[dict[str, Any]]:
    """
    Loads authentication-related logs.

    These logs simulate login attempts, including success/failure events.
    Used for detecting brute force attacks and suspicious login behavior.
    """
    return load_json_file("auth_logs.json")


def load_identity_logs() -> list[dict[str, Any]]:
    """
    Loads identity-related logs.

    These logs simulate account creation, role assignment, and privilege changes.
    Used for detecting identity-based attacks like privilege escalation.
    """
    return load_json_file("identity_logs.json")


def load_endpoint_logs() -> list[dict[str, Any]]:
    """
    Loads endpoint-related logs.

    These logs simulate process execution on machines.
    Used for detecting suspicious binaries, scripts, or abnormal behavior.
    """
    return load_json_file("endpoint_logs.json")


def load_all_logs() -> dict[str, list[dict[str, Any]]]:
    """
    Aggregates all log sources into a single structure.

    Why this matters:
    Detection systems typically correlate across multiple log sources.
    This function simulates a unified data pipeline feeding the detection engine.

    Returns:
        Dictionary mapping log types to their records
    """
    return {
        "auth": load_auth_logs(),
        "identity": load_identity_logs(),
        "endpoint": load_endpoint_logs(),
    }