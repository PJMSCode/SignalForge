import json
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"


def save_alerts(alerts: list[dict[str, Any]], file_name: str = "alerts.json") -> None:
    """
    Saves generated alerts to a JSON file.

    Why this matters:
    Real detection systems do not just print alerts.
    They send alerts to SIEMs, SOAR platforms, dashboards, or case management tools.
    This simulates that final alert output stage.
    """
    OUTPUT_DIR.mkdir(exist_ok=True)

    file_path = OUTPUT_DIR / file_name

    with file_path.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)