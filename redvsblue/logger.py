"""SIEM logging helpers for Red vs Blue simulation tool."""

import json
import os
import time
from datetime import datetime, timezone
from typing import Dict

from config import CONFIG
from utils import printc


def log_event(event_type: str, details: Dict[str, object], severity: str = "info") -> None:
    """
    Append an event JSON line to the SIEM log file using ISO 8601 timestamps.

    Args:
        event_type: Type of the event (e.g., LoginSuccess, UnauthorizedFileAccess)
        details: Dictionary with event-specific information
        severity: Logging severity level ('info', 'warning', 'critical')
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    event = {
        "timestamp": timestamp,
        "event": event_type,
        "severity": severity,
        "details": details,
    }
    log_path = CONFIG["LOG_PATH"]
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    try:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
    except OSError:
        # Best-effort logging; do not crash if log fails
        pass


def monitor_logs() -> None:
    """
    Follow the SIEM log in real-time and print critical/warning events to console.
    """
    printc("[+] SIEM Log Monitor Running. Press Ctrl+C to stop.", "yellow")
    try:
        with open(CONFIG["LOG_PATH"], "r", encoding="utf-8") as fh:
            fh.seek(0, os.SEEK_END)
            while True:
                line = fh.readline()
                if line:
                    try:
                        event = json.loads(line.strip())
                        severity = event.get("severity", "").lower()
                        if severity in ("critical", "warning"):
                            printc(
                                f"[ALERT] {event.get('timestamp')} - {event.get('event')}: {event.get('details')}",
                                "red"
                            )
                    except json.JSONDecodeError:
                        continue  # skip malformed lines
                else:
                    time.sleep(1)
    except KeyboardInterrupt:
        printc("[!] Monitoring stopped.", "yellow")
    except FileNotFoundError:
        printc("[!] Log file not found.", "red")

