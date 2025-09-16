"""Utility helpers for Red vs Blue simulation tool."""

import os
import platform
import socket
import time
from datetime import datetime, timedelta
from typing import Optional

from config import CONFIG


def init_environment() -> None:
    """Create directories, the flag file, fake files, and ensure log file exists."""
    flag_dir = os.path.dirname(CONFIG["FLAG_PATH"]) or "."
    log_dir = os.path.dirname(CONFIG["LOG_PATH"]) or "."

    os.makedirs(flag_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    # -----------------------------
    # Ensure log file exists
    # -----------------------------
    if not os.path.exists(CONFIG["LOG_PATH"]):
        with open(CONFIG["LOG_PATH"], "w", encoding="utf-8") as fh:
            fh.write("")  # create empty log file

    # -----------------------------
    # Ensure flag file exists
    # -----------------------------
    if not os.path.exists(CONFIG["FLAG_PATH"]):
        with open(CONFIG["FLAG_PATH"], "w", encoding="utf-8") as fh:
            fh.write("FLAG{you_evaded_detection_and_stole_the_flag}\n")

    # -----------------------------
    # Create fake files
    # -----------------------------
    fake_dir = os.path.join(flag_dir, "")
    for filename, contents in CONFIG["FAKE_FILES"].items():  # type: ignore[arg-type]
        path = os.path.join(fake_dir, filename)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(contents)
        except OSError:
            # best-effort: ignore file creation problems in constrained envs
            pass

def os_banner() -> str:
    """Return a short OS/host banner string."""
    return f"{platform.system()} {platform.release()} | Host: {socket.gethostname()}"


def printc(message: str, color: str = "green") -> None:
    """Print a message optionally with ANSI color codes (if enabled)."""
    if not CONFIG.get("COLOR", True):
        print(message)
        return

    codes = {"red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m", "end": "\033[0m"}
    color_code = codes.get(color, "")
    end_code = codes["end"]
    print(f"{color_code}{message}{end_code}")


def rotate_logs() -> None:
    """Rotate SIEM log file if older than retention days (best-effort)."""
    try:
        log_path = CONFIG["LOG_PATH"]
        if not os.path.exists(log_path):
            return

        modified_time = datetime.fromtimestamp(os.path.getmtime(log_path))
        retention = int(CONFIG.get("LOG_RETENTION_DAYS", 7))  # type: ignore[arg-type]
        if datetime.now() - modified_time > timedelta(days=retention):
            os.replace(log_path, log_path + ".old")
            with open(log_path, "w", encoding="utf-8"):
                pass
            printc("[*] Log rotated due to retention policy.", "yellow")
    except Exception:
        # Non-fatal; log rotation is best-effort in this script.
        pass


def safe_recv_line(sock: socket.socket, buffer_size: Optional[int] = None) -> Optional[str]:
    """
    Receive up to buffer_size bytes and return a newline-trimmed string.
    Returns None on socket close or error.
    """
    try:
        buf = buffer_size if buffer_size is not None else int(CONFIG["BUFFER_SIZE"])
        data = sock.recv(buf)
        if not data:
            return None
        return data.decode(errors="replace").strip()
    except Exception:
        return None
