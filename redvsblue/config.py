"""
config.py

Centralized configuration and runtime state for the RedVSBlue CTF project.

- STATIC_CONFIG: immutable settings and constants
- RUNTIME_STATE: mutable runtime variables
"""

from typing import Dict, Set, List

# -----------------------------
# STATIC CONFIGURATION
# -----------------------------
CONFIG = {
    "BUFFER_SIZE": 4096,
    "PORT": 5555,
    "FLAG_PATH": "./etc/secure/flag.txt",
    "FAKE_FILES": {
        "passwords.txt": "# Nothing to see here\nuser1:changeme\nadmin:unknown\n",
        "todo.txt": "- Clean logs\n- Move flag to flag.txt\n- Update user creds",
        "hint.txt": "Try bruteforcing user1. Password might be weak."
    },
    "LOG_PATH": "./logs/siem_log.json",
    "ALLOWLIST": ["127.0.0.1"],
    "BLOCK_DURATION": 300,
    "MAX_ATTEMPTS": 5,
    "RATE_LIMIT_DELAY": 2,
    "AUTH": {
        "user1": "iuser93",
        "admin": "admin123"
    },
    "2FA_CODES": {
        "user1": "654321",
        "admin": "123456"
    },
    "COLOR": True,
    "HONEYPOT_PORTS": [2222, 8888, 6000],
    "LOG_RETENTION_DAYS": 7,
    "ADMIN_USERS": ["admin"],
    "SUDO_PASSWORD": "supersecret123"
}

# -----------------------------
# RUNTIME STATE
# -----------------------------
# Mutable state variables updated during server execution
BLOCKED_IPS: Dict[str, float] = {}
ACTIVE_SESSIONS: Dict[str, str] = {}
MANUAL_BLOCKED_IPS: Set[str] = set()
