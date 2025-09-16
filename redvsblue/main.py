"""Entry point for Red vs Blue simulation tool."""

import argparse
from typing import Iterable, Optional

from client import RedTeamClient
from config import ACTIVE_SESSIONS
from server import BlueTeamServer


def parse_arguments(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments; kept simple for the challenge."""
    parser = argparse.ArgumentParser(description="RedVSBlue Simulation Tool")
    parser.add_argument("--mode", choices=["server", "client"], required=True, help="Run as server or client")
    parser.add_argument("--show-clients", action="store_true", help="Show currently logged in clients (server only)")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Iterable[str]] = None) -> None:
    """Program entry point used with `python -m redvsblue.main`."""
    args = parse_arguments(argv)

    if args.mode == "server":
        if args.show_clients:
            if ACTIVE_SESSIONS:
                print("[*] Active Sessions:")
                for ip, user in ACTIVE_SESSIONS.items():
                    print(f" - {ip}: {user}")
            else:
                print("[*] No active sessions.")
        else:
            BlueTeamServer().start()
    else:
        RedTeamClient().connect()


if __name__ == "__main__":
    main()
