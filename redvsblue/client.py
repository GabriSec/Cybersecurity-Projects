"""Red Team client for interacting with the Blue Team server (test client)."""

import socket
from typing import Tuple

from config import CONFIG, BLOCKED_IPS, ACTIVE_SESSIONS, MANUAL_BLOCKED_IPS
from utils import printc


class RedTeamClient:
    """Simple interactive client used to test the BlueTeamServer."""

    def __init__(self, target: Tuple[str, int] = ("127.0.0.1", CONFIG["PORT"])):
        self.target = (target[0], int(target[1]))  # type: ignore[arg-type]

    def connect(self) -> None:
        """Connect to a server and send/receive lines interactively."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(self.target)
                banner = sock.recv(CONFIG["BUFFER_SIZE"]).decode(errors="replace")
                printc(banner, "green")

                while True:
                    data = sock.recv(CONFIG["BUFFER_SIZE"]).decode(errors="replace")
                    if data:
                        print(data, end="")

                    try:
                        cmd = input()
                    except KeyboardInterrupt:
                        printc("\n[!] Client interrupted by user.", "yellow")
                        break

                    sock.send(f"{cmd}\n".encode())
                    if cmd.lower().strip() == "exit":
                        break
        except ConnectionRefusedError:
            printc(f"[X] Connection refused: {self.target}", "red")
        except Exception as exc:
            printc(f"[X] Connection failed: {exc}", "red")
