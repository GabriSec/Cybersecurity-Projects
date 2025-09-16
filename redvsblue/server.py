"""Blue Team server implementation."""
from __future__ import annotations

import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

from config import CONFIG, BLOCKED_IPS, ACTIVE_SESSIONS, MANUAL_BLOCKED_IPS
from logger import log_event, monitor_logs
from utils import init_environment, os_banner, printc, rotate_logs, safe_recv_line

# Module-level lock for state mutations
STATE_LOCK = threading.Lock()


@dataclass
class Session:
    """Session state container for a connected client."""
    username: str
    ip: str
    is_admin: bool = False


class BlueTeamServer:
    """Blue Team server for defending the system."""

    RESTRICTED_FILES = [
        os.path.basename(CONFIG["FLAG_PATH"]),
        "passwords.txt",
        "todo.txt",
        "hint.txt",
        "flag.txt",  # Fixed concatenation
    ]

    def __init__(self, host: str = "0.0.0.0", port: Optional[int] = None) -> None:
        self.host = host
        self.port = int(port if port is not None else CONFIG["PORT"])  # type: ignore[arg-type]
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self) -> None:
        """Initialize environment, spin honeypots and accept clients."""
        init_environment()
        rotate_logs()
        self._deploy_honeypots()

        try:
            self.server_sock.bind((self.host, self.port))
            self.server_sock.listen(5)
            printc(f"[+] Blue Team Server listening on port {self.port}", "green")
        except OSError as exc:
            printc(f"[!] Failed to bind: {exc}", "red")
            return

        threading.Thread(target=monitor_logs, daemon=True).start()

        try:
            while True:
                client_sock, addr = self.server_sock.accept()
                client_ip = addr[0]


                # Manual block
                if client_ip in MANUAL_BLOCKED_IPS:
                    client_sock.send(b"[!] IP has been manually blocked.\n")
                    log_event("ManualBlock", {"ip": client_ip}, "warning")
                    client_sock.close()
                    continue

                # Temporary block
                blocked_until = BLOCKED_IPS.get(client_ip)
                if blocked_until and time.time() < blocked_until:
                    client_sock.send(b"[!] IP temporarily blocked. Try again later.\n")
                    log_event("BlockedConnection", {"ip": client_ip}, "warning")
                    client_sock.close()
                    continue

                thread = threading.Thread(
                    target=self._handle_client_thread, args=(client_sock, client_ip), daemon=True
                )
                thread.start()
        except KeyboardInterrupt:
            printc("[*] Server shutting down.", "yellow")
        finally:
            try:
                self.server_sock.close()
            except Exception:
                pass

    def _deploy_honeypots(self) -> None:
        """Start honeypot listeners on configured ports."""
        for port in CONFIG.get("HONEYPOT_PORTS", []):  # type: ignore[arg-type]
            t = threading.Thread(target=self._listen_honeypot, args=(int(port),), daemon=True)
            t.start()

    def _listen_honeypot(self, port: int) -> None:
        """Honeypot that logs connections and denies access."""
        try:
            hp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            hp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            hp.bind(("0.0.0.0", port))
            hp.listen(1)
        except OSError:
            return

        while True:
            try:
                conn, addr = hp.accept()
                ip = addr[0]
                log_event("HoneypotConnection", {"ip": ip, "port": port}, "warning")
                conn.send(b"Access Denied. Activity logged.\n")
                conn.close()
            except Exception:
                continue

    def _handle_client_thread(self, client_sock: socket.socket, ip: str) -> None:
        """Wrap client handling and ensure socket cleanup."""
        try:
            self._authenticate_and_shell(client_sock, ip)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _authenticate_and_shell(self, sock: socket.socket, ip: str) -> None:
        """Authenticate client (with 2FA) then launch session shell on success."""
        attempts = 0
        sock.send(b"== Welcome to Blue Team Secure Gateway ==\n")

        while attempts < int(CONFIG.get("MAX_ATTEMPTS", 5)):  # type: ignore[arg-type]
            sock.send(b"Username: ")
            username = safe_recv_line(sock)
            if username is None:
                return
            sock.send(b"Password: ")
            password = safe_recv_line(sock)
            if password is None:
                return

            auth_map = CONFIG.get("AUTH", {})
            if auth_map.get(username) == password:  # type: ignore[attr-defined]
                sock.send(b"2FA Code: ")
                code = safe_recv_line(sock)
                if code is None:
                    return
                expected = CONFIG.get("2FA_CODES", {}).get(username)  # type: ignore[arg-type]
                if expected and code == expected:
                    sock.send(b"[+] Access Granted.\n")
                    log_event("LoginSuccess", {"ip": ip, "user": username})
                    with STATE_LOCK:
                        ACTIVE_SESSIONS[ip] = username
                    session = Session(username=username, ip=ip, is_admin=(username in CONFIG.get("ADMIN_USERS", [])))  # type: ignore[arg-type]
                    try:
                        self._shell_loop(sock, session)
                    finally:
                        with STATE_LOCK:
                            ACTIVE_SESSIONS.pop(ip, None)
                    return
                sock.send(b"[!] Invalid 2FA code.\n")
                log_event("2FAFailure", {"ip": ip, "user": username}, "warning")
                break
            else:
                attempts += 1
                log_event("LoginFailure", {"ip": ip, "attempt": attempts}, "warning")
                sock.send(b"[!] Login failed.\n")
                time.sleep(int(CONFIG.get("RATE_LIMIT_DELAY", 2)))  # type: ignore[arg-type]

        # too many attempts -> temporary block
        with STATE_LOCK:
            BLOCKED_IPS[ip] = time.time() + float(CONFIG.get("BLOCK_DURATION", 300))  # type: ignore[arg-type]
        sock.send(b"[!] Too many attempts. IP temporarily blocked.\n")

    def _shell_loop(self, sock: socket.socket, session: Session) -> None:
        """Primary command loop for an authenticated session."""
        sock.send(b"Welcome to SecureShell. Type 'help' for commands.\n")
        while True:
            sock.send(b"SecureShell$ ")
            line = safe_recv_line(sock)
            if line is None:
                return
            if not line:
                continue

            # Dispatch and possibly update session state (sudo elevation)
            new_admin_state = self._handle_command(sock, line, session)
            if new_admin_state is True:
                session.is_admin = True
            # If command requested exit, the handler closes the socket and returns sentinel
            # Some handlers will return "exit" to stop the loop:
            if new_admin_state == "exit":
                return

    # --- Command dispatcher & handlers ---
    def _handle_command(self, sock: socket.socket, cmd: str, session: Session):
        """
        Dispatch command string to the correct handler.

        Returns:
            True if is_admin should be set to True (sudo succeeded),
            "exit" if session should end, otherwise None.
        """
        raw = cmd.strip()
        if not raw:
            return None

        parts = raw.split(maxsplit=1)
        verb = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        dispatch = {
            "help": self._cmd_help,
            "whoami": self._cmd_whoami,
            "os_info": self._cmd_os_info,
            "list_files": self._cmd_list_files,
            "read_file": self._cmd_read_file,
            "get_flag": self._cmd_get_flag,
            "reverse_shell": self._cmd_reverse_shell,
            "search_logs": self._cmd_search_logs,
            "show_logged_users": self._cmd_show_logged_users,
            "deny_ip": self._cmd_deny_ip,
            "allow_ip": self._cmd_allow_ip,
            "sudo_su": self._cmd_sudo_su,
            "exit": self._cmd_exit,
        }

        handler = dispatch.get(verb)
        if handler is None:
            try:
                sock.send(b"Unknown command. Type 'help' for commands.\n")
            except Exception:
                pass
            return None

        try:
            return handler(sock, arg, session)
        except Exception as exc:
            log_event("CommandError", {"user": session.username, "ip": session.ip, "cmd": cmd, "error": str(exc)}, "warning")
            try:
                sock.send(b"An internal error occurred handling the command.\n")
            except Exception:
                pass
            return None

    # Handlers below return:
    # - None for normal processing
    # - True to signal sudo success (set is_admin)
    # - "exit" to close session

    def _cmd_help(self, sock: socket.socket, arg: str, session: Session):
        base = (
            "Available commands:\n"
            "  whoami - Show user info\n"
            "  os_info - Show system banner\n"
            "  list_files - List secure directory\n"
            "  read_file <file> - View file\n"
            "  reverse_shell <ip> <port> - Send a reverse shell\n"
            "  search_logs <keyword> - Search SIEM logs\n"
            "  sudo_su - Attempt to elevate privileges\n"
            "  exit - Close session\n"
        )
        if session.is_admin:
            base += (
                "  get_flag - Retrieve the flag (admin only)\n"
                "  show_logged_users - List active authenticated clients (admin only)\n"
                "  deny_ip <ip> - Manually block an IP (admin only)\n"
                "  allow_ip <ip> - Remove a manually blocked IP (admin only)\n"
            )
        sock.send(base.encode())
        return None

    def _cmd_whoami(self, sock: socket.socket, arg: str, session: Session):
        role = "admin" if session.is_admin else "user"
        sock.send(f"{session.username} from {session.ip} ({role})\n".encode())
        return None

    def _cmd_os_info(self, sock: socket.socket, arg: str, session: Session):
        sock.send((os_banner() + "\n").encode())
        return None

    def _cmd_list_files(self, sock: socket.socket, arg: str, session: Session):
        secure_dir = os.path.dirname(CONFIG["FLAG_PATH"]) or "."
        try:
            files = os.listdir(secure_dir)
            display_files = []
            for f in files:
                if f in self.RESTRICTED_FILES and not session.is_admin:
                    display_files.append(f"{f} [restricted]")
                else:
                    display_files.append(f)
            sock.send(("\n".join(display_files) + "\n").encode())
        except OSError:
            sock.send(b"Could not list files.\n")
        return None

    def _cmd_read_file(self, sock: socket.socket, arg: str, session: Session):
        if not arg:
            sock.send(b"Usage: read_file <filename>\n")
            return None
        name = arg.strip()
        path = os.path.join(os.path.dirname(CONFIG["FLAG_PATH"]), name)

        # Restrict access to sensitive files
        if name in self.RESTRICTED_FILES and not session.is_admin:
            sock.send(b"[!] Access Denied. Admin only.\n")
            log_event(
                "UnauthorizedFileAccess",
                {"user": session.username, "ip": session.ip, "file": name},
                "warning",
            )
            return None

        try:
            with open(path, "r", encoding="utf-8") as fh:
                sock.send(fh.read().encode())
        except OSError:
            sock.send(b"File not found.\n")
        return None

    def _cmd_get_flag(self, sock: socket.socket, arg: str, session: Session):
        if not session.is_admin:
            sock.send(b"[!] Access Denied. Admin only.\n")
            return None
        try:
            with open(CONFIG["FLAG_PATH"], "r", encoding="utf-8") as fh:
                sock.send(fh.read().encode())
            log_event("FlagAccessed", {"user": session.username, "ip": session.ip}, "critical")
        except OSError:
            sock.send(b"Flag missing.\n")
        return None

    def _cmd_reverse_shell(self, sock: socket.socket, arg: str, session: Session):
        parts = arg.split()
        if len(parts) != 2:
            sock.send(b"Usage: reverse_shell <ip> <port>\n")
            return None
        target_ip = parts[0]
        try:
            target_port = int(parts[1])
        except ValueError:
            sock.send(b"Invalid port number.\n")
            return None

        threading.Thread(target=self._launch_reverse_shell, args=(target_ip, target_port), daemon=True).start()
        sock.send(b"[!] Reverse shell launched.\n")
        log_event("ReverseShell", {"target_ip": target_ip, "user": session.username}, "critical")
        return None

    def _launch_reverse_shell(self, addr: str, port: int):
        """Minimal simulated reverse-shell connector (non-privileged demo)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((addr, port))
                s.send(b"Reverse shell connected (simulated)\n")
        except Exception:
            log_event("ReverseShellFailed", {"target_ip": addr, "port": port}, "warning")

    def _cmd_search_logs(self, sock: socket.socket, arg: str, session: Session):
        if not arg:
            sock.send(b"Usage: search_logs <keyword>\n")
            return None
        keyword = arg.lower()
        matches = []
        try:
            with open(CONFIG["LOG_PATH"], "r", encoding="utf-8") as fh:
                for line in fh:
                    if keyword in line.lower():
                        matches.append(line.strip())
        except OSError:
            sock.send(b"Could not open logs.\n")
            return None
        if matches:
            sock.send(("\n".join(matches) + "\n").encode())
        else:
            sock.send(b"No matches found.\n")
        return None

    def _cmd_show_logged_users(self, sock: socket.socket, arg: str, session: Session):
        if not session.is_admin:
            sock.send(b"[!] Access Denied. Admin only.\n")
            return None
        with STATE_LOCK:
            if ACTIVE_SESSIONS:
                clients = "\n".join(f"{ip}: {user}" for ip, user in ACTIVE_SESSIONS.items())
                sock.send((clients + "\n").encode())
            else:
                sock.send(b"No users currently logged in.\n")
        return None

    def _cmd_deny_ip(self, sock: socket.socket, arg: str, session: Session):
        if not session.is_admin:
            sock.send(b"[!] Access Denied. Admin only.\n")
            return None
        if not arg:
            sock.send(b"Usage: deny_ip <ip>\n")
            return None
        ip_to_block = arg.strip()
        with STATE_LOCK:
            MANUAL_BLOCKED_IPS.add(ip_to_block)
        sock.send(f"IP {ip_to_block} manually blocked.\n".encode())
        log_event("ManualBlock", {"admin": session.username, "ip": ip_to_block}, "warning")
        return None

    def _cmd_allow_ip(self, sock: socket.socket, arg: str, session: Session):
        if not session.is_admin:
            sock.send(b"[!] Access Denied. Admin only.\n")
            return None
        if not arg:
            sock.send(b"Usage: allow_ip <ip>\n")
            return None
        ip_to_allow = arg.strip()
        with STATE_LOCK:
            MANUAL_BLOCKED_IPS.discard(ip_to_allow)
        sock.send(f"IP {ip_to_allow} unblocked.\n".encode())
        log_event("ManualUnblock", {"admin": session.username, "ip": ip_to_allow}, "info")
        return None

    def _cmd_sudo_su(self, sock: socket.socket, arg: str, session: Session):
        if session.is_admin:
            sock.send(b"[!] You are already an admin.\n")
            return None
        sock.send(b"Enter sudo password: ")
        entered = safe_recv_line(sock) or ""
        if entered == str(CONFIG.get("SUDO_PASSWORD")):
            # signal to caller that is_admin should be set True
            sock.send(b"[+] Privileges elevated. You are now admin.\n")
            log_event("SudoSuSuccess", {"user": session.username, "ip": session.ip})
            return True
        sock.send(b"[!] Incorrect sudo password.\n")
        log_event("SudoSuFail", {"user": session.username, "ip": session.ip}, "warning")
        return None

    def _cmd_exit(self, sock: socket.socket, arg: str, session: Session):
        sock.send(b"Session closed.\n")
        try:
            sock.close()
        except Exception:
            pass
        return "exit"
