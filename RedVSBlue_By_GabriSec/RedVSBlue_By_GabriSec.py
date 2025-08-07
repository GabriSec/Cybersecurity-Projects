import socket
import threading
import argparse
import hashlib
import time
import os
import json
import platform
import random
import sys
import subprocess
from datetime import datetime, timedelta


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
BLOCKED_IPS = {}
ACTIVE_SESSIONS = {}
MANUAL_BLOCKED_IPS = set()


def init_environment():
    os.makedirs(os.path.dirname(CONFIG["FLAG_PATH"]), exist_ok=True)
    os.makedirs(os.path.dirname(CONFIG["LOG_PATH"]), exist_ok=True)
    if not os.path.exists(CONFIG["FLAG_PATH"]):
        with open(CONFIG["FLAG_PATH"], "w") as f:
            f.write("FLAG{you_evaded_detection_and_stole_the_flag}\n")
    for file, content in CONFIG["FAKE_FILES"].items():
        with open(f"./etc/secure/{file}", "w") as f:
            f.write(content)

def log_event(event_type, details, severity="info"):
    event = {
        "timestamp": time.ctime(),
        "event": event_type,
        "severity": severity,
        "details": details
    }
    with open(CONFIG["LOG_PATH"], "a") as log:
        log.write(json.dumps(event) + "\n")

def os_banner():
    return f"{platform.system()} {platform.release()} | Host: {socket.gethostname()}"

def printc(msg, color):
    if CONFIG["COLOR"]:
        codes = {"red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m", "end": "\033[0m"}
        print(f"{codes[color]}{msg}{codes['end']}")
    else:
        print(msg)

def monitor_logs():
    printc("[+] SIEM Log Monitor Running. Press Ctrl+C to stop.", "yellow")
    try:
        with open(CONFIG["LOG_PATH"], "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    try:
                        event = json.loads(line.strip())
                        if event['severity'] in ["critical", "warning"]:
                            printc(f"[ALERT] {event['timestamp']} - {event['event']}: {event['details']}", "red")
                    except:
                        continue
                else:
                    time.sleep(1)
    except KeyboardInterrupt:
        printc("[!] Monitoring stopped.", "yellow")

def rotate_logs():
    try:
        if not os.path.exists(CONFIG["LOG_PATH"]):
            return
        modified_time = datetime.fromtimestamp(os.path.getmtime(CONFIG["LOG_PATH"]))
        if datetime.now() - modified_time > timedelta(days=CONFIG["LOG_RETENTION_DAYS"]):
            os.rename(CONFIG["LOG_PATH"], CONFIG["LOG_PATH"] + ".old")
            with open(CONFIG["LOG_PATH"], "w"): pass
            printc("[*] Log rotated due to retention policy.", "yellow")
    except Exception as e:
        printc(f"[!] Log rotation error: {e}", "red")

#  SERVER

class BlueTeamServer:
    def __init__(self):
        self.host = "0.0.0.0"
        self.port = CONFIG["PORT"]
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        init_environment()
        rotate_logs()
        self.deploy_honeypots()
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        printc(f"[+] Blue Team Server listening with TLS on port {self.port}", "green")

        threading.Thread(target=monitor_logs, daemon=True).start()

        while True:
            client, addr = self.server.accept()
            ip = addr[0]


            if ip in MANUAL_BLOCKED_IPS:
                client.send(b"[!] IP has been manually blocked.\n")
                log_event("ManualBlock", {"ip": ip}, "warning")
                client.close()
                continue

            if ip in BLOCKED_IPS and time.time() < BLOCKED_IPS[ip]:
                client.send(b"[!] IP temporarily blocked. Try again later.\n")
                log_event("BlockedConnection", {"ip": ip}, "warning")
                client.close()
                continue

            threading.Thread(target=self.handle_client, args=(client, ip)).start()

    def deploy_honeypots(self):
        for port in CONFIG["HONEYPOT_PORTS"]:
            t = threading.Thread(target=self.listen_honeypot, args=(port,), daemon=True)
            t.start()

    def listen_honeypot(self, port):
        honeypot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        honeypot.bind(("0.0.0.0", port))
        honeypot.listen(1)
        while True:
            conn, addr = honeypot.accept()
            ip = addr[0]
            log_event("HoneypotConnection", {"ip": ip, "port": port}, "warning")
            conn.send(b"Access Denied. Activity logged.\n")
            conn.close()

    def handle_client(self, sock, ip):
        try:
            attempts = 0
            sock.send(b"== Welcome to Blue Team Secure Gateway ==\n")

            while attempts < CONFIG["MAX_ATTEMPTS"]:
                sock.send(b"Username: ")
                username = sock.recv(CONFIG["BUFFER_SIZE"]).decode().strip()
                sock.send(b"Password: ")
                password = sock.recv(CONFIG["BUFFER_SIZE"]).decode().strip()

                if CONFIG["AUTH"].get(username) == password:
                    sock.send(b"2FA Code: ")
                    code = sock.recv(CONFIG["BUFFER_SIZE"]).decode().strip()
                    if CONFIG["2FA_CODES"].get(username) == code:
                        sock.send(b"[+] Access Granted.\n")
                        log_event("LoginSuccess", {"ip": ip, "user": username})
                        ACTIVE_SESSIONS[ip] = username  # NEW FEATURE
                        self.shell(sock, username, ip)
                        ACTIVE_SESSIONS.pop(ip, None)  # NEW FEATURE: remove on exit
                        return
                    else:
                        sock.send(b"[!] Invalid 2FA code.\n")
                        log_event("2FAFailure", {"ip": ip, "user": username}, "warning")
                        break
                else:
                    attempts += 1
                    log_event("LoginFailure", {"ip": ip, "attempt": attempts}, "warning")
                    sock.send(b"[!] Login failed.\n")
                    time.sleep(CONFIG["RATE_LIMIT_DELAY"])

            BLOCKED_IPS[ip] = time.time() + CONFIG["BLOCK_DURATION"]
            sock.send(b"[!] Too many attempts. IP temporarily blocked.\n")
            sock.close()

        except Exception as e:
            log_event("ServerError", {"ip": ip, "error": str(e)}, "critical")
            sock.close()

    def shell(self, sock, username, ip):
        is_admin = username in CONFIG["ADMIN_USERS"]  # Initial admin check
        sock.send(b"Welcome to SecureShell. Type 'help' for commands.\n")

        while True:
            sock.send(b"SecureShell$ ")
            cmd = sock.recv(CONFIG["BUFFER_SIZE"]).decode().strip()

            if not cmd:
                continue

            lower_cmd = cmd.lower()

            if lower_cmd == "help":
                commands = """Available commands:
    whoami - Show user info
    os_info - Show system banner
    list_files - List secure directory
    read_file <file> - View file
    reverse_shell <ip> <port> - Send a reverse shell
    search_logs <keyword> - Search SIEM logs
    sudo_su - Attempt to elevate privileges
    exit - Close session"""
                if is_admin:
                    commands += """
    get_flag - Retrieve the flag (admin only)
    show_logged_users - List active authenticated clients (admin only)
    deny_ip <ip> - Manually block an IP (admin only)
    allow_ip <ip> - Remove a manually blocked IP (admin only)"""
                sock.send(commands.encode())

            elif lower_cmd == "whoami":
                role = "admin" if is_admin else "user"
                sock.send(f"{username} from {ip} ({role})\n".encode())

            elif lower_cmd == "os_info":
                sock.send(os_banner().encode())

            elif lower_cmd == "list_files":
                files = os.listdir("./etc/secure/")
                sock.send("\n".join(files).encode())

            elif lower_cmd.startswith("read_file"):
                parts = cmd.split()
                if len(parts) == 2:
                    try:
                        with open(f"./etc/secure/{parts[1]}", "r") as f:
                            sock.send(f.read().encode())
                    except:
                        sock.send(b"File not found.\n")
                else:
                    sock.send(b"Usage: read_file <filename>\n")

            elif lower_cmd == "get_flag":
                if not is_admin:
                    sock.send(b"[!] Access Denied. Admin only.\n")
                    continue
                try:
                    with open(CONFIG["FLAG_PATH"], "r") as f:
                        sock.send(f.read().encode())
                    log_event("FlagAccessed", {"user": username, "ip": ip}, "critical")
                except:
                    sock.send(b"Flag missing.\n")

            elif lower_cmd.startswith("reverse_shell"):
                parts = cmd.split()
                if len(parts) == 3:
                    target_ip, target_port = parts[1], int(parts[2])
                    threading.Thread(target=self.launch_reverse_shell, args=(target_ip, target_port)).start()
                    sock.send(b"[!] Reverse shell launched.\n")
                    log_event("ReverseShell", {"target_ip": target_ip, "user": username}, "critical")
                else:
                    sock.send(b"Usage: reverse_shell <ip> <port>\n")

            elif lower_cmd.startswith("search_logs"):
                keyword = cmd.split(" ", 1)[-1].lower()
                matches = []
                with open(CONFIG["LOG_PATH"], "r") as f:
                    for line in f:
                        if keyword in line.lower():
                            matches.append(line)
                sock.send("\n".join(matches).encode() if matches else b"No matches found.\n")

            elif lower_cmd == "show_logged_users":
                if not is_admin:
                    sock.send(b"[!] Access Denied. Admin only.\n")
                    continue
                if ACTIVE_SESSIONS:
                    clients = "\n".join([f"{ip}: {user}" for ip, user in ACTIVE_SESSIONS.items()])
                    sock.send(clients.encode())
                else:
                    sock.send(b"No users currently logged in.\n")

            elif lower_cmd.startswith("deny_ip"):
                if not is_admin:
                    sock.send(b"[!] Access Denied. Admin only.\n")
                    continue
                parts = cmd.split()
                if len(parts) == 2:
                    MANUAL_BLOCKED_IPS.add(parts[1])
                    sock.send(f"IP {parts[1]} manually blocked.\n".encode())
                else:
                    sock.send(b"Usage: deny_ip <ip>\n")

            elif lower_cmd.startswith("allow_ip"):
                if not is_admin:
                    sock.send(b"[!] Access Denied. Admin only.\n")
                    continue
                parts = cmd.split()
                if len(parts) == 2:
                    MANUAL_BLOCKED_IPS.discard(parts[1])
                    sock.send(f"IP {parts[1]} unblocked.\n".encode())
                else:
                    sock.send(b"Usage: allow_ip <ip>\n")

            elif lower_cmd == "sudo_su":
                if is_admin:
                    sock.send(b"[!] You are already an admin.\n")
                    continue
                sock.send(b"Enter sudo password: ")
                entered = sock.recv(CONFIG["BUFFER_SIZE"]).decode().strip()
                if entered == CONFIG["SUDO_PASSWORD"]:
                    is_admin = True
                    sock.send(b"[+] Privileges elevated. You are now admin.\n")
                    log_event("SudoSuSuccess", {"user": username, "ip": ip})
                else:
                    sock.send(b"[!] Incorrect sudo password.\n")
                    log_event("SudoSuFail", {"user": username, "ip": ip}, "warning")

            elif lower_cmd == "exit":
                sock.send(b"Session closed.\n")
                sock.close()
                return

            else:
                sock.send(b"Unknown command.\n")


#  CLIENT

class RedTeamClient:
    def __init__(self):
        self.target = ("127.0.0.1", CONFIG["PORT"])

    def connect(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(self.target)
            banner = sock.recv(CONFIG["BUFFER_SIZE"]).decode()
            printc(banner, "green")

            while True:
                data = sock.recv(CONFIG["BUFFER_SIZE"]).decode()
                if data:
                    print(data, end="")
                cmd = input()
                sock.send(f"{cmd}\n".encode())
                if cmd.lower().strip() == "exit":
                    break

        except Exception as e:
            printc(f"[X] Connection failed: {e}", "red")


def main():
    parser = argparse.ArgumentParser(description="RedVSBlue_By_GabriSec Simulation Tool")
    parser.add_argument("--mode", choices=["server", "client"], required=True, help="Run as server or client")
    parser.add_argument("--show-clients", action="store_true", help="Show currently logged in clients (server only)")
    args = parser.parse_args()

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
