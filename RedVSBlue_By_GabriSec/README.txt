# RedVsBlue_By_GabriSec 🛡️

A terminal-based Red vs Blue simulation showcasing core cybersecurity defense techniques:
- 2FA authentication, honeypots, reverse shells, IP blocking, privilege escalation, and SIEM log monitoring.

┌────────────────────────────────────────────────────────────┐
│ 🔧 USAGE EXAMPLES │
├────────────────────────────────────────────────────────────┤
│ $ python3 redvsblue.py --mode server │
│ → Start Blue Team server │
│ │
│ $ python3 redvsblue.py --mode client │
│ → Connect as Red Team (interactive shell) │
└────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ 🔐 DEFAULT CREDENTIALS │
├────────────┬────────────┬──────────┬────────┤
│ Username │ Password │ 2FA Code │ Admin? │
├────────────┼────────────┼──────────┼────────┤
│ user1 │ changeme │ 654321 │ ❌ │
│ admin │ letmein123 │ 123456 │ ✅ │
└────────────┴────────────┴──────────┴────────┘

→ user1 can use sudo_su to elevate with password: supersecret123

┌────────────────────────────────────────────────────────────┐
│ 💻 AVAILABLE COMMANDS │
├────────────────────────────────────────────────────────────┤
│ whoami → Show current user info │
│ os_info → Display system banner │
│ list_files → List ./etc/secure/ files │
│ read_file <file> → Read a specific file │
│ reverse_shell <ip> <port> → Launch reverse shell │
│ search_logs <keyword> → Search SIEM logs │
│ sudo_su → Attempt privilege escalation │
│ exit → Close session │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ 🔐 ADMIN-ONLY COMMANDS │
├────────────────────────────────────────────────────────────┤
│ get_flag → Read sensitive flag file │
│ show_logged_users → List active authenticated users │
│ deny_ip <ip> → Manually block an IP address │
│ allow_ip <ip> → Unblock previously denied IP │
└────────────────────────────────────────────────────────────┘

📁 SIEM Logs: ./logs/siem_log.json
📁 Fake Files: ./etc/secure/ (flag.txt, passwords.txt...)

🛡️ Features:

    2FA login with brute-force protection

    Dynamic honeypots on ports 2222, 8888, 6000

    Admin-only flag access & log monitoring

    Manual IP allow/block control

    Real-time SIEM monitoring + log rotation

    Privilege escalation simulation with sudo_su

🔒 Built for educational use.
