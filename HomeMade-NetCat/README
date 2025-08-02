=========================================================
     Homemade Netcat (Python)
     -------------------------
     A lightweight TCP client/server tool in Python
=========================================================

Author: GabriSec
Language: Python 3
Dependencies: None (standard library only)

DESCRIPTION
-----------
This script mimics the behavior of the classic 'netcat' utility.
It allows you to:

- Send data over TCP
- Start a listening shell on any port
- Upload or download files
- Execute remote commands
- Secure connections using TLS (optional)
- Allow only whitelisted IPs
- Handle multiple clients with threading

USAGE
-----

Start a server that spawns a command shell:
    python Homemade_Netcat.py -t 0.0.0.0 -p 5555 -l -c

Start a secure shell listener:
    python Homemade_Netcat.py -t 0.0.0.0 -p 5555 -l -c --secure

Upload a file to server:
    python Homemade_Netcat.py -t 0.0.0.0 -p 4444 -l -u=uploaded.txt

Send data to server from stdin:
    echo "Hello" | python Homemade_Netcat.py -t 127.0.0.1 -p 5555

Download a file from server:
    echo "GET filename.txt" | python Homemade_Netcat.py -t 127.0.0.1 -p 5555

Execute a command on connection:
    python Homemade_Netcat.py -t 0.0.0.0 -p 6666 -l -e "uptime"

Restrict access to specific IPs (server only):
    python Homemade_Netcat.py -t 0.0.0.0 -p 5555 -l --allow=192.168.1.10

OPTIONS
-------
  -t, --target      IP address (default: 127.0.0.1)
  -p, --port        Port to connect/listen (default: 5555)
  -l, --listen      Enable listening mode (server)
  -c, --command     Launch a command shell
  -e, --execute     Run a single command
  -u, --upload      Save file from incoming connection
  --secure          Enable encrypted connection (TLS)
  --allow           Comma-separated list of allowed IPs

NOTES
-----
- TLS is optional but recommended on untrusted networks.
- You can use standard tools like `telnet` or `nc` to test as well.
- Designed for local testing, learning, and development.

DISCLAIMER
----------
This tool is provided for educational purposes only.
Do not use it to access unauthorized systems or networks.

