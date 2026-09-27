#!/bin/bash
set -e

echo "[+] Starting In-Line Protective Gateway Defense..."

# Clear any previous rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 || true

# Redirect transit TCP Telnet traffic (port 23) to NFQUEUE queue 0
echo "[+] Directing transit Telnet traffic (port 23) to NFQUEUE 0..."
iptables -A FORWARD -p tcp --dport 23 -j NFQUEUE --queue-num 0
iptables -A FORWARD -p tcp --sport 23 -j NFQUEUE --queue-num 0

echo "[+] Launching Defense Daemon..."
python3 -u /app/gateway/defense_daemon.py 2>&1 | tee /proc/1/fd/1
