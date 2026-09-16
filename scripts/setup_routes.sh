#!/bin/bash
set -e

ROLE=$1

echo "[+] Initializing network routing for role: ${ROLE}"

case "${ROLE}" in
  gateway)
    echo "[+] Enabling IPv4 forwarding on Gateway..."
    sysctl -w net.ipv4.ip_forward=1
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -P FORWARD ACCEPT
    echo "[+] Gateway router configured (eth0: 10.0.1.1, eth1: 10.0.2.1)"
    ;;

  rtu)
    echo "[+] Configuring routing for RTU (10.0.1.20)..."
    # Replace default route with gateway on OT subnet
    ip route del default 2>/dev/null || true
    ip route add default via 10.0.1.1
    echo "[+] Default route set to 10.0.1.1"
    ;;

  client)
    echo "[+] Configuring routing for SCADA Client (10.0.1.10)..."
    # Replace default route with gateway on OT subnet
    ip route del default 2>/dev/null || true
    ip route add default via 10.0.1.1
    echo "[+] Default route set to 10.0.1.1"
    ;;

  attacker)
    echo "[+] Configuring routing for Attacker (10.0.2.50)..."
    # Replace default route with gateway on Ext subnet
    ip route del default 2>/dev/null || true
    ip route add default via 10.0.2.1
    echo "[+] Default route set to 10.0.2.1"
    ;;

  *)
    echo "[-] Unknown role: ${ROLE}"
    exit 1
    ;;
esac

echo "[+] Routing configuration completed for ${ROLE}"
