"""
Legacy RTU Telnet Server with RFC 793 Baseline TCP Engine.
Emulates an embedded RTU/PLC microcontroller running a legacy stack (e.g. lwIP)
with a predictable linear ISN timer and 64KB RFC 793 in-window RST acceptance.
"""
import os
import sys
import time
import struct
import socket
import threading
from scapy.all import sniff, IP, TCP, Raw, send, conf

conf.verb = 0

LISTEN_PORT = 23
RTU_IP = "10.0.1.20"
WINDOW_SIZE = 65535
TIMER_TICK_RATE = 250000  # 250,000 ISN ticks per second
BASE_ISN = 1000000000

# Session State Storage
# Key: (client_ip, client_port) -> Dict of session attributes
active_sessions = {}
sessions_lock = threading.Lock()


def get_current_isn() -> int:
    """Computes predictable linear timer-based ISN."""
    elapsed = time.time()
    return int(BASE_ISN + (elapsed * TIMER_TICK_RATE)) & 0xFFFFFFFF


def send_packet(packet):
    """Sends a packet via Scapy."""
    send(packet, verbose=False)


def handle_packet(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]

    if ip_layer.dst != RTU_IP or tcp_layer.dport != LISTEN_PORT:
        return

    client_ip = ip_layer.src
    client_port = tcp_layer.sport
    session_key = (client_ip, client_port)
    seg_seq = tcp_layer.seq
    seg_ack = tcp_layer.ack
    flags = tcp_layer.flags

    with sessions_lock:
        session = active_sessions.get(session_key)

        # 1. Handle SYN (Handshake Initiation)
        if flags & 0x02 and not (flags & 0x10):  # Pure SYN
            server_isn = get_current_isn()
            rcv_nxt = (seg_seq + 1) & 0xFFFFFFFF
            active_sessions[session_key] = {
                "state": "SYN_RECEIVED",
                "snd_nxt": (server_isn + 1) & 0xFFFFFFFF,
                "rcv_nxt": rcv_nxt,
                "server_isn": server_isn,
                "client_isn": seg_seq,
                "established_time": time.time(),
            }
            print(f"[RTU] SYN received from {client_ip}:{client_port}. Generated ISN: {server_isn}")
            syn_ack = (
                IP(src=RTU_IP, dst=client_ip)
                / TCP(
                    sport=LISTEN_PORT,
                    dport=client_port,
                    seq=server_isn,
                    ack=rcv_nxt,
                    flags="SA",
                    window=WINDOW_SIZE,
                )
            )
            send_packet(syn_ack)
            return

        # 2. Handle RST (Reset Processing per RFC 793)
        if flags & 0x04:  # RST or RST+ACK
            if not session or session["state"] == "CLOSED":
                return

            rcv_nxt = session["rcv_nxt"]
            # RFC 793 In-Window Check: RCV.NXT <= SEG.SEQ < RCV.NXT + W
            in_window_diff = (seg_seq - rcv_nxt) & 0xFFFFFFFF
            if in_window_diff < WINDOW_SIZE:
                session["state"] = "CLOSED"
                print(
                    f"\n[RTU] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                )
                print(
                    f"[RTU] [!] RFC 793 IN-WINDOW RST ACCEPTED from {client_ip}:{client_port}!"
                )
                print(
                    f"[RTU] [!] Injected SEQ: {seg_seq} within [RCV.NXT: {rcv_nxt} .. {rcv_nxt + WINDOW_SIZE}]"
                )
                print(f"[RTU] [!] Session {session_key} transition: ESTABLISHED -> CLOSED")
                print(
                    f"[RTU] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                )
            else:
                # Out-of-window RST is silently discarded in RFC 793
                pass
            return

        # 3. Check for Packets on a CLOSED Session (Subsequent Rejection)
        if session and session["state"] == "CLOSED":
            print(
                f"[RTU] Subsequent query received from {client_ip}:{client_port} on CLOSED socket. Emitting unsolicited RST."
            )
            unsolicited_rst = (
                IP(src=RTU_IP, dst=client_ip)
                / TCP(
                    sport=LISTEN_PORT,
                    dport=client_port,
                    seq=seg_ack if seg_ack else 0,
                    flags="R",
                    window=0,
                )
            )
            send_packet(unsolicited_rst)
            return

        # 4. Handle Final ACK of Handshake
        if flags & 0x10 and session and session["state"] == "SYN_RECEIVED":
            session["state"] = "ESTABLISHED"
            print(f"[RTU] Handshake completed with {client_ip}:{client_port}. Session ESTABLISHED.")
            # Send Telnet Welcome Banner
            banner = b"\r\n--- Industrial RTU Telemetry Console (Telnet RFC 854) ---\r\nReady for polling queries.\r\n> "
            data_pkt = (
                IP(src=RTU_IP, dst=client_ip)
                / TCP(
                    sport=LISTEN_PORT,
                    dport=client_port,
                    seq=session["snd_nxt"],
                    ack=session["rcv_nxt"],
                    flags="PA",
                    window=WINDOW_SIZE,
                )
                / Raw(load=banner)
            )
            session["snd_nxt"] = (session["snd_nxt"] + len(banner)) & 0xFFFFFFFF
            send_packet(data_pkt)
            return

        # 5. Handle SCADA Application Polling Query
        if session and session["state"] == "ESTABLISHED":
            payload_len = len(tcp_layer.payload)
            if payload_len > 0:
                session["rcv_nxt"] = (session["rcv_nxt"] + payload_len) & 0xFFFFFFFF
                # Generate Telemetry Register Response
                telemetry_data = (
                    b"\r\n[RTU-TELEMETRY] REG_0x01: PUMP_SPEED=1450_RPM | "
                    b"REG_0x02: TANK_PRESSURE=4.2_BAR | STATUS=NORMAL\r\n> "
                )
                resp_pkt = (
                    IP(src=RTU_IP, dst=client_ip)
                    / TCP(
                        sport=LISTEN_PORT,
                        dport=client_port,
                        seq=session["snd_nxt"],
                        ack=session["rcv_nxt"],
                        flags="PA",
                        window=WINDOW_SIZE,
                    )
                    / Raw(load=telemetry_data)
                )
                session["snd_nxt"] = (session["snd_nxt"] + len(telemetry_data)) & 0xFFFFFFFF
                send_packet(resp_pkt)
                print(f"[RTU] Processed telemetry poll for {client_ip}:{client_port}. New RCV.NXT={session['rcv_nxt']}")


def main():
    print("=" * 65)
    print("  Legacy RTU Server (RFC 793 Baseline & Telnet SCADA)")
    print(f"  IP: {RTU_IP} | Port: {LISTEN_PORT} | Window: {WINDOW_SIZE}")
    print(f"  Linear ISN Clock Rate: {TIMER_TICK_RATE} ticks/sec")
    print("=" * 65)

    # Suppress host kernel automatic RST packets for port 23
    os.system("iptables -A OUTPUT -p tcp --sport 23 --tcp-flags RST RST -j DROP 2>/dev/null || true")

    print("[RTU] Listening for incoming network segments on eth0...")
    sniff(iface="eth0", prn=handle_packet, filter="tcp port 23", store=False)


if __name__ == "__main__":
    main()
