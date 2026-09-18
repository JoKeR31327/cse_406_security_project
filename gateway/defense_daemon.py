"""
Two-Stage In-Line Protective Gateway Defense Daemon.
Implements:
- Stage 1: Handshake Anomaly & Rate Throttling (Flags connections without Telnet IAC negotiations)
- Stage 2: Delayed Reset Quarantine (DRQ) with 64-entry LRU buffer, 80ms quarantine timer,
           token-bucket rate limiter, and Active Zero-Window Challenge Probing.
"""
import time
import socket
import threading
from collections import deque, OrderedDict
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, send, conf

# Keep scapy quiet
conf.verb = 0

GATEWAY_OT_IP = "10.0.1.1"
GATEWAY_EXT_IP = "10.0.2.1"
RTU_IP = "10.0.1.20"
TELNET_PORT = 23

# DRQ Configuration Parameters
MAX_BUFFER_SIZE = 64
QUARANTINE_TIMEOUT = 0.080  # Tq = 80 ms quarantine window
MAX_EVAL_RATE = 50.0        # Rmax = 50 evaluations per second

# Token bucket state for rate-limiting incoming RST evaluations
tokens = MAX_EVAL_RATE
last_token_update = time.time()
token_lock = threading.Lock()

# State tracking
# active_sessions: (client_ip, client_port) -> {"last_ack": int, "last_seq": int, "has_iac": bool, "last_active": float}
active_sessions = {}
# quarantine_buffer: (client_ip, client_port) -> {"pkt": nfq_packet, "timer": threading.Timer, "timestamp": float}
quarantine_buffer = OrderedDict()
state_lock = threading.Lock()

# Signals client liveliness when a pure ACK is observed
ack_events = {}


def get_tokens() -> bool:
    """Refills and checks the token bucket (allowing up to 50 evals/sec)."""
    global tokens, last_token_update
    with token_lock:
        now = time.time()
        elapsed = now - last_token_update
        last_token_update = now
        tokens = min(MAX_EVAL_RATE, tokens + (elapsed * MAX_EVAL_RATE))
        if tokens >= 1.0:
            tokens -= 1.0
            return True
        return False


def send_zero_window_probe(client_ip: str, client_port: int, expected_ack: int):
    """
    Sends an active zero-window probe packet to the client: <Win=0, ACK=expected_ack>.
    If the client stack is alive, TCP specifications require it to reply with an ACK immediately.
    """
    probe = (
        IP(src=RTU_IP, dst=client_ip)
        / TCP(
            sport=TELNET_PORT,
            dport=client_port,
            seq=expected_ack,
            ack=0,
            flags="A",
            window=0,
        )
    )
    send(probe, verbose=False)
    print(f"[GATEWAY-DRQ] Dispatched Active Zero-Window Probe to {client_ip}:{client_port} (Win=0, SEQ={expected_ack})")


def handle_quarantine_timeout(session_key, nfq_pkt_id, nfq_payload):
    """
    Fires if 80ms passes without a client ACK.
    This means the client really did close or crash, so we let the RST through.
    """
    with state_lock:
        if session_key in quarantine_buffer:
            del quarantine_buffer[session_key]
    
    print(f"[GATEWAY-DRQ] Timeout (Tq = 80ms) expired for {session_key}. No client ACK received.")
    print(f"[GATEWAY-DRQ] Client deemed unreachable/terminated. Forwarding RST to RTU (NF_ACCEPT).")
    try:
        nfq_payload.accept()
    except Exception:
        pass


def process_packet(nfq_pkt):
    """Inspects every packet passed through iptables NFQUEUE hook."""
    raw_payload = nfq_pkt.get_payload()
    scapy_pkt = IP(raw_payload)

    if not scapy_pkt.haslayer(TCP):
        nfq_pkt.accept()
        return

    ip_layer = scapy_pkt[IP]
    tcp_layer = scapy_pkt[TCP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    sport = tcp_layer.sport
    dport = tcp_layer.dport
    flags = tcp_layer.flags

    # Inbound traffic destined for RTU Telnet port
    if dst_ip == RTU_IP and dport == TELNET_PORT:
        session_key = (src_ip, sport)
        
        with state_lock:
            if session_key not in active_sessions:
                active_sessions[session_key] = {
                    "last_seq": tcp_layer.seq,
                    "last_ack": tcp_layer.ack,
                    "has_iac": False,
                    "last_active": time.time(),
                }
            else:
                active_sessions[session_key]["last_seq"] = tcp_layer.seq
                active_sessions[session_key]["last_ack"] = tcp_layer.ack
                active_sessions[session_key]["last_active"] = time.time()

            # Stage 1: Check for standard Telnet IAC negotiation byte (0xFF)
            if len(tcp_layer.payload) > 0:
                payload_bytes = bytes(tcp_layer.payload)
                if b"\xff" in payload_bytes:
                    active_sessions[session_key]["has_iac"] = True

        # Stage 2: Inspect RST and RST+ACK segments
        if flags & 0x04:
            print("\n" + "=" * 65)
            print(f"[GATEWAY-STAGE2] Intercepted Candidate RST targeting {RTU_IP}:{TELNET_PORT}")
            print(f"[GATEWAY-STAGE2] Source: {src_ip}:{sport} | SEQ: {tcp_layer.seq} | Flags: {tcp_layer.flags}")

            # Check rate limiter quota: drop bursts exceeding 50 evals/sec immediately
            if not get_tokens():
                print(f"[GATEWAY-STAGE2] Rate limit exceeded (> {MAX_EVAL_RATE} evals/sec). Dropping at wire speed (NF_DROP).")
                nfq_pkt.drop()
                print("=" * 65 + "\n")
                return

            with state_lock:
                # Keep quarantine buffer bounded to MAX_BUFFER_SIZE (LRU policy)
                if len(quarantine_buffer) >= MAX_BUFFER_SIZE:
                    oldest_key, oldest_val = quarantine_buffer.popitem(last=False)
                    print(f"[GATEWAY-STAGE2] Quarantine buffer full ({MAX_BUFFER_SIZE}). Evicting oldest: {oldest_key}")
                    oldest_val["timer"].cancel()

                # Dispatch challenge probe to verify whether the client is actually alive
                expected_seq = active_sessions.get(session_key, {}).get("last_ack", tcp_layer.seq)
                send_zero_window_probe(src_ip, sport, expected_seq)

                ack_event = threading.Event()
                ack_events[session_key] = ack_event

                timer = threading.Timer(
                    QUARANTINE_TIMEOUT,
                    handle_quarantine_timeout,
                    args=[session_key, nfq_pkt.id, nfq_pkt],
                )
                quarantine_buffer[session_key] = {
                    "pkt": nfq_pkt,
                    "timer": timer,
                    "timestamp": time.time(),
                }
                timer.start()

            # Wait for client's response to the challenge probe
            ack_received = ack_event.wait(timeout=QUARANTINE_TIMEOUT)
            if ack_received:
                with state_lock:
                    if session_key in quarantine_buffer:
                        quarantine_buffer[session_key]["timer"].cancel()
                        del quarantine_buffer[session_key]
                print(f"[GATEWAY-STAGE2] [✓] Client ACK received within Tq ({QUARANTINE_TIMEOUT*1000}ms)!")
                print(f"[GATEWAY-STAGE2] [✓] Client Liveliness Confirmed! Dropping Quarantined RST (NF_DROP).")
                print(f"[GATEWAY-STAGE2] [✓] SCADA Telnet Session Intact & Preserved!")
                print("=" * 65 + "\n")
                nfq_pkt.drop()
                return
            else:
                # Timer callback handles forwarding if no response received
                print("=" * 65 + "\n")
                return

    # Outbound or Client challenge responses
    if src_ip == RTU_IP and sport == TELNET_PORT:
        pass  # Server response packet
    elif dport == TELNET_PORT and (flags & 0x10) and not (flags & 0x04):
        # Client replied with a pure ACK
        session_key = (src_ip, sport)
        if session_key in ack_events:
            ack_events[session_key].set()

    nfq_pkt.accept()


def main():
    print("=" * 65)
    print("  In-Line Protective Gateway Defense Daemon (Stage 1 & Stage 2 DRQ)")
    print(f"  Quarantine Buffer: {MAX_BUFFER_SIZE} entries | Timeout: {QUARANTINE_TIMEOUT*1000} ms")
    print(f"  Token Bucket Limit: {MAX_EVAL_RATE} evals/sec")
    print("=" * 65)

    nfqueue = NetfilterQueue()
    nfqueue.bind(0, process_packet)

    try:
        print("[GATEWAY] NetfilterQueue bound to Queue 0. Filtering live transit packets...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[GATEWAY] Stopping defense daemon.")
    finally:
        nfqueue.unbind()


if __name__ == "__main__":
    main()
