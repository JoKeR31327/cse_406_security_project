"""
SCADA HMI Client Simulation.
Periodically polls the Legacy RTU server over Telnet with defined quiescent pauses.
Monitors session state and detects unexpected socket termination.
"""
import socket
import time
import sys

RTU_IP = "10.0.1.20"
RTU_PORT = 23
CLIENT_SOURCE_PORT = 49152
POLL_INTERVAL = 3.0  # 3-second quiet interval between telemetry polls (Delta SEQ = 0)


def run_scada_client():
    print("=" * 65)
    print("  SCADA HMI Telemetry Polling Console")
    print(f"  Target RTU: {RTU_IP}:{RTU_PORT}")
    print(f"  Client Source Port: {CLIENT_SOURCE_PORT}")
    print(f"  Polling Cadence: Every {POLL_INTERVAL} seconds")
    print("=" * 65)

    while True:
        try:
            print(f"[SCADA-HMI] Establishing Telnet session to {RTU_IP}:{RTU_PORT} from port {CLIENT_SOURCE_PORT}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                # Bind specifically to the known industrial client port
                sock.bind(("", CLIENT_SOURCE_PORT))
            except Exception as e:
                print(f"[SCADA-HMI] Note: bind to specific port: {e}")

            sock.settimeout(5.0)
            sock.connect((RTU_IP, RTU_PORT))
            print("[SCADA-HMI] Connected! Receiving banner...")
            
            try:
                banner = sock.recv(1024).decode(errors="ignore")
                print(f"[SCADA-HMI] Server Banner: {banner.strip()}")
            except socket.timeout:
                pass

            poll_count = 0
            while True:
                poll_count += 1
                query = f"POLL_TELEMETRY_CYCLE_{poll_count}\n"
                print(f"\n[SCADA-HMI] [{time.strftime('%H:%M:%S')}] >>> Transmitting Poll Query #{poll_count}...")
                
                sock.sendall(query.encode())
                response = sock.recv(1024).decode(errors="ignore")
                
                if not response:
                    print("[SCADA-HMI] [!] Connection closed by foreign host (Zero bytes received).")
                    break

                print(f"[SCADA-HMI] [{time.strftime('%H:%M:%S')}] <<< Received Response: {response.strip()}")
                print(f"[SCADA-HMI] Entering Quiescent Pause ({POLL_INTERVAL}s) [Delta SEQ = 0, Window Stationary]...")
                time.sleep(POLL_INTERVAL)

        except (socket.error, ConnectionResetError, BrokenPipeError) as e:
            print("\n" + "!" * 65)
            print(f"[SCADA-HMI] [!] CONNECTION TERMINATED: {e}")
            print("[SCADA-HMI] [!] Connection closed by foreign host.")
            print("!" * 65)

            # Check if socket is dead on the server side (expecting server rejection)
            print("[SCADA-HMI] Attempting immediate follow-up query to verify socket state...")
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.settimeout(2.0)
                test_sock.connect((RTU_IP, RTU_PORT))
                test_sock.close()
            except Exception as follow_up_err:
                print(f"[SCADA-HMI] Follow-up connection rejected: {follow_up_err}")
        
        print("\n[SCADA-HMI] Retrying connection in 5 seconds...\n")
        time.sleep(5)


if __name__ == "__main__":
    run_scada_client()
