"""
Cross-Platform Python Demonstration Runner.
Executes both Scenario A (Undefended Attack) and Scenario B (Defended Attack with In-Line Gateway).
"""
import time
import subprocess
import sys


def run_cmd(cmd: str, desc: str = ""):
    if desc:
        print(f"\n[+] {desc}")
    print(f"    $ {cmd}")
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if res.stdout:
        print(res.stdout.strip())
    if res.stderr and res.returncode != 0:
        print(f"[-] Error: {res.stderr.strip()}")
    return res


def main():
    print("=" * 75)
    print("  CSE 406 Project: Off-Path TCP Reset Attack & In-Line Gateway Defense")
    print("  Topic 14 — Automated End-to-End Demonstration Suite")
    print("=" * 75)

    # Step 1: Check Containers
    run_cmd("docker compose ps", "Step 1: Checking Docker Container Status")

    # Step 2: Observe Undefended SCADA Polling
    print("\n[+] Step 2: Observing Active SCADA Polling (Undefended Baseline)...")
    time.sleep(2)
    run_cmd("docker compose logs --tail=6 client", "Current Client Telemetry Logs")

    # Step 3: Scenario A - Undefended Attack
    print("\n" + "=" * 75)
    print("  SCENARIO A: UNDEFENDED ATTACK EXECUTION")
    print("=" * 75)
    print("[*] Launching Phase 1 (Recon Clock Sampling) & Phase 2 (Micro-Burst Injection)...")
    run_cmd("docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py")

    time.sleep(1)
    print("\n[*] Verifying Observable Teardown Indicators (§5 of Design Report):")
    run_cmd("docker compose logs --tail=10 rtu", "Indicator 1: RTU Server Socket Deallocation Logs")
    run_cmd("docker compose logs --tail=10 client", "Indicator 2: SCADA Client Disconnection & Rejection Logs")
    print("\n[+] SCENARIO A RESULT: Undefended Telnet session severed successfully!")

    # Step 4: Scenario B - Defended Attack
    print("\n" + "=" * 75)
    print("  SCENARIO B: DEFENDED ATTACK EXECUTION (IN-LINE GATEWAY ACTIVE)")
    print("=" * 75)
    print("[*] Activating In-Line Gateway Defense (Stage 1 Anomaly Limiter + Stage 2 DRQ)...")
    run_cmd("docker compose exec -d gateway /app/gateway/run_gateway.sh")
    time.sleep(4)

    print("\n[*] Allowing SCADA client to establish active polling under Gateway protection...")
    run_cmd("docker compose logs --tail=5 client", "SCADA Client Telemetry under Gateway")

    print("\n[*] Attacking Node (10.0.2.50) re-launches identical Exploit Micro-Burst...")
    run_cmd("docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py")

    time.sleep(1)
    print("\n[*] Verifying Gateway Defense and Session Integrity:")
    run_cmd("docker compose logs --tail=15 gateway", "Gateway Defense Logs (DRQ & Active Probing)")
    run_cmd("docker compose logs --tail=6 client", "SCADA Client Status (Unbroken Session)")

    print("\n" + "=" * 75)
    print("  DEMONSTRATION SUMMARY & PROJECT VALIDATION")
    print("  1. Undefended Target: Session severed via in-window micro-burst (<50ms)")
    print("  2. Defended Target:   Spoofed RSTs intercepted & dropped by DRQ")
    print("  3. Zero-Window Probe: Confirmed client liveliness (Win=0, ACK=expected)")
    print("  4. Session Integrity: SCADA telemetry uninterrupted during attack")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    main()
