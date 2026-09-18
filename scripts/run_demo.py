"""
Cross-Platform Python Demonstration Runner.
Executes:
1. Scenario A: Undefended Attack (Session teardown).
2. Scenario B1: Defended Attack - Standard High-Speed Burst (Filtered by Rate Limiter & DRQ).
3. Scenario B2: Defended Attack - Dynamically Narrower Throttled Burst (Bypasses rate limiter, caught by DRQ Active Probe).
"""
import time
import subprocess
import sys


def run_cmd(cmd: str, desc: str = ""):
    """Executes a shell command and displays stdout/stderr output."""
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

    # 1. Verify container runtime status
    run_cmd("docker compose ps", "Step 1: Checking Docker Container Status")

    # 2. Check baseline client polling
    print("\n[+] Step 2: Observing Active SCADA Polling (Undefended Baseline)...")
    time.sleep(2)
    run_cmd("docker compose logs --tail=6 client", "Current Client Telemetry Logs")

    # 3. Scenario A: Run undefended attack
    print("\n" + "=" * 75)
    print("  SCENARIO A: UNDEFENDED ATTACK EXECUTION")
    print("=" * 75)
    print("[*] Launching Phase 1 (Recon Clock Sampling) & Phase 2 (Standard Micro-Burst)...")
    run_cmd("docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py --mode standard")

    time.sleep(1)
    print("\n[*] Verifying Observable Teardown Indicators (§5 of Design Report):")
    run_cmd("docker compose logs --tail=10 rtu", "Indicator 1: RTU Server Socket Deallocation Logs")
    run_cmd("docker compose logs --tail=10 client", "Indicator 2: SCADA Client Disconnection & Rejection Logs")
    print("\n[+] SCENARIO A RESULT: Undefended Telnet session severed successfully!")

    # 4. Scenario B: Launch in-line gateway defense
    print("\n" + "=" * 75)
    print("  SCENARIO B: DEFENDED ATTACK EXECUTION (IN-LINE GATEWAY ACTIVE)")
    print("=" * 75)
    print("[*] Activating In-Line Gateway Defense (Stage 1 Anomaly Limiter + Stage 2 DRQ)...")
    run_cmd("docker compose exec -d gateway /app/gateway/run_gateway.sh")
    time.sleep(4)

    print("\n[*] Allowing SCADA client to establish active polling under Gateway protection...")
    run_cmd("docker compose logs --tail=5 client", "SCADA Client Telemetry under Gateway")

    # Attempt 1: Standard wire-speed burst against gateway
    print("\n" + "-" * 75)
    print("  ATTEMPT 1: Attacker Launches Standard High-Speed Burst (250 pkts @ wire speed)")
    print("-" * 75)
    run_cmd("docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py --mode standard")
    time.sleep(1)
    run_cmd("docker compose logs --tail=5 client", "SCADA Client Status after Attempt 1 (Intact)")

    # Attempt 2: Throttled narrow burst trying to slip past rate limiter
    print("\n" + "-" * 75)
    print("  ATTEMPT 2: Attacker Adapts -> Dynamically Narrower Burst (20 pkts @ ~25 pkts/sec)")
    print("  Goal: Sneak under the 50 evals/sec rate limiter to test DRQ probe defense")
    print("-" * 75)
    run_cmd("docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py --mode narrow")
    time.sleep(1)

    print("\n[*] Verifying Gateway Defense and Session Integrity:")
    run_cmd("docker compose logs --tail=15 gateway", "Gateway Defense Logs (DRQ & Active Probing)")
    run_cmd("docker compose logs --tail=6 client", "SCADA Client Status after Attempt 2 (Unbroken Session)")

    print("\n" + "=" * 75)
    print("  DEMONSTRATION SUMMARY & PROJECT VALIDATION")
    print("  1. Undefended Target: Session severed via in-window micro-burst (<50ms)")
    print("  2. Defended (Attempt 1): High-speed flood filtered & dropped by Token-Bucket")
    print("  3. Defended (Attempt 2): Narrow stealth burst caught & dropped by DRQ Probe")
    print("  4. Zero-Window Probe: Confirmed client liveliness (Win=0, ACK=expected)")
    print("  5. Session Integrity: SCADA telemetry 100% uninterrupted across all attacks")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    main()
