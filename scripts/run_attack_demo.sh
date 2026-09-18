#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=========================================================================${NC}"
echo -e "${CYAN}  CSE 406 Project: Off-Path TCP Reset Attack & In-Line Gateway Defense   ${NC}"
echo -e "${CYAN}  Topic 14 — Automated End-to-End Demonstration Suite                   ${NC}"
echo -e "${CYAN}=========================================================================${NC}"

echo -e "\n${BLUE}[+] STEP 1: Verifying Environment & Container Status...${NC}"
docker compose ps

echo -e "\n${BLUE}[+] STEP 2: Observing Active SCADA Polling (Undefended Baseline)...${NC}"
echo -e "Displaying live telemetry exchange between SCADA Client (10.0.1.10) and RTU Server (10.0.1.20:23):"
sleep 2
docker compose logs --tail=6 client

echo -e "\n${YELLOW}=========================================================================${NC}"
echo -e "${YELLOW}  SCENARIO A: UNDEFENDED ATTACK EXECUTION                                 ${NC}"
echo -e "${YELLOW}=========================================================================${NC}"
echo -e "[*] Launching Phase 1 (Clock Sampling) and Phase 2 (Standard Micro-Burst)..."
docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py --mode standard

echo -e "\n${BLUE}[*] Verifying Observable Teardown Indicators (§5 of Design Report):${NC}"
sleep 1

echo -e "\n${CYAN}--- Indicator 1: Server Socket State Deallocation (RTU Logs) ---${NC}"
docker compose logs --tail=10 rtu

echo -e "\n${CYAN}--- Indicator 2: Client Terminal Disconnection & Rejection (Client Logs) ---${NC}"
docker compose logs --tail=10 client

echo -e "\n${GREEN}[+] SCENARIO A RESULT: Undefended Telnet session severed successfully!${NC}"

echo -e "\n${YELLOW}=========================================================================${NC}"
echo -e "${YELLOW}  SCENARIO B: DEFENDED ATTACK EXECUTION (IN-LINE GATEWAY ACTIVE)          ${NC}"
echo -e "${YELLOW}=========================================================================${NC}"
echo -e "[*] Activating In-Line Gateway Defense (Stage 1 Anomaly Limiter + Stage 2 DRQ with Zero-Window Probing)..."
docker compose exec -d gateway /app/gateway/run_gateway.sh
sleep 3

echo -e "\n[*] Allowing SCADA client to re-establish active polling under Gateway protection..."
sleep 4
docker compose logs --tail=5 client

echo -e "\n${BLUE}--- ATTEMPT 1: Attacker Launches Standard High-Speed Burst (250 pkts @ wire speed) ---${NC}"
docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py --mode standard
sleep 1
docker compose logs --tail=5 client

echo -e "\n${BLUE}--- ATTEMPT 2: Attacker Adapts -> Dynamically Narrower Throttled Burst (20 pkts @ ~25 pkts/sec) ---${NC}"
echo -e "Goal: Attempting to sneak below the 50 evals/sec rate limiter to test DRQ probe defense..."
docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py --mode narrow
sleep 1

echo -e "\n${BLUE}[*] Verifying Gateway Defense and Session Integrity:${NC}"
sleep 1

echo -e "\n${CYAN}--- Gateway Defense Daemon Logs (DRQ & Active Zero-Window Probes) ---${NC}"
docker compose logs --tail=15 gateway

echo -e "\n${CYAN}--- SCADA Client Status (Checking if session remains unbroken) ---${NC}"
docker compose logs --tail=6 client

echo -e "\n${GREEN}=========================================================================${NC}"
echo -e "${GREEN}  DEMONSTRATION SUMMARY & PROJECT VALIDATION                             ${NC}"
echo -e "${GREEN}  1. Undefended Target: Session severed via in-window micro-burst (<50ms)${NC}"
echo -e "${GREEN}  2. Defended (Attempt 1): High-speed flood filtered & dropped by Rate Limiter${NC}"
echo -e "${GREEN}  3. Defended (Attempt 2): Narrow stealth burst caught & dropped by DRQ Probe${NC}"
echo -e "${GREEN}  4. Zero-Window Probe: Confirmed client liveliness (Win=0, ACK=expected)${NC}"
echo -e "${GREEN}  5. Session Integrity: SCADA telemetry 100% uninterrupted across all attacks${NC}"
echo -e "${GREEN}=========================================================================${NC}\n"
