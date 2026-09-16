# CSE 406 Project: Off-Path TCP Reset Attack & In-Line Gateway Defense

**Course**: CSE 406: Computer Security Sessional  
**Topic 14**: Off-Path TCP Reset Attack on Telnet and In-Line Gateway Defense  
**Group**: C2 Group 6  

---

## 1. Project Overview & Architecture

This project implements an experimental testbed demonstrating:
1. **Off-Path TCP RST Attack**: A blind adversary without packet sniffing capabilities profiles the server's linear ISN timer clock and executes a targeted micro-burst (150–400 packets) during SCADA quiescent intervals to tear down active Telnet sessions on legacy RFC 793 RTUs.
2. **Two-Stage In-Line Protective Gateway Defense**: Deployed as a transparent bump-in-the-wire router using Linux Netfilter/NFQUEUE:
   - **Stage 1: Handshake Anomaly Inspection & Rate Throttling**: Identifies rapid recon connections that lack RFC 854 Telnet option negotiations (`IAC DO/WILL`).
   - **Stage 2: Delayed Reset Quarantine (DRQ)**: Intercepts candidate RST packets, buffers them in a 64-entry LRU ring buffer, and dispatches an **Active Zero-Window Challenge Probe** (`<Win=0, ACK=expected>`) to the client. If client responds with an ACK within $T_q = 80\text{ ms}$, liveliness is confirmed and the RST is dropped (`NF_DROP`).

```
Protected OT Subnet (10.0.1.0/24)                  External Subnet (10.0.2.0/24)
+------------------------+                           +------------------------+
|    SCADA HMI Client    |                           |    Off-Path Attacker   |
|      10.0.1.10         |                           |      10.0.2.50         |
|  - Telemetry Polling   |                           |  - Clock Sampler       |
|  - Telnet Client       |                           |  - Cadence Detector    |
|  - Expects Window Probe|                           |  - Raw Socket Crafter  |
+-----------+------------+                           |  - Micro-burst Injector|
            |                                        +-----------+------------+
            |                                                    |
            |       +------------------------------------+       |
            +------>|    Intermediate Gateway Router     |<------+
                    |  eth0: 10.0.1.1  |  eth1: 10.0.2.1 |
                    |  - IP Forwarding (sysctl=1)        |
                    |  - Stage 1: Handshake Anomaly & RL |
                    |  - Stage 2: DRQ (NFQUEUE + Probes) |
                    +-----------------+------------------+
                                      |
            +-------------------------+
            |
+-----------v------------+
|    Legacy RTU Server   |
|      10.0.1.20:23      |
|  - RFC 793 TCP Stack   |
|  - Linear Timer ISN    |
|  - W = 65,535          |
|  - Telnet Register Svc |
+------------------------+
```

---

## 2. Directory Structure

```
d:/security/
├── attacker/
│   ├── checksum.py            # RFC 1071 IP & TCP pseudo-header checksum engine
│   ├── raw_socket_crafter.py  # Binary struct packed raw packet builder
│   ├── recon_sampler.py       # Phase 1: Timer-based ISN clock profiler
│   └── exploit_burst.py       # Phase 2: Micro-burst RST injector
├── client/
│   └── scada_hmi.py           # SCADA HMI client with periodic quiescent polling
├── rtu/
│   └── rfc793_server.py       # Legacy RTU server emulator (RFC 793 W=65535, linear ISN)
├── gateway/
│   ├── defense_daemon.py      # Two-stage In-Line NFQUEUE defense with DRQ & Probing
│   └── run_gateway.sh         # iptables configuration and daemon starter
├── docker/
│   ├── gateway.Dockerfile     # Dual-homed router container
│   ├── rtu.Dockerfile         # OT RTU node container
│   ├── client.Dockerfile      # SCADA HMI node container
│   └── attacker.Dockerfile    # External attacker node container
├── scripts/
│   ├── setup_routes.sh        # Routing table configuration on container boot
│   └── run_attack_demo.sh     # Automated end-to-end demonstration script
├── tests/
│   ├── test_checksum.py       # Unit tests for RFC 1071 algorithm
│   ├── test_packet_crafter.py # Unit tests for raw header struct serialization
│   └── test_defense_logic.py  # Unit tests for DRQ LRU, Telnet IAC, and RFC 793 logic
├── docker-compose.yml         # Containerized routed topology
└── implementation_plan.md     # Detailed engineering design plan
```

---

## 3. How to Run

### A. Local Unit Tests
Run using your virtual environment:
```powershell
D:\environments\sec_env\Scripts\python.exe -m pytest tests/ -v
```

### B. Full Docker Demonstration
1. **Start the Multi-Container Environment**:
   ```bash
   docker compose up -d --build
   ```
2. **Execute the End-to-End Attack & Defense Demo**:
   - Via Python (PowerShell / Windows / Linux):
     ```powershell
     D:\environments\sec_env\Scripts\python.exe scripts/run_demo.py
     ```
   - Or via Bash (Git Bash / WSL / Linux):
     ```bash
     bash scripts/run_attack_demo.sh
     ```
3. **Manual Step-by-Step Execution**:
   - **View SCADA polling**: `docker compose logs -f client`
   - **Launch Attack**: `docker compose exec attacker python3 /app/attacker/exploit_burst.py`
   - **Enable Defense**: `docker compose exec -d gateway /app/gateway/run_gateway.sh`
   - **Relaunch Attack against Defended Gateway**: Observe that the session remains unbroken!

