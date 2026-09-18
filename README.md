# CSE 406 Project: Off-Path TCP Reset Attack & In-Line Gateway Defense

**Course**: CSE 406: Computer Security Sessional  
**Topic 14**: Off-Path TCP Reset Attack on Telnet and In-Line Gateway Defense  
**Evaluation Group**: C2 Group 6  
**Authors**:
- Ariful Islam Shadhin (2105166)
- Mustafa Muhaimin (2105178)

---

## 1. Project Overview & Operational Motivation

In real-world **Supervisory Control and Data Acquisition (SCADA)** and industrial networks, field devices such as **Remote Terminal Units (RTUs)** are low-power embedded microcontrollers. Because they have minimal CPU capacity and tight memory limits, they cannot run heavy security mechanisms such as TLS 1.3 encryption, cryptographically secure PRNGs, or local firewalls. Furthermore, live firmware patching in running industrial plants is operationally risky and rarely performed. 

Consequently, the legacy RTU endpoint operates with **no native on-device protection**. To solve this, all defensive responsibilities are offloaded to an **intermediate In-Line Gateway Router** deployed as a transparent bump-in-the-wire inspection filter.

### Core Demonstration Capabilities
1. **Off-Path (Blind) TCP Reset Attack**:
   - A blind adversary without packet sniffing or eavesdropping capabilities profiles the server's linear hardware ISN timer ($R \approx 250{,}000 \text{ ticks/s}$).
   - Derives the current sequence base and executes a targeted micro-burst (250 packets with a $W/2 = 32{,}768$ byte stride) during SCADA idle polling gaps ($\Delta SEQ = 0$).
   - Successfully severs the established Telnet connection on an undefended path in **8.07 ms**.
2. **Two-Stage In-Line Protective Gateway Defense**:
   - **Stage 1 (IAC Anomaly Filter)**: Rejects malformed connection probes that lack RFC 854 Telnet negotiations at line rate.
   - **Stage 2 (Token Bucket Rate Limiter)**: Drops high-speed wire floods exceeding $50 \text{ evals/s}$ synchronously (`NF_DROP`).
   - **Stage 2 (Delayed Reset Quarantine - DRQ)**: Quarantines stealthy low-rate RSTs ($T_q = 80 \text{ ms}$) and dispatches an **Active Zero-Window Challenge Probe** (`<Win=0, ACK=expected>`) to the client. If the real client responds with a pure ACK, the quarantined RST is proven spoofed and dropped (`NF_DROP`), preserving continuous SCADA telemetry.

---

## 2. Network Topology & Threat Model

The environment uses Docker to isolate the industrial Operational Technology (OT) subnet from the external network via a dual-homed Linux gateway:

```
Protected OT Subnet (10.0.1.0/24)                  External Plant Subnet (10.0.2.0/24)
+------------------------+                           +------------------------+
|    SCADA HMI Client    |                           |    Off-Path Attacker   |
|      10.0.1.10:49152   |                           |      10.0.2.50         |
|  - Telemetry Polling   |                           |  - Clock Velocity Recon|
|  - 3.0s Quiescent Gap  |                           |  - Window Projection   |
|  - Telnet Client       |                           |  - Raw Socket Crafter  |
|  - Kernel Liveliness   |                           |  - Micro-Burst Crafter |
+-----------+------------+                           +-----------+------------+
            |                                                    |
            |       +------------------------------------+       |
            +------>|    Intermediate Gateway Router     |<------+
                    |  eth0: 10.0.1.1  |  eth1: 10.0.2.1 |
                    |  - Linux iptables NFQUEUE (Queue 0)|
                    |  - Stage 1: Telnet IAC Anomaly     |
                    |  - Stage 2: Token Bucket (50/s)    |
                    |  - Stage 2: DRQ (80ms) + Probing   |
                    +-----------------+------------------+
                                      |
            +-------------------------+
            |
+-----------v------------+
|  Low-Power RTU Server  |
|      10.0.1.20:23      |
|  - RFC 793 TCP Engine  |
|  - Linear ISN Clock    |
|  - Window W = 65,535   |
|  - Telnet Register Svc |
+------------------------+
```

---

## 3. Repository Structure

```
d:/security/
├── attacker/
│   ├── checksum.py            # RFC 1071 16-bit 1's complement IP/TCP checksum engine
│   ├── raw_socket_crafter.py  # Binary struct packing for wire-speed raw IP/TCP packets
│   ├── recon_sampler.py       # Phase 1: Un-spoofed SYN clock rate profiler
│   └── exploit_burst.py       # Phase 2: Micro-burst RST injector (standard & narrow modes)
├── client/
│   └── scada_hmi.py           # SCADA HMI client with periodic 3.0s quiescent polling
├── rtu/
│   └── rfc793_server.py       # Legacy RTU emulator (RFC 793 W=65535, linear ISN clock)
├── gateway/
│   ├── defense_daemon.py      # Two-stage In-Line NFQUEUE defense with DRQ & Active Probing
│   └── run_gateway.sh         # iptables configuration and gateway defense daemon launcher
├── docker/
│   ├── gateway.Dockerfile     # Dual-homed router container (Ubuntu + NetfilterQueue)
│   ├── rtu.Dockerfile         # OT RTU node container
│   ├── client.Dockerfile      # SCADA HMI node container
│   └── attacker.Dockerfile    # External attacker node container
├── scripts/
│   ├── setup_routes.sh        # Subnet routing configuration on container boot
│   ├── run_attack_demo.sh     # Automated end-to-end demonstration (Bash)
│   ├── run_demo.py            # Automated cross-platform demonstration runner (Python)
│   ├── inspect_pcap_report.py # Automated PCAP dissection and metric extraction script
│   └── gateway_traffic.pcap   # Live traffic trace of attack and defense validation
├── tests/
│   ├── test_checksum.py       # Unit tests for RFC 1071 algorithm
│   ├── test_packet_crafter.py # Unit tests for raw header byte serialization
│   └── test_defense_logic.py  # Unit tests for DRQ LRU buffer, Telnet IAC, and RFC 793 window
├── docker-compose.yml         # Containerized dual-subnet topology definition
├── requirements.txt           # Host Python dependencies for testing and demonstration
├── report.TEX                 # Formal final technical report (LaTeX)
├── FINAL_REPORT_OBSERVATIONS.md # Markdown synthesis of empirical lab observations
└── README.md                  # Project documentation
```

---

## 4. Setup & Installation

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (with WSL2 backend on Windows)
- Python 3.10+ (for running host scripts and unit tests)

### Step 1: Install Host Python Dependencies
Create and activate a virtual environment, then install the required dependencies:

```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```bash
# Linux / macOS / WSL (Bash)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 5. How to Run

### A. Run Local Unit Tests
Run the unit test suite verifying RFC 1071 checksums, packet crafting, and gateway buffer logic:

```powershell
# Using project virtual environment
Scripts\python.exe -m pytest tests/ -v

# Or with activated venv:
pytest tests/ -v
```

All 8 tests should pass in $<0.1\text{s}$.

---

### B. Start the Docker Environment
Build and launch all 4 containers in background mode:

```bash
docker compose up -d --build
```

Verify that all containers are healthy:
```bash
docker compose ps
```

---

### C. Capture Live Gateway Traffic (PCAP Recording)
To capture real transit traffic across both the OT and external subnets during the demonstration, run `tcpdump` inside the gateway container:

```bash
docker compose exec gateway tcpdump -i any -w /app/scripts/gateway_traffic.pcap
```

> **Note**: Press `Ctrl+C` when the attack and defense runs finish to finalize the `.pcap` capture file. The capture will be saved directly to `scripts/gateway_traffic.pcap`.

---

### D. Automated End-to-End Demonstration

Execute the complete multi-scenario test suite:

#### Windows / PowerShell:
```powershell
Scripts\python.exe scripts/run_demo.py
```

#### Linux / WSL / Git Bash:
```bash
bash scripts/run_attack_demo.sh
```

### Demonstration Scenarios Executed:
1. **Scenario A (Undefended Attack Execution)**:
   - Attacker samples the RTU clock ($R \approx 250{,}000 \text{ ticks/s}$).
   - Dispatches a 250-packet micro-burst at wire speed ($8.07 \text{ ms}$).
   - RTU accepts the in-window RST (`ESTABLISHED -> CLOSED`).
   - SCADA client polling fails with `ConnectionResetError (104)`.
2. **Scenario B.1 (Defended: High-Speed Flood vs. Rate Limiter)**:
   - Gateway defense is activated (`run_gateway.sh`).
   - Attacker launches standard wire-speed flood ($>25{,}000 \text{ pkts/s}$).
   - Gateway Token Bucket drops all 250 packets at line rate (`NF_DROP`).
   - Client session remains intact (polling continues).
3. **Scenario B.2 (Defended: Adaptive Stealth Narrow Burst vs. DRQ Active Probing)**:
   - Attacker adapts by throttling burst to 20 packets with 40 ms delays ($24.9 \text{ pkts/s}$) to slip under the 50 evals/s threshold.
   - Gateway DRQ intercepts packets and transmits an **Active Zero-Window Challenge Probe** (`<Win=0, ACK=expected>`).
   - Live client immediately returns a pure ACK, confirming session liveliness.
   - Gateway classifies the RST as spoofed and drops it (`NF_DROP`). SCADA session continues unbroken.

---

### E. Manual Step-by-Step Execution (Optional)

If you prefer to trigger individual steps manually:

1. **Monitor live SCADA polling**:
   ```bash
   docker compose logs -f client
   ```
2. **Execute Phase 1 & Phase 2 Undefended Attack**:
   ```bash
   docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py --mode standard
   ```
3. **Inspect RTU teardown**:
   ```bash
   docker compose logs --tail=10 rtu
   ```
4. **Activate In-Line Gateway Defense**:
   ```bash
   docker compose exec -d gateway /app/gateway/run_gateway.sh
   ```
5. **Launch Standard Flood against Gateway**:
   ```bash
   docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py --mode standard
   ```
6. **Launch Adaptive Stealth Narrow Burst**:
   ```bash
   docker compose exec -e PYTHONPATH=/app attacker python3 /app/attacker/exploit_burst.py --mode narrow
   ```
7. **Inspect Gateway Defense Decisions**:
   ```bash
   docker compose logs --tail=20 gateway
   ```

---

## 6. Inspecting the Captured PCAP & Wireshark Analysis

You can inspect and parse the generated capture file (`scripts/gateway_traffic.pcap`) directly from the command line:

```powershell
Scripts\python.exe scripts/inspect_pcap_report.py scripts/gateway_traffic.pcap
```

This outputs exact frame numbers, timestamps, sequence step sizes, and probe exchanges.

### Recommended Wireshark Display Filters:

| Analysis Phase | Wireshark Filter Expression |
| :--- | :--- |
| **All Telnet & Attack Traffic** | `tcp.port == 23` |
| **Phase 1 Clock Recon (SYN/SYN-ACK)** | `ip.addr == 10.0.2.50 && tcp.flags.syn == 1` |
| **Phase 2 Spoofed Micro-Burst (Scenario A)** | `ip.src == 10.0.1.10 && tcp.dst == 10.0.1.20 && tcp.flags.reset == 1` |
| **Gateway Active Zero-Window Probes** | `tcp.window_size == 0 && tcp.flags.ack == 1` |
| **Client Liveliness Pure ACKs** | `ip.src == 10.0.1.10 && tcp.dst == 10.0.1.20 && tcp.flags.ack == 1 && tcp.len == 0` |

---

## 7. Clean Teardown

To shut down all containers and clean up the virtual bridges:

```bash
docker compose down
```
