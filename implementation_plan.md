# Implementation Plan: Off-Path TCP RST Attack on Telnet & In-Line Gateway Defense

Implementation plan for **Topic 14: Off-Path TCP Reset Attack on Telnet and In-Line Gateway Defense** (CSE 406: Computer Security Sessional, C2 Group 6).

The plan translates the system design report into a fully executable, containerized testbed with raw socket packet generation, two-phase reconnaissance and attack automation, and an in-line NFQUEUE-based protective gateway defense.

---

## User Review Required

> [!IMPORTANT]
> **Docker & Host Requirements**:
> The testbed uses Docker Compose to provision two isolated bridge subnets (`10.0.1.0/24` and `10.0.2.0/24`) and four containerized nodes. Containers executing raw socket manipulation, routing, or Netfilter manipulation require Linux network capabilities (`NET_ADMIN` and `NET_RAW`). On Windows, this will run cleanly within Docker Desktop (WSL2 backend).

> [!WARNING]
> **RFC 793 vs. Modern Linux TCP Stack (RFC 5961)**:
> Modern Linux kernels (kernel 3.6+) implement RFC 5961 Challenge-ACK safeguards by default and randomize ISNs via SipHash/PRNG (RFC 6528). To faithfully emulate the legacy RTU running an RFC 793 stack (e.g., lwIP / VxWorks) with a linear ISN clock and 64 KB window ($W=65,535$), we implement the RTU service using a dedicated user-space RFC 793 TCP engine / lwIP tap daemon on `10.0.1.20:23`. This guarantees 100% deterministic reproducibility regardless of the underlying host kernel.

---

## Architecture & Component Overview

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

## Proposed Changes

### 1. Testbed & Environment Provisioning

Establish the routed multi-subnet container environment.

#### [NEW] [docker-compose.yml](file:///d:/security/docker-compose.yml)
- Defines two isolated Docker bridge networks:
  - `ot_net`: `10.0.1.0/24` (Gateway: `10.0.1.1`, Client: `10.0.1.10`, RTU: `10.0.1.20`)
  - `ext_net`: `10.0.2.0/24` (Gateway: `10.0.2.1`, Attacker: `10.0.2.50`)
- Nodes:
  - `gateway`: Dual-homed router with `cap_add: [NET_ADMIN]`, IP forwarding enabled.
  - `rtu`: Target server on `ot_net`, static IP `10.0.1.20`, default gateway `10.0.1.1`.
  - `client`: SCADA HMI on `ot_net`, static IP `10.0.1.10`, default gateway `10.0.1.1`.
  - `attacker`: Blind adversary on `ext_net`, static IP `10.0.2.50`, default gateway `10.0.2.1`. No interface on `ot_net`.

#### [NEW] [docker/gateway.Dockerfile](file:///d:/security/docker/gateway.Dockerfile)
- Based on Debian/Ubuntu with `iptables`, `iproute2`, `net-tools`, `python3`, `libnetfilter-queue-dev`, `python3-netfilterqueue`, `scapy`, and build essentials.

#### [NEW] [docker/rtu.Dockerfile](file:///d:/security/docker/rtu.Dockerfile)
- Environment for the legacy RTU with Python 3, `scapy`, raw socket tools, and networking utilities.

#### [NEW] [docker/client.Dockerfile](file:///d:/security/docker/client.Dockerfile)
- Python 3, `telnet`, networking test utilities.

#### [NEW] [docker/attacker.Dockerfile](file:///d:/security/docker/attacker.Dockerfile)
- Python 3 raw socket environment with `NET_RAW` / `NET_ADMIN` capability.

#### [NEW] [scripts/setup_routes.sh](file:///d:/security/scripts/setup_routes.sh)
- Automatic routing table configuration inside containers upon boot:
  - Gateway: Configures `net.ipv4.ip_forward=1`, sets up iptables baseline rules.
  - Client & RTU: Sets default route via `10.0.1.1`.
  - Attacker: Sets default route via `10.0.2.1`.
  - Validates network isolation: ensures attacker cannot sniff traffic on `ot_net`.

---

### 2. Legacy RTU Server (RFC 793 Stack & SCADA Registry)

Emulates an embedded RTU microcontroller (e.g., lwIP stack) without RFC 5961 Challenge-ACK logic.

#### [NEW] [rtu/rfc793_server.py](file:///d:/security/rtu/rfc793_server.py)
- **Linear ISN Clock**: ISN generation adheres to $ISN(t) = (ISN_0 + \alpha \cdot t) \pmod{2^{32}}$ where $\alpha$ is a constant timer increment (e.g. 250,000 ticks/sec), mimicking embedded firmware hardware timers.
- **RFC 793 In-Window Acceptance**:
  - Receive window fixed at $W = 65,535$.
  - Upon receiving an incoming segment with `RST` flag:
    - If $RCV.NXT \le SEG.SEQ < RCV.NXT + W$: immediate transition to `CLOSED`, releasing socket state.
    - If outside the window: silently drop or ignore.
- **SCADA Register Service**:
  - Listens on TCP port 23 (Telnet).
  - Handles basic Telnet option negotiation (DO/DONT/WILL/WONT IAC bytes `0xFF 0xFD 0x18`, etc.).
  - Serves simulated industrial telemetry registers (e.g., `REG 0x01: PUMP_SPEED = 1450 RPM`, `REG 0x02: TANK_PRESSURE = 4.2 BAR`).
  - Upon socket closure by RST, subsequent client queries trigger unsolicited `RST` generation.

---

### 3. SCADA HMI Client Simulation

#### [NEW] [client/scada_hmi.py](file:///d:/security/client/scada_hmi.py)
- Establishes a persistent Telnet connection to RTU at `10.0.1.20:23` from an ephemeral port (e.g., 49152).
- Completes RFC 854 Telnet option negotiations.
- **Cadence & Quiescent Loop**:
  - Emits telemetry polling query every $T_{poll} = 3.0$ seconds (e.g., `GET_TELEMETRY\n`).
  - Reads and logs response.
  - Enters quiescent pause of 3.0 seconds ($\Delta SEQ = 0$, window stationary).
- **Socket Break Detector**:
  - Detects `Connection closed by foreign host` or `ECONNRESET`.
  - Attempts immediate subsequent query to document the unsolicited RST behavior post-teardown.

---

### 4. Low-Level Packet Crafter & Checksum Engine

Per Section 3.1 & 3.2 of the design report: strictly zero high-level packet generation libraries for attack injection. All attack segments crafted via Python binary struct packing and raw sockets.

#### [NEW] [attacker/checksum.py](file:///d:/security/attacker/checksum.py)
- Implements RFC 1071 16-bit one's complement checksum:
  - `compute_ip_checksum(header_bytes)`: standard IPv4 header checksum.
  - `compute_tcp_checksum(src_ip, dst_ip, tcp_header_and_payload)`: standard 12-byte pseudo-header sum + TCP header sum.

#### [NEW] [attacker/raw_socket_crafter.py](file:///d:/security/attacker/raw_socket_crafter.py)
- **IPv4 Serialization (Table 1)**:
  - Version: 4 (4b), IHL: 5 (4b) -> `0x45`
  - DSCP/ECN: `0x00` (8b)
  - Total Length: 40 bytes (`0x0028`)
  - Identification: `0x1337` (16b)
  - Flags & Fragment Offset: `0x4000` (DF flag set, offset 0)
  - TTL: 64 (8b)
  - Protocol: 6 [TCP] (8b)
  - Source IP: `10.0.1.10` (spoofed client IP)
  - Destination IP: `10.0.1.20` (target RTU IP)
- **TCP Serialization (Table 2 & 3)**:
  - Source Port: Ephemeral client port (16b)
  - Destination Port: 23 [Telnet] (16b)
  - Sequence Number: In-window candidate SEQ (32b)
  - Acknowledgment Number: Echoed/computed ACK (32b)
  - Data Offset: 5 (4b, offset 20 bytes), Reserved: 0
  - Flags: `0x14` (RST + ACK)
  - Window Size: 0
  - Urgent Pointer: 0
- Raw socket transport: `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` with `setsockopt(IPPROTO_IP, IP_HDRINCL, 1)`.

---

### 5. Reconnaissance Engine (Clock Sampling & Cadence Profiling)

#### [NEW] [attacker/recon_sampler.py](file:///d:/security/attacker/recon_sampler.py)
- **Step 1: Clock Sampling**:
  - Connects to server port 23 using an un-spoofed handshake from `10.0.2.50`.
  - Captures the server's SYN-ACK $ISN_{sample}$ at timestamp $t_0$.
  - Takes a second sample at $t_1$ to estimate the linear clock advancement rate:
    $$\text{Clock Rate } R = \frac{\Delta ISN}{\Delta t} \pmod{2^{32}}$$
- **Step 2: Cadence Detection**:
  - Detects polling period $T_{idle}$ and identifies the phase of the quiescent interval.

---

### 6. Attack Orchestrator (Targeted Micro-Burst Injection)

#### [NEW] [attacker/exploit_burst.py](file:///d:/security/attacker/exploit_burst.py)
- **Window Projection**:
  - Computes candidate sequence number:
    $$SEQ_{est} = ISN_{sample} + R \cdot (t_{attack} - t_{sample}) + \text{offset}$$
  - Defines uncertainty bound $[SEQ_{est} - \delta, SEQ_{est} + \delta]$.
- **Focused Micro-Burst Injection**:
  - Emits 150–400 spoofed RST+ACK packets.
  - Stride size $\le W$ (e.g., step of $W/2 = 32,768$ or smaller) sweeping the projected sequence interval.
  - Dispatches burst directly within the detected SCADA quiescent pause ($\Delta t > T_{idle}, \Delta SEQ = 0$).
  - Evaluates teardown efficiency (< 50ms teardown, < 500 pps burst rate, 95%+ overhead reduction vs $2^{32}/W$).

---

### 7. In-Line Protective Gateway Defense

Implemented directly on the intermediate router (`10.0.1.1` / `10.0.2.1`).

#### [NEW] [gateway/defense_daemon.py](file:///d:/security/gateway/defense_daemon.py)
- **Netfilter / iptables Hooks**:
  - Forwarded TCP traffic targeting `10.0.1.20:23` is directed to `NFQUEUE num 0`.
- **Stage 1: Handshake Anomaly & Rate Throttling**:
  - Tracks embryonic handshakes to port 23.
  - Detects connections that open and terminate without sending Telnet option negotiations (`IAC DO/WILL`, `0xFF 0xFD`, etc.) — classifying them as reconnaissance probes.
  - Applies per-source IP rate limiting (token bucket / quarantine table).
- **Stage 2: Delayed Reset Quarantine (DRQ)**:
  - Catches candidate RST / RST+ACK packets destined for active Telnet sessions.
  - Enforces evaluation token bucket ($R_{max} = 50\text{ evaluations/sec}$); excessive packets dropped at wire speed.
  - Buffers the candidate RST segment in a 64-entry LRU ring buffer and initiates quarantine timer $T_q = 80\text{ ms}$.
  - Dispatches an **Active Zero-Window Challenge Probe** to the client (`10.0.1.10`):
    - Handcrafted TCP packet: `Flags: ACK`, `Win = 0`, `ACK = expected RCV.NXT`.
  - **Liveliness Decision Logic**:
    - **Case 1 (Client alive & active/idle)**: Client kernel stack responds with a pure ACK. Upon receipt within $T_q = 80\text{ ms}$:
      - Liveliness confirmed $\to$ Quarantined RST is dropped (`NF_DROP`).
      - SCADA Telnet session remains completely intact!
    - **Case 2 (Legitimate teardown / client dead)**: No ACK received within $T_q = 80\text{ ms}$:
      - Client is confirmed unreachable / intentionally terminated.
      - Gateway releases and forwards the RST packet to RTU (`NF_ACCEPT`).
      - Normal socket teardown proceeds with negligible ($<80\text{ ms}$) delay.

#### [NEW] [gateway/run_gateway.sh](file:///d:/security/gateway/run_gateway.sh)
- Configures iptables rules for forwarding, Stage 1 bypass/queueing, and Stage 2 NFQUEUE attachment. Launches `defense_daemon.py`.

---

### 8. Testing & Demonstration Scripts

#### [NEW] [tests/test_checksum.py](file:///d:/security/tests/test_checksum.py)
- Unit tests verifying RFC 1071 IP and TCP checksums against RFC test vectors and Scapy-generated reference packets.

#### [NEW] [tests/test_packet_crafter.py](file:///d:/security/tests/test_packet_crafter.py)
- Tests byte-level layout (Table 1 & Table 2) of serialized IP and TCP headers, endianness, and flag settings.

#### [NEW] [scripts/run_attack_demo.sh](file:///d:/security/scripts/run_attack_demo.sh)
- End-to-end automated test runner:
  1. Spins up Docker Compose testbed.
  2. Runs undefended baseline: SCADA client connects, attacker profiles clock, fires micro-burst, confirms SCADA disconnect and RTU socket `CLOSED`.
  3. Enables In-Line Gateway Defense (Stage 1 + Stage 2 DRQ).
  4. Reruns attacker micro-burst against defended session: confirms client Zero-Window Probe exchange, RST drop, and continuous unbroken SCADA session.

---

## Verification Plan

### Automated Tests
1. **Checksum & Packet Serialization Validation**:
   - Run `pytest tests/` to confirm bit-exact matching of raw packet headers and RFC 1071 mathematical checksums.
2. **Network Isolation Verification**:
   - Execute tcpdump on the attacker container while client and RTU communicate; assert 0 packets captured (proves strictly off-path).

### End-to-End Simulation Scenarios
1. **Undefended Scenario (Attack Success)**:
   - Client starts polling RTU registers.
   - Attacker samples clock and injects 150–400 packet micro-burst during quiescent gap.
   - Assert: Client disconnects (`Connection closed by foreign host`).
   - Assert: RTU socket state switches from `ESTABLISHED` to `CLOSED` (verified via `ss -t -a`).
   - Assert: Subsequent client poll receives unsolicited `RST`.
2. **Defended Scenario (Defense Success)**:
   - Gateway defense daemon active with DRQ and Zero-Window probing.
   - Attacker launches identical micro-burst.
   - Assert: Gateway intercepts RST, issues probe to client, receives client ACK, drops spoofed RST.
   - Assert: Client connection never breaks; continuous polling continues uninterrupted.
   - Assert: Gateway logs show quarantined burst drops and zero memory leaks in 64-entry LRU buffer.
