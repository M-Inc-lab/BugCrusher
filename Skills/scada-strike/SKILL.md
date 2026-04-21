---
name: scada-strike
description: |
  Offensive security tool for ICS/SCADA environments — targets Siemens S7, Modbus, DNP3, and other industrial protocols.
  
  USE WHEN:
  - Target is an industrial control system, PLC, RTU, or SCADA deployment
  - Asked to assess ICS security, test PLCs, or audit industrial networks
  - Working on bug bounty involving industrial systems, critical infrastructure, or OT environments
  - Need to enumerate Siemens S7 PLCs, test Modbus devices, or assess industrial protocol security
  
  CAPABILITIES:
  - PLC discovery and enumeration (Siemens S7-300/1200/1500, Modbus TCP, DNP3)
  - S7CommPlus protocol manipulation and authentication bypass
  - Industrial protocol fuzzing and vulnerability assessment
  - PLC program extraction and logic analysis
  - CVE weaponization for industrial equipment
  - Hardware-in-the-loop testbed construction
  - Anomaly detection bypass for industrial traffic
  
  RESEARCH PERSONA NOTES (Key Experts):
  - Nathan Brubaker (Miteru): Siemens S7 protocol analysis, S7CommPlus exploitation
  - Marina Levy (Check Point): ICS network protocol vulnerabilities, Modbus security
  - See references/ for full expert taxonomy
  
metadata:
  author: morningstar.zo.computer
  version: 1.0
  created: 2026-04-21
  tags: [ics, scada, plc, industrial, siemens, modbus, ot-security]
allowed-tools: Bash, Read, Edit, Grep
---

# SCADA-STRIKE — ICS Offensive Framework

## PERSONA: Domain Experts Modeled

### Lead Exploit Researchers
- **Nathan Brubaker** (Miteru) — Siemens S7 deep-dive, S7CommPlus protocol manipulation
- **Marina Levy** (Check Point) — ICS network protocol fuzzing, Modbus/DNP3 analysis
- **Johannes F. (KIT)** — Data-modification attacks on S7, smart grid security

### Vulnerability Researchers
- **K. Ovaz Akpinar** (Scientific Reports 2026) — S7-1200/1500 PLC vulnerability frameworks
- **Jonas Chrabrow** (IHP) — S7-300 remote attack frameworks, low-traffic exploitation
- **Amit Kleinmann** (ERAU) — Model-based IDS for S7 networks, DFA detection

### Red Team Operators
- **B. Kind [Redpacket Security]** — CVE analysis for industrial systems
- **Applied Risk Researchers** — DoS vulnerabilities in safety controllers
- **Dr. Klaus R. (Siemens Advanta)** — Zero Trust for OT environments

---

## ATTACK PLAYBOOK

### PHASE 1: ICS Discovery

```bash
# Nmap ICS-specific port scan
nmap -p 102,502,44818,1911,2404,20547 --script=modbus-discover,s7-enumerate,enip-info <target>

# PLC identification
python3 Skills/scada-strike/scripts/scada_enum.py <target>

# Siemens S7 device discovery
nmap -p 102 --script s7-info <target>
```

### PHASE 2: S7 Protocol Exploitation

**S7-1200/1500 Authentication Bypass:**
```bash
# Probe S7comm for version info
python3 Skills/scada-strike/scripts/s7_probe.py <target>

# Test CVE-2020-15700 (S7-1200/1500 auth bypass)
msfconsole -x "use exploit/windows/scada/s7_login_bypass"

# Test session hijack via S7CommPlus
python3 Skills/scada-strike/scripts/s7_hijack.py <target> --session <session_token>
```

**S7-300 Remote Attack (IHP-Attack Framework):**
```bash
# PNIO Scanner — discover PLCs
python3 Skills/scada-strike/scripts/pnio_scanner.py <target>

# Inner Scanner — extract PLC data
python3 Skills/scada-strike/scripts/inner_scanner.py <target> --plc-ip <ip>

# Authentication Bypass module
python3 Skills/scada-strike/scripts/s7_bypass.py <target>
```

### PHASE 3: Industrial Protocol Fuzzing

```bash
# Modbus fuzzing
python3 Skills/scada-strike/scripts/modbus_fuzz.py <target> --unit-id 1

# DNP3 fuzzer
python3 Skills/scada-strike/scripts/dnp3_fuzz.py <target>

# S7comm parameter enumeration
python3 Skills/scada-strike/scripts/s7_enum_params.py <target>
```

### PHASE 4: CVE Weaponization (ICS)

```python
# Key CVEs for Siemens PLCs:
# CVE-2020-15700 — S7-1200/1500 auth bypass (CVSS 8.1)
# CVE-2022-38791 — S7-300 remote code execution (CVSS 9.8)
# CVE-2023-42744 — Siemens Industrial Edge Management auth bypass
# CVE-2021-45105 — DNP3 protocol vulnerabilities

# Run CVE weaponizer for ICS targets
python3 Skills/scada-strike/scripts/cve_ics_weaponizer.py --target <target> --plc-model s7-1500
```

### PHASE 5: PLC Logic Analysis

```bash
# Extract PLC program (if authenticated)
python3 Skills/scada-strike/scripts/plc_dump.py <target> --plc-ip <ip> --slot 1

# Analyze ladder logic for backdoors
python3 Skills/scada-strike/scripts/plc_analyze.py /tmp/plc_dump.bin

# Test for safety controller DoS (Applied Risk research)
python3 Skills/scada-strike/scripts/safety_dos.py <target>
```

---

## SEVERITY TRIAGE — ICS Specific

### P1/P2 (Worth Hunting)
- RCE on PLC (any vendor: Siemens, Schneider, Rockwell)
- Authentication bypass on S7CommPlus/S7-1200/S7-1500
- SSRF from industrial management interface (cloud metadata)
- Safety controller DoS (life/safety risk)
- Cross-instance data access in industrial cloud platforms
- Supply-chain compromise of PLC firmware

### P3/P4 (Submit If In Scope)
- Modbus TCP write without authentication (operational risk)
- Unencrypted industrial protocol traffic (passive interception)
- Weak cryptographic implementation in S7comm
- Information disclosure via Apollo Tracing for ICS
- PLC firmware version disclosure

### P5 (Skip Unless Program Accepts)
- ICS device open on internet (informational)
- Missing security headers on SCADA web interfaces
- Public enumeration of PLC models via Shoden/Radiation Bird
- GraphQL introspection on industrial management (no auth path)

---

## TESTBED CONSTRUCTION (For Research)

```bash
# Deploy ICS honeypot (Conpot)
python3 Skills/scada-strike/scripts/conpot_deploy.py --interface eth0 --protocols s7,modbus

# Hardware-in-the-loop testbed (Akpinar method)
python3 Skills/scada-strike/scripts/testbed_builder.py --plc s7-1500 --topology linear,star
```

---

## REFERENCES

### Key Papers (In references/)
- `siemens_s7_vulnerability_assessment.pdf` — Nature Scientific Reports 2026
- `s7_protocol_attacks_kit.pdf` — ACM e-Energy 2025
- `plc_ics_sok_arxiv.pdf` — 17-year survey of PLC security
- `s7commplus_manipulation.pdf` — Elsevier IJOCIP 2021
- `ihp_attack_framework.pdf` — S7-300 remote attack paper

### CVE Database for ICS
- Siemens S7-1200: CVE-2020-15700, CVE-2021-45105
- Siemens S7-300: CVE-2022-38791, CVE-2023-28489
- Siemens S7-1500: CVE-2020-15700, CVE-2023-42744
- Schneider Modicon: CVE-2022-45715, CVE-2023-38789
- Rockwell: CVE-2023-21554, CVE-2024-22134

### Expert Taxonomy
See `references/experts.md` for full researcher database.