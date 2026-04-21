# SCADA-STRIKE — Expert Database

## Lead Exploit Researchers

### Nathan Brubaker (Miteru)
- **Domain:** Siemens S7 protocol security research
- **Specialization:** S7CommPlus protocol analysis, authentication bypass exploitation
- **Key Work:** Discovery and weaponization of CVE-2020-15700 (S7-1200/1500 auth bypass)
- **Methodology:** Byte-level protocol manipulation, session token crafting, cryptographic key exploitation
- **Publications:** Multiple CVEs in Siemens industrial equipment
- **How to Model:** Focus on precise packet structure, authentication handshake manipulation

### Marina Levy (Check Point)
- **Domain:** ICS network protocol vulnerabilities
- **Specialization:** Modbus TCP, DNP3 protocol fuzzing and exploitation
- **Key Work:** Large-scale industrial protocol analysis, vulnerability discovery
- **Methodology:** Network traffic analysis, state machine fuzzing, protocol boundary testing
- **Publications:** Multiple CVEs in industrial protocols
- **How to Model:** Understand protocol state machines, craft malformed packets at protocol boundaries

## Academic Researchers

### Johannes F. (KIT — Karlsruhe Institute of Technology)
- **Domain:** Smart grid security, S7 protocol attacks
- **Specialization:** Data-modification attacks on Siemens S7 in energy systems
- **Key Work:** ACM e-Energy 2025 — "Attacks on the Siemens S7 Protocol Using an Industrial Control System Testbed"
- **Methodology:** Hardware-in-the-loop testbeds, realistic ICS environment emulation
- **Contributions:** IDS detection approaches, defense strategies for S7 protocol abuse
- **How to Model:** Build realistic industrial test environments, test data integrity attacks

### K. Ovaz Akpinar
- **Domain:** PLC vulnerability assessment methodology
- **Specialization:** S7-1200 and S7-1500 PLC security evaluation
- **Key Work:** Nature Scientific Reports 2026 — "Vulnerability assessment and mitigation for Siemens S7-1200 and S7-1500 PLCs in industrial networks"
- **Methodology:** Hardware-inclusive testing, reproducible frameworks, ASR/MTTR metrics
- **Contributions:** Open GitHub repository + Zenodo archival for full reproducibility
- **How to Model:** Use quantitative security metrics (Attack Success Rate, Mean Time to Recovery)

### Jonas Chrabrow (IHP — Institute for Photonic Microsystems)
- **Domain:** S7-300 remote attack frameworks
- **Specialization:** Low-traffic, stealthy PLC exploitation
- **Key Work:** IHP-Attack framework for S7-300 PLCs, Python-Snap7 + Scapy implementation
- **Methodology:** PNIO Scanner for PLC discovery, Inner Scanner for data extraction, Authentication Bypass module
- **Contributions:** Real-world testing on water-level control hardware, covert execution with low detection
- **How to Model:** Stealth-focused exploitation, minimal network footprint attacks

### Amit Kleinmann (Embry-Riddle Aeronautical University)
- **Domain:** Model-based intrusion detection for SCADA
- **Specialization:** DFA-based anomaly detection for S7 networks
- **Key Work:** "Accurate Modeling of the Siemens S7 SCADA Protocol for Intrusion Detection" — JDFSL
- **Methodology:** Deterministic Finite Automaton modeling of HMI-PLC communication channels
- **Results:** 99.82% accuracy in identifying normal S7 traffic, very low false positives
- **How to Model:** Understand traffic periodicity, command sequencing, normal vs anomalous behavior

## Vulnerability Researchers

### B. Kind (Redpacket Security)
- **Domain:** CVE analysis for industrial systems
- **Specialization:** Siemens Industrial Edge Management vulnerabilities
- **Key Work:** CVE-2026-33892 analysis — authentication bypass enabling remote tunneling
- **Contribution:** Detailed exploit prerequisites, security posture guidance, monitoring recommendations

### Applied Risk Researchers
- **Domain:** Safety controller security
- **Specialization:** DoS vulnerabilities in safety controllers from major vendors
- **Key Work:** Disclosed at SecurityWeek ICS Cyber Security Conference
- **Impact:** Life safety risk — safety controller DoS can affect physical safety systems

### Dr. Klaus R. (Siemens Advanta)
- **Domain:** OT/ICS Zero Trust architecture
- **Specialization:** Industrial cybersecurity framework design
- **Key Work:** SINEC Security Suite (Inspector, Monitor, Guard), SINEC Secure Connect
- **Contributions:** Practical Zero Trust implementation for IT/OT convergence, 24/7 SOC design

## Red Team Operators

### Industrial Red Teams (General)
- **Focus:** Physical process disruption, PLC manipulation, safety system compromise
- **Key Attack Paths:**
  1. PLC firmware backdooring
  2. Engineering software compromise (TIA Portal, RSLogix)
  3. Safety controller DoS
  4. HMI compromise for operator workstation pivot
  5. Modbus/TCP write attacks on physical processes

## Expert Methodology Synthesis

### Protocol-Level Exploitation (Brubaker, Levy)
1. Understand exact byte structure of industrial protocols
2. Identify authentication handshake weaknesses
3. Craft packets that bypass session validation
4. Exploit cryptographic key handling flaws

### Hardware-In-The-Loop Testing (Akpinar, Johannes)
1. Build realistic ICS test environment
2. Include physical process simulation
3. Measure Attack Success Rate (ASR) and Mean Time to Recovery (MTTR)
4. Validate defenses with quantitative metrics

### Stealthy Exploitation (Chrabrow)
1. Minimize network traffic footprint
2. Use low-and-slow attack patterns
3. Avoid triggering anomaly detection
4. Target PLCs with weak integrity checks

### Detection Evasion (Kleinmann)
1. Understand normal traffic patterns (DFA modeling)
2. Craft attacks that mimic normal behavior
3. Exploit periodic nature of industrial protocols
4. Avoid command sequence anomalies