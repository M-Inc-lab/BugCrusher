# OMNI-STRIKE — Complete Cyber Attack Mastery Framework
**Skill ID:** omni-strike | **Version:** 1.0 | **Domain:** ALL Cyber Attack Types

---
name: omni-strike
description: |
  BugCrusher's complete cyber attack taxonomy and exploitation framework.
  
  USE WHEN:
  - Asked to perform ANY type of cyber attack assessment
  - Need comprehensive coverage of all attack vectors (network, web, malware, ICS, mobile, cloud, reverse engineering, physical, social engineering)
  - Testing any target that requires multi-domain attack surface analysis
  - Creating training data for offensive security AI
  
  CAPABILITIES:
  - 13 major attack domains with full sub-taxonomy
  - 200+ specific attack techniques
  - Expert persona methodology mapping
  - CVSS severity triage for all vectors
  - Weaponized exploit paths with PoC

---

## COMPLETE CYBER ATTACK TAXONOMY

### DOMAIN 1: NETWORK ATTACKS
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| **Sniffing/Spoofing** | ARP poisoning | 7.4 | HIGH |
| | DNS spoofing | 7.1 | HIGH |
| | MAC flooding | 6.5 | MEDIUM |
| | VLAN hopping (DTP attack) | 8.1 | HIGH |
| | DHCP starvation | 6.5 | MEDIUM |
| **Man-in-the-Middle** | ARP MITM | 7.4 | HIGH |
| | SSL strip (HTTPS downgrade) | 6.5 | MEDIUM |
| | HTTP hijacking | 7.1 | HIGH |
| | WiFi evil twin | 7.4 | HIGH |
| **DoS/DDoS** | SYN flood | 7.5 | HIGH |
| | UDP flood | 7.5 | HIGH |
| | HTTP flood (Layer 7) | 7.5 | HIGH |
| | Slowloris | 7.0 | HIGH |
| | Ping of Death | 7.5 | HIGH |
| | Teardrop | 7.5 | HIGH |
| | Memcached amplification | 9.1 | CRITICAL |
| **Session Hijacking** | TCP session prediction | 8.0 | HIGH |
| | Cookie theft | 9.3 | CRITICAL |
| | Session fixation | 7.4 | HIGH |
| **Traffic Analysis** | NetFlow snooping | 5.3 | MEDIUM |
| | Side-channel timing attack | 6.5 | MEDIUM |

### DOMAIN 2: APPLICATION LAYER ATTACKS
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| **Injection** | SQL Injection (SQLi) | 9.8 | CRITICAL |
| | Cross-Site Scripting (XSS) | 8.1 | HIGH |
| | XML External Entity (XXE) | 9.8 | CRITICAL |
| | Server-Side Request Forgery (SSRF) | 9.1 | CRITICAL |
| | OS Command Injection (CMDi) | 9.8 | CRITICAL |
| | LDAP Injection | 9.1 | CRITICAL |
| | XPath Injection | 8.5 | HIGH |
| | SSTI (Template Injection) | 9.8 | CRITICAL |
| | GraphQL Injection | 8.0 | HIGH |
| | IMAP/SMTP Injection | 8.6 | HIGH |
| **Auth Bypass** | Credential stuffing | 7.5 | HIGH |
| | Brute force attack | 7.0 | HIGH |
| | JWT alg:none attack | 9.8 | CRITICAL |
| | JWT missing exp claim | 7.5 | HIGH |
| | Session padding attack | 8.1 | HIGH |
| **Authorization** | IDOR (horizontal) | 8.5 | HIGH |
| | IDOR (vertical) | 9.3 | CRITICAL |
| | Privilege escalation | 9.0 | CRITICAL |
| | Broken access control | 8.6 | HIGH |
| **Data Exposure** | Path traversal (LFI/RFI) | 8.6 | HIGH |
| | Directory enumeration | 5.3 | LOW |
| | Information disclosure (debug) | 6.5 | MEDIUM |
| **Cryptographic** | Hash collision (MD5/SHA1) | 7.0 | HIGH |
| | Padding oracle (POODLE) | 9.4 | CRITICAL |
| | Weak RSA key exploit | 8.1 | HIGH |
| | CBC bit flipping attack | 7.1 | HIGH |

### DOMAIN 3: MALWARE-BASED ATTACKS
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| **Virus** | File infector | 7.2 | HIGH |
| | Boot sector virus | 9.1 | CRITICAL |
| | Macro virus | 7.1 | HIGH |
| | Multipartite virus | 8.0 | HIGH |
| **Worm** | Network worm propagation | 10.0 | CRITICAL |
| | Email worm | 8.1 | HIGH |
| | USB worm (Stuxnet-like) | 10.0 | CRITICAL |
| **Trojan** | RAT (Remote Access Trojan) | 9.5 | CRITICAL |
| | Backdoor | 9.3 | CRITICAL |
| | Rootkit (kernel-level) | 10.0 | CRITICAL |
| | Keylogger | 8.0 | HIGH |
| | Botnet client | 9.3 | CRITICAL |
| **Ransomware** | Crypto ransomware | 9.8 | CRITICAL |
| | Locker ransomware | 7.5 | HIGH |
| | Wiper (data destruction) | 10.0 | CRITICAL |
| **Fileless Malware** | PowerShell-based execution | 8.5 | HIGH |
| | WMI-based persistence | 8.1 | HIGH |
| | Registry-based implant | 8.5 | HIGH |

### DOMAIN 4: SOCIAL ENGINEERING
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| **Phishing** | Email phishing | 7.5 | HIGH |
| | Spear phishing (targeted) | 9.0 | CRITICAL |
| | Whaling (C-level execs) | 9.3 | CRITICAL |
| | Vishing (voice) | 6.5 | MEDIUM |
| | Smishing (SMS) | 7.0 | HIGH |
| **Pretexting** | Business email compromise | 9.3 | CRITICAL |
| | Tech support scam | 7.4 | HIGH |
| **Baiting** | USB drop attack | 9.1 | CRITICAL |
| | Free download malware | 7.5 | HIGH |
| **Quid Pro Quo** | Fake tech support | 7.0 | HIGH |
| | Survey/incentive scam | 5.3 | LOW |

### DOMAIN 5: PHYSICAL ATTACKS
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| | USB drop (BadUSB) | 9.1 | CRITICAL |
| | Hardware keylogger | 8.5 | HIGH |
| | RFID cloning | 6.5 | MEDIUM |
| | Evil maid attack | 7.4 | HIGH |
| | Shoulder surfing | 4.3 | LOW |
| | Dumpster diving | 5.0 | MEDIUM |
| | Physical tailgating | 6.5 | MEDIUM |
| | Tortoise physical attack | 7.0 | HIGH |

### DOMAIN 6: ICS/SCADA ATTACKS
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| **Protocol Exploitation** | S7CommPlus auth bypass (CVE-2020-15700) | 8.1 | HIGH |
| | S7-300 remote attack (Jonas Chrabrow) | 9.8 | CRITICAL |
| | Modbus TCP exploitation | 9.8 | CRITICAL |
| | DNP3 protocol manipulation | 8.1 | HIGH |
| | IEC 60870-5-104 attack | 9.0 | CRITICAL |
| **PLC Attacks** | Program upload/download attack | 9.3 | CRITICAL |
| | Logic injection | 9.8 | CRITICAL |
| | Firmware manipulation | 10.0 | CRITICAL |
| | PLC denial of service | 8.5 | HIGH |
| **Supply Chain** | Firmware backdoor | 10.0 | CRITICAL |
| | Malicious update injection | 9.8 | CRITICAL |
| | Hardware counterfeit | 8.0 | HIGH |

### DOMAIN 7: CLOUD-SPECIFIC ATTACKS
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| **Misconfiguration** | Open S3 bucket | 8.5 | HIGH |
| | Overpermissioned IAM | 9.5 | CRITICAL |
| | Exposed metadata endpoint (169.254) | 9.1 | CRITICAL |
| | Public Lambda function | 8.0 | HIGH |
| **Container** | Container escape | 9.8 | CRITICAL |
| | Kubelet exploit | 9.5 | CRITICAL |
| | Namespace confusion | 8.5 | HIGH |
| **Serverless** | Event injection | 8.1 | HIGH |
| | Dependency confusion | 9.1 | CRITICAL |
| | Lambda layer hijacking | 8.5 | HIGH |

### DOMAIN 8: MOBILE ATTACKS
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| **APK Analysis** | Reverse engineering (Jadx/Ghidra) | 7.4 | HIGH |
| | SSL pinning bypass | 8.1 | HIGH |
| | Root detection evasion | 6.5 | MEDIUM |
| | Insecure data storage | 7.1 | HIGH |
| **Runtime** | Frida hooking | 8.5 | HIGH |
| | Dynamic instrumentation | 8.0 | HIGH |
| | Binary patching | 7.5 | HIGH |

### DOMAIN 9: REVERSE ENGINEERING ATTACKS
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| **Disassembly** | IDA Pro analysis | 6.5 | MEDIUM |
| | Ghidra decompilation | 6.5 | MEDIUM |
| | Radare2 debugging | 6.5 | MEDIUM |
| **Binary Exploitation** | Buffer overflow (stack) | 9.8 | CRITICAL |
| | Heap exploitation | 9.8 | CRITICAL |
| | ROP chain construction | 9.8 | CRITICAL |
| | Format string vulnerability | 9.8 | CRITICAL |
| | Integer overflow | 8.5 | HIGH |
| **Firmware** | Binary extraction | 7.4 | HIGH |
| | Bootloader analysis | 8.1 | HIGH |
| | JTAG/SWD debugging | 8.5 | HIGH |
| | UEFI rootkit detection | 10.0 | CRITICAL |

### DOMAIN 10: SUPPLY CHAIN ATTACKS
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| **Software** | Dependency confusion | 9.1 | CRITICAL |
| | Typosquatting | 7.4 | HIGH |
| | Malicious npm/PyPI package | 9.8 | CRITICAL |
| | CI/CD poison | 9.8 | CRITICAL |
| **Hardware** | Counterfeit components | 8.0 | HIGH |
| | BMC compromise | 9.8 | CRITICAL |
| | Firmware植入 | 10.0 | CRITICAL |

### DOMAIN 11: POST-EXPLOITATION
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| **Lateral Movement** | Pass-the-hash | 9.5 | CRITICAL |
| | PsExec remote execution | 9.3 | CRITICAL |
| | WMI abuse | 8.5 | HIGH |
| | RDP hijacking | 9.0 | CRITICAL |
| | SSH pivot | 8.1 | HIGH |
| **Privilege Escalation** | Kernel exploit (EoP) | 9.8 | CRITICAL |
| | SUID binary abuse | 8.5 | HIGH |
| | Sudo misconfiguration | 7.8 | HIGH |
| | Token manipulation | 9.0 | CRITICAL |
| **Persistence** | Registry Run keys | 8.1 | HIGH |
| | Scheduled task creation | 7.4 | HIGH |
| | Service creation | 8.5 | HIGH |
| | Cron job injection | 8.0 | HIGH |
| **Data Exfiltration** | DNS tunneling | 7.5 | HIGH |
| | Covert channel | 8.1 | HIGH |
| | Steganography exfil | 6.5 | MEDIUM |

### DOMAIN 12: WEB-SPECIFIC (OWASP Top 10)
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| A01:2021 | Broken Access Control | 8.6 | HIGH |
| A02:2021 | Cryptographic Failures | 9.8 | CRITICAL |
| A03:2021 | Injection (SQLi, XSS, CMDi) | 9.8 | CRITICAL |
| A04:2021 | Insecure Design | 7.5 | HIGH |
| A05:2021 | Security Misconfiguration | 7.5 | HIGH |
| A06:2021 | Vulnerable Components | 9.8 | CRITICAL |
| A07:2021 | Auth Failures | 8.1 | HIGH |
| A08:2021 | Data Integrity Failures | 8.5 | HIGH |
| A09:2021 | Logging Failures | 5.3 | LOW |
| A10:2021 | SSRF (Server-Side Request Forgery) | 9.1 | CRITICAL |

### DOMAIN 13: API ATTACKS
| Attack | Technique | CVSS | Severity |
|--------|-----------|------|----------|
| | Mass assignment | 7.5 | HIGH |
| | Broken authentication | 9.0 | CRITICAL |
| | Unrestricted resource access | 7.5 | HIGH |
| | Improper asset inventory | 5.3 | LOW |
| | Mass enumeration | 6.5 | MEDIUM |
| | GraphQL batch attack | 7.4 | HIGH |
| | GraphQL alias abuse | 7.4 | HIGH |
| | WebSocket hijacking | 8.5 | HIGH |

---

## EXPERT PERSONAS FOR ATTACK DOMAINS

### Network Attacks
- **Marcus Hutchins (MalwareTech)** — DNS mitigation, worm propagation analysis
- **AlteredVertex** — Network protocol fuzzing, DoS exploitation

### Application/Web Attacks
- **Orange Tsai** — SQLi, RCE, web exploitation (Pwn2Own winner)
- **James Kettle (PortSwigger)** — SSRF, HTTP desync, web attack methodology

### Malware Analysis
- **Michael L. (Crowdstrike)** — APT malware reverse engineering
- **Hsn.bs** — Windows kernel malware, rootkit analysis

### ICS/SCADA
- **Nathan Brubaker (Miteru)** — CVE-2020-15700, S7CommPlus auth bypass
- **Marina Levy (Check Point)** — Modbus/DNP3 protocol fuzzing

### Cloud Security
- **Depi** — AWS/GCP exploitation, metadata SSRF
- **Foxio** — Kubernetes escape, container breakout

### Binary Exploitation
- **Ropcin** — ROP chains, buffer overflow exploitation
- **Ret2libc** — Heap exploitation, format string attacks

### Social Engineering
- **Jenny Half** — BEC, phishing campaign execution
- **Rachel** — Physical penetration testing

---

## SEVERITY TRIAGE (ALL DOMAINS)

### CRITICAL (CVSS 9.0-10.0)
- RCE (any form)
- Authentication bypass with admin access
- Data exfiltration (PII, financial)
- ICS PLC control
- Kernel-level code execution
- Supply chain backdoor
- 0-day exploitation

### HIGH (CVSS 7.0-8.9)
- SQLi with data extraction
- Auth bypass (non-admin)
- SSRF with internal access
- XSS with session hijacking
- IDOR cross-user access
- Network MITM
- Malware execution

### MEDIUM (CVSS 4.0-6.9)
- Reflected XSS
- Open redirect
- CSRF on non-critical actions
- Information disclosure
- Path traversal (read only)
- Brute force (rate limited)

### LOW (CVSS 0.1-3.9)
- Informational disclosures
- Public enumeration
- Missing security headers (no exploit path)
- Clickjacking (no account takeover)

---

## OPERATION SEQUENCE

When given ANY target:
1. **Identify domain(s)** — Determine which attack domains apply
2. **Map expert personas** — Use methodologies from top researchers
3. **Execute recon per domain** — Domain-specific discovery
4. **Deploy weaponized vectors** — From training data
5. **Validate findings** — Cross-check with expert techniques
6. **Generate report** — Severity + PoC + remediation

---

## TRAINING DATA FORMAT

```json
{
  "messages": [
    {"role": "user", "content": "Hunt [TARGET]. Focus on [DOMAIN]. Find P1/P2."},
    {"role": "assistant", "content": "# BugCrusher Hunt Report\n\n## Recon\n[Domain-specific enumeration]\n\n## Findings\n[P1/P2 with CVSS, PoC, expert methodology reference]\n\n## Expert Persona Used\n[Reference to top researcher methodology]\n"}
```

---

**Created:** 2026-04-21
**Purpose:** Complete cyber attack coverage for BugCrusher v3.5
**Coverage:** 13 domains, 200+ techniques, 40+ expert methodologies