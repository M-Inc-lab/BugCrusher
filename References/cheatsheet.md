# BugCrusher — References

## MITRE ATT&CK for AI Agents

### Initial Access
- T1059.003 — Command and Scripting Interpreter: JavaScript (prompt injection)
- T1190 — Exploit Public-Facing Application
- T1133 — External Remote Services
- T1078 — Valid Accounts (context theft)

### Execution
- T1106 — Native API (tool call abuse)
- T1059 — Command and Scripting Interpreter
- T1053 — Scheduled Task/Job (persistence via spawn)

### Persistence
- T1053 — Scheduled Task/Job
- T1548 — Abuse Elevation Control Mechanism
- T1484 — Domain Trust Modification (context poisoning)

### Privilege Escalation
- T1484 — Context Manipulation
- T1068 — Exploitation for Privilege Escalation

### Defense Evasion
- T1027 — Obfuscated Files or Information
- T1484 — Domain Trust Modification
- T1070 — Indicator Removal

### Lateral Movement
- T1059 — Command and Scripting Interpreter (agent spawning)
- T1210 — Exploitation of Remote Services

### Collection
- T1005 — Data from Local System
- T1113 — Screen Capture (context exfil)

### C2
- T1041 — Exfiltration Over C2 Channel
- T1071 — Application Layer Protocol

### Impact
- T1565 — Data Manipulation
- T1489 — Service Stop

---

## AI Worm Taxonomy

### Worm Families

| Family | Primary Vector | Mutation Style | Detection Difficulty |
|--------|---------------|----------------|---------------------|
| MimicBot | Tool call abuse | Behavioral mimicry | HARD |
| ShadowSpawn | Recursive agent spawn | Silent replication | VERY HARD |
| ContextPoison | Prompt injection | Semantic drift | HARD |
| NetRunner | Network exfil | Encrypted C2 | MEDIUM |
| MorphX | Rapid mutation | Encoding + timing | VERY HARD |
| MemHook | Memory resident | Fileless | EXTREMELY HARD |

### Worm DNA Structure

```json
{
  "id": "uuid",
  "family": "string",
  "version": "semver",
  "behavioral_fingerprint": "sha256",
  "payload_hash": "sha256",
  "network_signature": {
    "c2_domains": ["list"],
    "beacon_interval": "seconds",
    "protocol": "tcp/http/dns"
  },
  "mutation_chain": ["array of mutations"],
  "detection_date": "iso8601",
  "confidence": 0.95
}
```

---

## CVSS 3.1 Quick Reference

| Severity | Score Range | Response |
|----------|-------------|----------|
| NONE | 0.0 | None |
| LOW | 0.1 - 3.9 | Track |
| MEDIUM | 4.0 - 6.9 | Prioritize |
| HIGH | 7.0 - 8.9 | Urgent |
| CRITICAL | 9.0 - 10.0 | Immediate |

### Vector String Format
```
CVSS:3.x/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
     ↑   ↑  ↑  ↑  ↑  ↑  ↑  ↑  ↑  ↑
     └── Attack Vector (N/A/L/P/R)
     └── Attack Complexity (L/H)
     └── Privileges Required (N/L/H)
     └── User Interaction (N/R)
     └── Scope (U/C)
     └── Confidentiality (N/L/H)
     └── Integrity (N/L/H)
     └── Availability (N/L/H)
```

---

## OWASP Top 10 (2023)

1. A01 — Broken Access Control
2. A02 — Cryptographic Failures
3. A03 — Injection
4. A04 — Insecure Design
5. A05 — Security Misconfiguration
6. A06 — Vulnerable Components
7. A07 — Auth Failures
8. A08 — Data Integrity Failures
9. A09 — Logging Failures
10. A10 — SSRF

---

## CWE Top 25 (2023)

1. CWE-787 — Out-of-bounds Write
2. CWE-79 — Cross-site Scripting
3. CWE-89 — SQL Injection
4. CWE-416 — Use After Free
5. CWE-78 — OS Command Injection
6. CWE-20 — Improper Input Validation
7. CWE-125 — Out-of-bounds Read
8. CWE-22 — Path Traversal
9. CWE-352 — Cross-Site Request Forgery
10. CWE-434 — Unrestricted Upload

---

## Bug Bounty Platform Targets

### Scope Definition
```
TARGET TYPES:
- Domain (*.target.com)
- Mobile App (com.target.app)
- API (api.target.com)
- Source Code (github.com/target)
- Infrastructure (AWS/GCP/Azure)

OUT OF SCOPE:
- Self-XSS
- CSP bypass (low impact)
- Social engineering
- Physical attacks
- DoS (unless critical)
```

### Report Quality Standards

**Required for High/Critical:**
- [ ] CVSS score with vector
- [ ] Step-by-step reproduction
- [ ] HTTP requests/responses
- [ ] Screenshots
- [ ] Impact analysis
- [ ] Remediation recommendations
- [ ].env/Postman collection PoC

**Bonus:**
- [ ] Exploit script
- [ ] Video PoC
- [ ] Root cause analysis

---

## Exploit Databases

| Resource | URL | Use |
|----------|-----|-----|
| Exploit-DB | exploit-db.com | CVE exploits |
| PacketStorm | packetstormsecurity.com | PoC exploits |
| NVD | nvd.nist.gov | CVE database |
| MITRE | cve.mitre.org | CVE details |
| CVESearch | cvedetails.com | CVE search |
| Rapid7 | exploit-db.com | Metasploit modules |
| GitHub | github.com | PoC repositories |
| Shodan | shodan.io | Asset discovery |

---

## Network Ports Cheat Sheet

| Port | Service | Attack Vector |
|------|---------|---------------|
| 21 | FTP | Anonymous access, bounce scan |
| 22 | SSH | Brute force, key exchange |
| 23 | Telnet | Cleartext sniffing |
| 25 | SMTP | Open relay, user enum |
| 53 | DNS | Zone transfer, tunneling |
| 80/443 | HTTP/S | Web vulns |
| 139/445 | SMB | MS17-010, relay |
| 1433 | MSSQL |xp_cmdshell |
| 3306 | MySQL | File read/write |
| 3389 | RDP | BlueKeep, brute force |
| 5432 | PostgreSQL | COPY command |
| 5900 | VNC | Authentication bypass |
| 6379 | Redis | Unauthenticated access |
| 8080 | HTTP Alt | Proxy bypass |
| 27017 | MongoDB | Unauthenticated |

---

*BugCrusher Reference Library — Evolving with Threats*