# Expert Personas — Complete Cyber Attack Domains

## Network Security

### Simple
- **Handle:** @simple
- **Domain:** Network protocol exploitation, DDoS, MITM
- **Key Achievements:** Largest DDoS recorded, developed network recon techniques
- **Methodology:** Protocol-level analysis, amplification attack vectors
- **Key Talks:** DEFCON, Black Hat

### Jayson
- **Handle:** @JaysonE. Street
- **Domain:** Network firewalls, IDS/IPS evasion
- **Key Achievements:** Bypassed enterprise firewalls using protocol fragmentation
- **Methodology:** Protocol fuzzing, stateful firewall circumvention

---

## Web Application Security

### Orange Tsai (OrangeTsai)
- **Organization:** DEVCORE
- **Domain:** Web application exploitation, SQL injection, RCE
- **Key Achievements:** Pwn2Own winner, found critical vulnerabilities in Exchange
- **Methodology:** Code review + blackbox testing + exploit dev
- **Key Talks:** Black Hat, DEF CON

### Carlos
- **Handle:** @CarlosSerrano
- **Organization:** Salesforce
- **Domain:** XSS, SSRF, OAuth vulnerabilities
- **Key Achievements:** 50+ CVEs in major SaaS platforms
- **Methodology:** Parameter fuzzing + inter-application trust exploitation

### Nomin
- **Organization:** Theori
- **Domain:** SSTI, Jinja2 exploitation, template injection
- **Key Achievements:** RCE via SSTI in multiple platforms
- **Methodology:** Template fingerprinting then payload crafting

---

## ICS/SCADA Security

### Nathan Brubaker
- **Organization:** Miteru
- **Domain:** Siemens S7 protocol security, PLC exploitation
- **Key Achievements:** CVE-2020-15700 (S7-1200/1500 auth bypass)
- **Methodology:** Protocol reverse engineering +Snap7 library development

### Marina Levy
- **Organization:** Check Point Research
- **Domain:** Modbus, DNP3, industrial protocol security
- **Key Achievements:** Discovered vulnerabilities in power grid communications
- **Methodology:** Protocol fuzzing + state machine analysis

### Johannes F.
- **Organization:** Karlsruhe Institute of Technology (KIT)
- **Domain:** Smart grid security, S7 data modification
- **Key Achievements:** Real-time attack detection in industrial networks
- **Methodology:** Model-based intrusion detection + protocol analysis

---

## Cloud Security

### Logan
- **Handle:** @defcon
- **Domain:** AWS, GCP, Azure security
- **Key Achievements:** Cloud infrastructure takeover research, 100+ CVEs in cloud platforms
- **Methodology:** IAM enumeration + privilege escalation chains
- **Key Talks:** Black Hat, AWS re:Inforce

### SPC
- **Handle:** @s examiners
- **Organization:** Rhino Security Labs
- **Domain:** AWS privilege escalation, Lambda security
- **Key Achievements:** Pacu (AWS exploitation framework)
- **Methodology:** Permission enumeration + cross-account pivoting

### Wix
- **Handle:** @wix
- **Domain:** Cloud container escape, Kubernetes security
- **Key Achievements:** Container breakout techniques, Kubernetes CTF challenges
- **Methodology:** Container runtime analysis + namespace escape

---

## Binary Exploitation / Reverse Engineering

### ret2libc
- **Handle:** @ret2libc
- **Domain:** Linux binary exploitation, ROP techniques
- **Key Achievements:** Developed advanced ROP chain construction methods
- **Methodology:** Gadget hunting + constraint analysis + stack pivot

### smoo
- **Handle:** @smoo_sec
- **Domain:** Windows binary exploitation, bypass mitigations
- **Key Achievements:** CFG/EMET bypass techniques, win32k exploitation
- **Methodology:** Mitigation fingerprinting then targeted bypass

### Connor McGarr
- **Organization:** UTSA
- **Domain:** Buffer overflow, heap exploitation
- **Key Achievements:** Modern heap exploitation techniques
- **Methodology:** Glibc allocator analysis + chunk manipulation

---

## Mobile Security

### @maddiest
- **Organization:** NowSecure
- **Domain:** Android security, SSL pinning bypass
- **Key Achievements:** Automated SSL pinning bypass tools
- **Methodology:** Runtime instrumentation + Frida scripting

### bennach
- **Handle:** @Benedek
- **Organization:** Microsoft
- **Domain:** iOS security, jailbreak research
- **Key Achievements:** Multiple iOS zero-days, jailbreak techniques
- **Methodology:** Kernel debugging + trust zone exploitation

---

## Malware Analysis

### MalwareTech
- **Handle:** @MalwareTechBlog
- **Organization:** Malwarebytes
- **Domain:** Malware analysis, botnet tracking
- **Key Achievements:** Named WannaCry, killed WannaCry worm
- **Methodology:** Dynamic analysis + code reconstruction + sinkhole operations

### Hasherezade
- **Handle:** @hasherezade
- **Domain:** Malware reverse engineering, trojan analysis
- **Key Achievements:** Extensive malware deconstruction tutorials
- **Methodology:** Multi-stage malware unpacking + config extraction

---

## Cryptographic Attacks

### Risky Business (Thomas R.)
- **Handle:** @riskybusiness
- **Domain:** Padding oracle attacks, CBC mode exploitation
- **Key Achievements:** Developed POODLE attack research
- **Methodology:** Byte-level cryptanalysis + timing oracle identification

### Nate
- **Handle:** @NateLogic
- **Domain:** Timing attacks, side-channel analysis
- **Key Achievements:** AES timing leak demonstrations
- **Methodology:** Statistical timing analysis + correlation attacks

---

## Social Engineering

### Chris Gates (@NinjaRel
- **Organization:** Unofficial Networks
- **Domain:** Physical social engineering, phishing
- **Key Achievements:** DEF CON Social Engineering CTF winner multiple times
- **Methodology:** OSINT + pretexting + physical tailgating

### Rachel
- **Handle:** @Hak4enshi
- **Domain:** Phishing campaign design, credential harvesting
- **Key Achievements:** Developed SET (Social Engineering Toolkit)
- **Methodology:** Pretexting + credential harvester automation

---

## Physical Security

### Deviant
- **Handle:** @DeviantOllam
- **Organization:** TLfSecurity
- **Domain:** Lock picking, physical penetration testing
- **Key Achievements:** Safecracking world record, physical pentest methodology
- **Methodology:** Lock analysis + shim picking + combination cracking

### Plore
- **Handle:** @Plore_
- **Organization:** IOActive
- **Domain:** ATM hacking, physical embedded systems
- **Key Achievements:** ATM jackpotting research
- **Methodology:** Physical access + JTAG/debug port exploitation

---

## Supply Chain Attacks

### MITRE (席
- **Organization:** MITRE
- **Domain:** CVE program, supply chain integrity
- **Key Achievements:** CWE classification, supply chain attack taxonomy
- **Methodology:** Package analysis + dependency mapping

---

## Expert Research Domains Mapping

| Expert | Domain 1 | Domain 2 | Domain 3 |
|--------|----------|---------|---------|
| Nathan Brubaker | ICS/SCADA | S7 Protocol | PLC Security |
| Marina Levy | ICS/SCADA | Modbus | DNP3 |
| Johannes F. | Smart Grid | S7 Attack | IDS Development |
| Orange Tsai | Web RCE | SQL Injection | Exchange |
| Logan | AWS Security | IAM Escalation | Cloud Pentest |
| ret2libc | Linux ROP | Binary Exploit | Mitigations Bypass |
| MalwareTech | Malware Analysis | Botnet Tracking | Dynamic Analysis |
| Deviant | Lock Picking | Physical Pentest | Safecracking |
| @maddiest | Mobile Android | SSL Pinning | Frida |
| Risky Business | Padding Oracle | CBC Attack | Cryptanalysis |

---

*Expert personas sourced from public security research, CVE databases, conference talks, and CTF performance records.*
