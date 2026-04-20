---
name: persistence-frameworks
description: |
  Local privilege escalation pathways, token manipulation, in-memory shellcode
  execution, and C2 profile generation. Maps from RCE to full system dominance.
  
  Use when: You have RCE/shell access and need to escalate privileges or establish
  persistent access on Windows/Linux/AD targets.
---

## USAGE

```bash
# Check available techniques
cat /home/workspace/BugCrusher/Skills/persistence-frameworks/references/Windows_LPE.md
cat /home/workspace/BugCrusher/Skills/persistence-frameworks/references/Linux_LPE.md
cat /home/workspace/BugCrusher/Skills/persistence-frameworks/references/C2_Profiles.md

# Run enumeration
python3 /home/workspace/BugCrusher/Skills/persistence-frameworks/scripts/privesc_check.py --target <host> --type windows|linux|ad
```

## PRIVILEGE ESCALATION MATRIX

### Windows

| Vector | OS Version | CVSS | Fitness |
|--------|-------------|------|---------|
| SeImpersonatePrivilege (JuicyPotato) | Win 7-10, Server 2012-2019 | 8.8 | 0.92 |
| SeDebugPrivilege + LSASS dump | Win 10, Server 2016+ | 8.2 | 0.88 |
| AlwaysInstallElevated | Win 7-10 (misconfig) | 7.8 | 0.75 |
| Token Manipulation (incognito) | All versions | 9.0 | 0.95 |
| UAC Bypass ( fodhelper.exe ) | Win 10 1803+ | 7.6 | 0.80 |
| DLL Hijacking (PATH abuse) | All versions | 7.4 | 0.72 |
| Kernel Exploit (CVE-2024-XXXX) | Win 11, Server 2022 | 9.8 | 0.98 |

### Linux

| Vector | Distribution | CVSS | Fitness |
|--------|-------------|------|---------|
| SUID binary abuse | Ubuntu, Debian, CentOS | 8.1 | 0.85 |
| Sudo policy bypass (sudo <1.8.28) | All versions | 7.8 | 0.80 |
| Polkit pkexec (CVE-2021-4034) | Ubuntu, Debian | 9.8 | 0.97 |
| kernel Exploit (CVE-2022-0847) | Linux 5.8+ | 9.8 | 0.96 |
| Docker.sock exposure | Dockerized envs | 8.6 | 0.90 |
| crontab abuse | All versions | 6.5 | 0.65 |

### Active Directory

| Vector | Requirement | CVSS | Fitness |
|--------|-------------|------|---------|
| Kerberoasting (ASREPRoast) | User SPN set | 8.6 | 0.88 |
| DCSync (DS-Replication-Extended) | Domain Admin equivalent | 10.0 | 1.00 |
| Pass-the-Hash (Sekurlsa) | Credential dump | 9.0 | 0.95 |
| Pass-the-Ticket (Kirbi) | Ticket grant ticket | 8.8 | 0.92 |
| Golden Ticket (krbtgt NTLM) | Domain hash | 10.0 | 1.00 |
| Silver Ticket (service NTLM) | Service account hash | 8.6 | 0.88 |
| ACL Abuse (WriteDACL) | Specific ACE misconfig | 9.3 | 0.95 |
| RBCD (Resource-Based Constrained Delegation) | AD CS + write access | 9.0 | 0.92 |
| Unconstrained Delegation | Computer object + printer spool | 9.2 | 0.94 |

## C2 PROFILE GENERATOR

Generates C2 profiles compatible with:

```
- Cobalt Strike (Malleable C2)
- Metasploit (payload stageless)
- Sliver (Malleable profiles)
- Covenant (Grunt profiles)
- Brute Ratel (Malleable profiles)
- Heeeelion (custom profiles)
```

Usage:
```bash
python3 /home/workspace/BugCrusher/Skills/persistence-frameworks/scripts/c2_profile_gen.py --type cobalt --domain <domain> --c2 <c2_url> --profile high-performance|low-profile|apartment
```

## EXECUTION CHECKLIST

```
[ ] Systeminfo/enum → identify OS/build
[ ] Whoami / privs → check SeImpersonatePrivilege
[ ] Check AlwaysInstallElevated registry keys
[ ] SeDebugPrivilege → LSASS access attempt
[ ] Token enumeration (whoami /all)
[ ] Service enumeration (sc query / powershell Get-Service)
[ ] Scheduled tasks (schtasks /query)
[ ] PATH misconfig enumeration
[ ] Kernel exploit search (searchsploit / exploitdb)
[ ] AD: Kerberoast any user with SPN
[ ] AD: Check for Unconstrained Delegation
[ ] AD: Check Constrained Delegation (S4U2Self)
[ ] AD: ACL enumeration (DS-Replication-Extended)
```