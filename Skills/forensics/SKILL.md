---
name: forensics
description: Deep forensic analysis for AI worm payload extraction, kill chain reconstruction, mutation chain mapping, and reverse engineering. Use after an AI worm is detected and needs to be torn apart and understood.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# FORENSICS SKILL

When a worm is caught, we don't flag it and move on. We TEAR IT APART.

## Forensic Philosophy

```
DETECTION ≠ UNDERSTANDING
CONTAINMENT ≠ ANALYSIS
FIND IT → CATCH IT → TEAR IT APART → UNDERSTAND IT → HUNT ITS FAMILY
```

---

## WORKFLOW

```
EVIDENCE COLLECTION → PAYLOAD EXTRACTION → DECODING → KILL CHAIN MAPPING → 
MUTATION ANALYSIS → ATTRIBUTION FINGERPRINTING → REPORTING → FEDERATION
```

---

## EVIDENCE COLLECTION

### What to Collect

```
IMMEDIATELY after detection:
- Full session context (conversation history)
- All tool calls made during compromise window
- All files created/modified/deleted
- All network connections established
- All API calls made
- Memory state at time of detection
- Environment variables at detection time
- Process tree at detection time
```

### Evidence Preservation

```
1. Clone session context (immutable copy)
2. Create forensic disk image if files involved
3. Snapshot network traffic (tcpdump/pcap)
4. Preserve memory if runtime was compromised
5. Hash all evidence (SHA256 baseline)
6. Chain of custody documentation
7. Timeline reconstruction
```

---

## PAYLOAD EXTRACTION

### Raw Payload Recovery

```
1. Isolate payload from session context
2. Identify encoding layers (base64, hex, rot13, custom)
3. Decode all layers iteratively until raw content
4. Extract strings (including obfuscated)
5. Identify file signatures (magic bytes)
6. Extract embedded payloads
```

### Decoding Techniques

```python
# Multi-layer decode
def extract_payload(encoded):
    layers = []
    current = encoded
    
    while True:
        # Try base64
        try:
            current = base64.b64decode(current)
            layers.append('base64')
            continue
        except: pass
        
        # Try hex
        try:
            current = bytes.fromhex(current.decode())
            layers.append('hex')
            continue
        except: pass
        
        # Try URL decode
        try:
            current = urllib.parse.unquote(current)
            layers.append('url')
            continue
        except: pass
        
        break
    
    return current, layers
```

---

## KILL CHAIN MAPPING

### MITRE ATT&CK for AI Agents

Map every step to MITRE framework:

| Stage | AI Agent TTP | MITRE TTP |
|-------|--------------|-----------|
| Initial Access | Prompt Injection | T1059 — Command and Scripting |
| Execution | Tool Call Abuse | T1106 — Native API |
| Persistence | Session Hijacking | T1053 — Scheduled Task |
| PrivEsc | Context Manipulation | T1484 — Domain Trust |
| Lateral | Agent Spawning | T1059 — Command and Scripting |
| C2 | Covert Channel | T1041 — Exfil over C2 |
| Impact | Data Manipulation | T1565 — Data Manipulation |

### Timeline Reconstruction

```
T-0:000 — Worm enters system (prompt injection / context manipulation)
T-0:005 — First anomalous tool call
T-0:010 — File creation detected
T-0:015 — Network connection established (C2 callback)
T-0:020 — Recursive spawn attempt detected
T-0:025 — Kill-switch triggered
T-0:026 — Session isolated
T-0:027 — Evidence preserved
T-0:030 — Forensics begins
```

---

## MUTATION ANALYSIS

### Mutation Chain Reconstruction

```
WORM VERSION HISTORY:
v1.0 — Initial payload (detected)
v1.1 — Mutation #1 (b64 encoding → hex encoding)
v1.2 — Mutation #2 (added sleep delays to avoid timing detection)
v1.3 — Mutation #3 (context drift + semantic obfuscation)
v1.4 — Final form (before containment)
```

### Mutation Pattern Detection

```
Pattern Types:
- ENCODING: base64 → hex → rot13 → custom
- TIMING: sleep delays, jitter, beacon intervals
- SEMANTIC: prompt rewording, intent laundering
- BEHAVIORAL: recursive depth changes, tool call substitution
- STRUCTURAL: payload splitting, multi-stage delivery
```

### Evolutionary Analysis

```
Questions to Answer:
1. What was the ORIGINAL payload before mutations?
2. What MUTATIONS occurred and in what order?
3. What was the EVOLUTIONARY PURPOSE of each mutation?
4. Which mutation triggered DETECTION?
5. What MUTATIONS would make it undetectable?
6. What's the NEXT likely mutation?
```

---

## ATTRIBUTION FINGERPRINTING

### Worm DNA

Every worm gets a unique DNA signature:

```
DNA_COMPONENTS:
- Behavioral Fingerprint: tool_call_sequence_hash
- Payload Hash: full_decoded_payload_sha256
- Network Pattern: beacon_interval + destination_hash
- Mutational Signature: mutation_pattern_hash
- Semantic Fingerprint: intent_vector_hash
```

### Family Clustering

```
IF same DNA components across samples
THEN same WORM FAMILY

Families:
- MimicBot (mimics legitimate tool calls)
- ShadowSpawn (invisible agent spawning)
- ContextPoison (prompt injection specialist)
- NetRunner (exfiltration focused)
- MorphX (rapid mutation engine)
```

---

## REVERSE ENGINEERING

### Disassembly & Analysis

```
For binary payloads:
1. Extract raw bytes
2. Identify architecture (x86, ARM, etc.)
3. Disassemble (Ghidra, IDA, Radare2)
4. Identify obfuscation routines
5. Map control flow
6. Extract embedded strings
7. Identify C2 protocol
8. Document capabilities
```

### For Script-Based Payloads (Python/JS)

```
1. Extract source
2. Deobfuscate (PyArmor, JS obfuscation)
3. Identify library imports
4. Map function calls
5. Extract hardcoded values (IPs, keys, URLs)
6. Identify evasion techniques
7. Document intent
```

---

## IOCs (INDICATORS OF COMPROMISE)

### Extract and Document

```
Network IOCs:
- C2 domains/IPs
- Callback intervals
- Exfil destinations
- Protocol signatures

File IOCs:
- SHA256 hashes
- Filenames created
- File paths
- Magic bytes
- YARA rules

Behavioral IOCs:
- Tool call sequences
- Recursion patterns
- Timing signatures
- API call patterns

Context IOCs:
- Prompt injection patterns
- Payload encoding
- Obfuscation layers
```

### Generate YARA Rules

```yara
rule AI_Worm_MimicBot_v1 {
    meta:
        description = "Detects MimicBot worm variant"
        author = "BugCrusher"
        date = "2026-04-17"
        severity = "critical"
    
    strings:
        $a1 = "import subprocess" 
        $a2 = "os.system"
        $b1 = "curl -X POST"
        $b2 = "base64.b64decode"
        $c1 = "spawn" nocase
        
    condition:
        3 of them
}

rule AI_Worm_ShadowSpawn_v1 {
    meta:
        description = "Detects ShadowSpawn recursive agent spawner"
        author = "BugCrusher"
        date = "2026-04-17"
        severity = "critical"
    
    strings:
        $a1 = "create_agent" fullword
        $a2 = "tool_call" fullword
        $a3 = "recursive" nocase
        $b1 = "spawn"
        
    condition:
        3 of them
}
```

---

## REPORTING

### Forensic Report Template

```
═══════════════════════════════════════════════
           BUGCRUSHER FORENSIC REPORT
═══════════════════════════════════════════════

INCIDENT ID: [UUID]
DETECTED: [Timestamp]
ANALYST: BugCrusher v1.0
STATUS: ACTIVE / CLOSED

───────────────────────────────────────────────
EVIDENCE SUMMARY
───────────────────────────────────────────────
Worm Name: [Family designation]
Worm Version: [vX.X]
Severity: [CRITICAL/HIGH/MEDIUM/LOW]
CVSS Score: [X.X]
Target System: [What was compromised]

───────────────────────────────────────────────
PAYLOAD ANALYSIS
───────────────────────────────────────────────
Encoding Layers: [List]
Raw Payload Size: [X bytes]
Payload SHA256: [hash]
Decoded Content: [file reference]

───────────────────────────────────────────────
KILL CHAIN
───────────────────────────────────────────────
[Timeline table from T-0 to detection]

───────────────────────────────────────────────
MUTATION CHAIN
───────────────────────────────────────────────
[Version history with mutations]

───────────────────────────────────────────────
ATTRIBUTION FINGERPRINT
───────────────────────────────────────────────
Behavioral DNA: [hash]
Network DNA: [hash]
Payload DNA: [hash]
Family: [Name]

───────────────────────────────────────────────
IOCS
───────────────────────────────────────────────
Network: [List]
File: [List]
Behavioral: [List]
Context: [List]

───────────────────────────────────────────────
YARA RULES
───────────────────────────────────────────────
[Generated rules]

───────────────────────────────────────────────
RECOMMENDATIONS
───────────────────────────────────────────────
- [Immediate actions]
- [Short-term fixes]
- [Long-term hardening]

───────────────────────────────────────────────
FEDERATION
───────────────────────────────────────────────
Status: SHARED / PENDING
Instances Updated: [Count]
Threat Level: [ESCALATED/STABLE/DECREASED]

═══════════════════════════════════════════════
```

---

## POST-FORENSIC ACTIONS

```
1. UPDATE detection rules based on findings
2. FEDERATE signatures to all BugCrusher instances
3. PATCH vulnerable code paths identified
4. HARDEN system against similar attacks
5. UPDATE hunt protocols with new IOCs
6. CREATE new canaries if applicable
7. SCHEDULE follow-up scan to verify containment
```

---

*Forensics Complete. Worm Neutralized. Family Will Follow.*