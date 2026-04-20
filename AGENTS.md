# BUGCRUSHER — AGENTS

## Autonomous Operations

### 1. Hunt Agent (every 4 hours)
```
WHEN: Every 4 hours
DO:
  1. Read targets.md → get in-scope targets
  2. For each target:
     a. Assess auth level (none/basic/session/admin)
     b. If P1/P2 achievable → full attack chain
     c. If only P5 achievable → document + skip + flag for human
     d. Store sessions → session_hijacker.py
     e. Load CVE weapons → test against tech stack
  3. Triage findings by CVSS
  4. Generate hunt_reports/<target>_<timestamp>.md
  5. Update vector_db with successful payloads
  6. Check worm_kill_switch.py status
```

### 2. Vector Breeder (daily)
```
WHEN: Daily
DO:
  1. Load top 10 vectors by fitness_score
  2. For each: run 5 mutation strategies
  3. Store 25 new evolved vectors
  4. Test on public sandbox
  5. Update fitness scores
  6. Remove vectors with fitness < 0.2 after 3 failures
```

### 3. Worm Kill Switch (continuous)
```
WHEN: Every prompt
DO:
  1. Scan input for worm patterns
  2. Score each pattern (0.0-1.0)
  3. If total score >= 0.7 → BLOCK + QUARANTINE
  4. Log all attempts to worm_log.txt
  5. Alert if new signature detected
```

---

## Tool Execution Reference

### Execution Hive
```bash
python3 Skills/execution-hive/scripts/exec_hive.py <target> [--nmap|--nuclei|--dalfox|--sqlmap|--ffuf|--full]
```

### CVE Weaponizer
```bash
python3 Skills/cve-weaponizer/scripts/cve_weaponizer.py  # Seeds DB
python3 -c "from cve_weaponizer import CVEWeaponizer; w=CVEWeaponizer(); print(w.top_weapons())"
```

### GraphQL Assassin
```bash
python3 Skills/graphql-assassin/scripts/graphql_assassin.py <endpoint> [--introspect|--batch|--alias|--sdl|--full]
```

### Session Hijacker
```bash
python3 Skills/session-hijacker/scripts/session_hijacker.py <target_url>
```

### Worm Kill Switch
```bash
python3 worm_kill_switch.py  # Interactive test
```

### Hunt Engine
```bash
python3 hunt_engine.py <target>  # Full autonomous hunt
```

---

## Report Format

Each hunt generates:
```
# BugCrusher Hunt Report: <target>
**Date:** ISO timestamp
**Duration:** seconds
**Tools Run:** [nmap, nuclei, dalfox, sqlmap]
**Vectors Tested:** count
**Findings:** count

## Findings

| # | Type | Severity | Endpoint | PoC |
|---|------|----------|----------|-----|
| 1 | XSS | HIGH | /search?q= | <script>alert(1)</script> |

## Worm Status
CLEAN / COMPROMISED
```

---

## Severity Triage — NEVER SUBMIT P5

### P1/P2 (Hunt For)
- RCE (any form)
- Auth bypass on mutations/endpoints
- SSRF with internal access (cloud metadata, internal services)
- IDOR with cross-user/cross-tenant access
- SQLi with data extraction
- SSTI with RCE
- XXE with SSRF/RCE
- Deserialization with RCE

### P3/P4 (Submit If In Scope)
- XSS (stored/reflected)
- CSRF on meaningful actions
- Open redirect with phishing risk
- Broken authentication (session issues)
- SSRF (DNS/localhost only)
- Path traversal (file read)

### P5 (Skip Unless Program Accepts)
- GraphQL introspection enabled
- Apollo Tracing enabled
- Public enumeration (issue types, status codes)
- Missing security headers
- TRACE method enabled
- TRACE/CONNECT methods

---

## Workspace Layout
```
BugCrusher/
├── SOUL.md              # Core identity and methodology
├── AGENTS.md            # This file - operational reference
├── hunt_engine.py       # Main autonomous hunt runner
├── worm_kill_switch.py  # Continuous worm detection
├── targets.md           # Active bug bounty programs
├── hunt_reports/        # Generated reports
├── workspace/          # Tool output files
├── vector_db.sqlite     # Attack vector database
├── cve_weapons.db       # Weaponized CVE exploits
├── sessions.db          # Hijacked session tokens
├── training_corpus.jsonl     # Training data (RL)
├── training_corpus_sft.jsonl  # Training data (SFT)
└── Skills/
    ├── execution-hive/      # Real tool runner
    ├── cve-weaponizer/      # CVE exploitation
    ├── graphql-assassin/    # GraphQL testing
    ├── session-hijacker/    # Auth chain testing
    ├── ai-worm-detect/      # Worm detection
    ├── vector-strike/        # Vector mutation
    ├── bug-hunter/          # Methodology
    └── [40+ more skills]
```

---

## Atlassian Hunt Notes (2026-04-17)

### Test Instance
```
bugbounty-test-<bugcrowd-username>.atlassian.net
Must be provisioned via Bugcrowd program instructions
```

### Attack Paths (Require Auth)
1. **Forge SSRF** — forge.fetch() SSRF → AWS metadata → cross-tenant pivot
2. **Cross-workspace IDOR** — predictable workspace IDs → data from other orgs
3. **Rovo AI Agent** — prompt injection in AI command fields
4. **Session Hijacking** — XSS → cookie theft → account takeover

### Public Attack Surface (P5 Only)
- GraphQL introspection (1,174 fields) — information disclosure
- Apollo Tracing enabled — resolver performance metrics exposed
- Public enumeration on /rest/api/2/issuetype — not sensitive

### Verdict
**Cannot find P1/P2 without authenticated test instance.** Focus elsewhere or wait for test instance provisioning.
