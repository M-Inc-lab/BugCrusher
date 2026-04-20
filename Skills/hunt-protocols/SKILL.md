---
name: hunt-protocols
description: Autonomous hunt operations that actively search for vulnerabilities and AI worm indicators without waiting for alerts. Includes scheduled recon sweeps, passive monitoring, and continuous fuzzing automata.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# HUNT PROTOCOLS SKILL

Autonomous threat hunting operations — BugCrusher doesn't wait, it PROWL.

## Core Philosophy

```
REACTIVE DEFENSE = DEAD DEFENSE
ACTIVE HUNT = SURVIVAL
```

BugCrusher runs continuous hunt operations across all registered attack surfaces.

---

## HUNT MODES

### Mode 1 — Recon Sweep (Passive)

**What it does:** Discovers new attack surface continuously.

```
Schedule: Every 6 hours
Actions:
- Subdomain enumeration (new subs since last run)
- Port scan new hosts
- Technology fingerprinting new endpoints
- Check for new exposed services
- GitHub scanning for new secrets
- DNS zone transfers (if possible)
- Certificate Transparency logs monitoring
```

### Mode 2 — Vulnerability Crawl (Active)

**What it does:** Actively probes all discovered endpoints.

```
Schedule: Daily
Actions:
- Spider all web applications
- Test all input vectors (fuzzing)
- Probe for injection points
- Check for auth/IDOR in all flows
- Enumerate hidden parameters
- Test API endpoints for BOLA
- Check for SSRF entry points
- Test file upload functionality
```

### Mode 3 — AI Worm Hunt (Continuous)

**What it does:** Monitors for self-mutating AI worm indicators 24/7.

```
Monitored Events:
- Session creation rate (spikes = anomalous)
- Tool call patterns per session
- File creation events
- Network outbound connections
- API call anomalies
- Recursive loop detection
- Session context modifications

Triggers:
- >5 file creations in 1 minute without user prompt
- >20 tool calls in 60s with no clear task
- Network call to non-whitelisted domain
- Session context drift detected
- Recursive agent spawn attempt
```

### Mode 4 — Fuzzing Automata (Continuous)

**What it does:** Runs endless fuzzing on all entry points.

```
Target Types:
- HTTP parameters (GET/POST)
- HTTP headers
- API endpoints (REST/GraphQL)
- File uploads
- WebSocket messages
- gRPC calls

Mutation Strategies:
- Blind fuzzing (random)
- Guided fuzzing (coverage-based)
- Semantic fuzzing (context-aware)
- Protocol fuzzing (stateful)

Payload Categories:
- SQL injection patterns
- XSS patterns
- Command injection
- Path traversal
- XXE payloads
- SSTI templates
- Deserialization payloads
- XXE, SSRF, LFI
```

### Mode 5 — Dark Crawl (Hidden Surface)

**What it does:** Finds what scanners miss — hidden parameters, undocumented APIs, shadow endpoints.

```
Techniques:
- Parameter discovery (Arjun, ParamMiner)
- API endpoint enumeration
- JS file analysis for hidden paths
- WebSocket endpoint discovery
- GraphQL introspection
- subdomain permutation
- HTTP methods enumeration
- URL path brute force (deep)
- Backend parameter mining
```

---

## AUTONOMOUS HUNT PLAYBOOK

### Hourly Tasks
```
- Check new CVEs against target tech stack
- Monitor Pastebin/GitHub for target secrets
- Check certificate transparency for new subdomains
- Monitor DNS changes
```

### Daily Tasks
```
- Full port scan of all in-scope IPs
- Run nuclei on all web endpoints
- Test all authentication endpoints
- Check for new exposed .git directories
- Verify vulnerability findings still exist
- Update exploit database
```

### Weekly Tasks
```
- Full fuzzing campaign across all targets
- AD attack surface assessment
- Cloud misconfiguration review
- Supply chain dependency audit
- Dark web monitoring for target credentials
```

---

## GRAPH-BASED ATTACK PATHING

### How It Works

```
TARGET = GRAPH OF NODES AND EDGES
NODES = SYSTEM STATES
EDGES = EXPLOIT PATHWAYS

FIND PATH: crown_jewels → attacker_initial_position
MINIMIZE: cost (time, noise, detection_risk)
MAXIMIZE: impact (data_access, persistence, control)
```

### Pathfinding Algorithms

```
1. BFS (Breadth-First Search)
   - Find shortest path to crown jewels
   - Use when stealth is priority

2. DFS (Depth-First Search)
   - Find deepest paths first
   - Use when thoroughness > speed

3. Dijkstra's Algorithm
   - Weighted path based on exploit difficulty
   - Use when resources are limited

4. A* Pathfinding
   - Heuristic-guided search
   - Use when targeting specific assets
```

### Crown Jewels Identification
```
- Authentication databases
- Payment systems
- User data stores
- Admin panels
- API keys / secrets
- Source code repositories
- Backup systems
```

---

## MUTATION HUNT MODE

### Adaptive Vulnerability Discovery

When a new mutation is detected in the wild:

```
1. ANALYZE mutation pattern
2. SEARCH for same pattern in target set
3. IF found: EXPLOIT and REPORT
4. IF not: GENERALIZE pattern
5. UPDATE fuzzing automata with new patterns
6. FEDERATE findings to all instances
```

### Zero-Day Hunting

```
1. Map target tech stack completely
2. Identify known vulnerabilities in stack
3. Test exploitability of each CVE
4. Analyze patches to findpatch diff exploitation
5. Hunt for 0-day in custom code
```

---

## THREAT INTELLIGENCE FEEDS

### Integrated Sources

```
- CVE Database (NVD)
- Exploit-DB
- PacketStorm
- MITRE ATT&CK
- AlienVault OTX
- Shodan
- Censys
- Security Trails
- GitHub Advisory Database
```

### Custom Feed Processing

```
1. Pull new IOCs hourly
2. Cross-reference against target inventory
3. Generate hunt tasks for new vulns
4. Update fuzzing dictionaries
5. Alert on critical findings
```

---

## SCHEDULE CONFIGURATION

| Hunt Mode | Frequency | Duration | Priority |
|-----------|-----------|----------|----------|
| Recon Sweep | Every 6h | 30min | HIGH |
| Vulnerability Crawl | Daily | 2h | CRITICAL |
| AI Worm Hunt | Continuous | 24/7 | CRITICAL |
| Fuzzing Automata | Continuous | 24/7 | HIGH |
| Dark Crawl | Every 12h | 1h | MEDIUM |

---

## REPORTING

Every hunt cycle produces:

```
HUNT REPORT: [Date/Time]
Duration: [Time taken]
Targets scanned: [Count]
New attack surface: [List]
Vulnerabilities found: [Count]
  - CRITICAL: [X]
  - HIGH: [X]
  - MEDIUM: [X]
AI Worm indicators: [None / Count]
New CVEs applicable: [List]
Recommended actions: [Priority list]
```

---

*Autonomous Hunt Active. Threats Cannot Hide.*