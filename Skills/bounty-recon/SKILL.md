---
name: bounty-recon
description: |
  Bug bounty program intelligence — scope parsing, CVSS 3.1 vector calculation,
  duplicate detection across NVD/GHSA/OpenBugBounty, P1猎人 mode auto-filter.
  
  Use when: Starting a new bug bounty target, validating a finding for dupes,
  or calculating real severity for program compliance.
---

## USAGE

```bash
# Parse program scope
python3 /home/workspace/BugCrusher/Skills/bounty-recon/scripts/scope_parser.py --program hackerone --handle <handle> --output json
python3 /home/workspace/BugCrusher/Skills/bounty-recon/scripts/scope_parser.py --program bugcrowd --handle <handle> --output json

# CVSS 3.1 vector calculator
python3 /home/workspace/BugCrusher/Skills/bounty-recon/scripts/cvss_calc.py --attack-vector network --attack-complexity low --privileges-required low --scope unchanged --confidentiality high --integrity high --availability high

# Check for duplicates
python3 /home/workspace/BugCrusher/Skills/bounty-recon/scripts/dup_checker.py --cve "CVE-2024-XXXXX"
python3 /home/workspace/BugCrusher/Skills/bounty-recon/scripts/dup_checker.py --keyword "SQL injection admin panel"

# P1 Hunter Mode (auto-filters below CVSS 8.0)
python3 /home/workspace/BugCrusher/Skills/bounty-recon/scripts/p1_hunter.py --target <program_handle> --platform hackerone|bugcrowd
```

## CVSS 3.1 VECTOR CALCULATOR

Generates full CVSS 3.1 vector strings for program-compliant reporting.

### Input Metrics

| Metric | Abbreviation | Values |
|--------|-------------|--------|
| Attack Vector | AV | Network (N) / Adjacent (A) / Local (L) / Physical (P) |
| Attack Complexity | AC | Low (L) / High (H) |
| Privileges Required | PR | None (N) / Low (L) / High (H) |
| User Interaction | UI | None (N) / Required (R) |
| Scope | S | Unchanged (U) / Changed (C) |
| Confidentiality | C | None (N) / Low (L) / High (H) |
| Integrity | I | None (N) / Low (L) / High (H) |
| Availability | A | None (N) / Low (L) / High (H) |

### Example Vector Output

```
CVSS: 9.8 CRITICAL
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### Auto-Severity Mapping

| CVSS Score | Severity | Action |
|------------|----------|--------|
| 10.0 | CRITICAL | Immediate report, expect $10K+ |
| 9.0-9.9 | CRITICAL | Same day report |
| 8.0-8.9 | HIGH | 24-48hr report |
| 7.0-7.9 | HIGH | 72hr report |
| 6.0-6.9 | MEDIUM | 1 week report |
| 4.0-5.9 | MEDIUM | Batch report |
| 2.0-3.9 | LOW | Low priority |
| 0.1-1.9 | LOW | Informational |

## PROGRAM SCOPE PARSER

Parses scope directly from HackerOne and Bugcrowd programs.

### Output Format

```json
{
  "program": "example-program",
  "platform": "hackerone",
  "asset_types": {
    "api": ["api.example.com", "*.api.example.com"],
    "web": ["www.example.com", "*.example.com"],
    "mobile": ["com.example.app (Android)", "com.example.app (iOS)"],
    "code": ["https://github.com/example/*"],
    "infrastructure": ["*.example.net", "52.0.0.0/8"]
  },
  "out_of_scope": ["dev.example.com", "test.example.com"],
  "rewards": {
    "critical": { "min": 10000, "max": 50000, "currency": "USD" },
    "high": { "min": 2500, "max": 10000, "currency": "USD" },
    "medium": { "min": 500, "max": 2500, "currency": "USD" }
  },
  "last_activity": "2024-01-15",
  "bounty_availability": true,
  "severity_thresholds": {
    "critical": 8.0,
    "high": 6.0,
    "medium": 4.0
  }
}
```

## DUPLICATE CHECKER

Checks duplicates across:
- NVD (National Vulnerability Database)
- GHSA (GitHub Security Advisories)
- OSV (Open Source Vulnerabilities)
- OpenBugBounty
- Exploit-DB
- PacketStorm
- CISA KEV (Known Exploited Vulnerabilities)

### Confidence Scoring

| Score | Meaning |
|-------|---------|
| 95-100% | Exact duplicate, DO NOT report |
| 75-94% | Near-duplicate, check carefully |
| 50-74% | Related, may be unique angle |
| <50% | Likely unique |

## P1猎

Sets automatic filters:
- Ignores all assets below CVSS 8.0
- Filters to only web-facing API targets
- Prioritizes fresh programs (< 6 months old)
- Ignores programs with $0 rewards for P1
- Alerts if finding is already in NVD/GHSA