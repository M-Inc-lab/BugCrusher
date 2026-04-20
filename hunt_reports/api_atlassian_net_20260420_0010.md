# BugCrusher Hunt Report: api.atlassian.net

**Date:** 2026-04-20 00:10 UTC  
**Duration:** 40s  
**Tools Run:** hunt_engine, execution_hive, graphql_assassin, cve_weaponizer, session_hijacker  
**Vectors Tested:** 5  
**Findings:** 3

## Worm Status
**CLEAN** — No worm artifacts detected

---

## Findings

| # | Type | Severity | Endpoint | PoC |
|---|------|----------|----------|-----|
| 1 | Apollo Tracing Enabled | MEDIUM | `https://marketplace.atlassian.com/gateway/api/graphql` | Trace header exposed in responses |
| 2 | GraphQL Introspection | INFO | `https://marketplace.atlassian.com/gateway/api/graphql` | Schema with 25,796 types enumerated |
| 3 | SDL Enumeration | INFO | `https://marketplace.atlassian.com/gateway/api/graphql` | Base types: User, Admin, Query, Mutation, Subscription |

---

## Detailed Findings

### Finding 1 — Apollo Tracing Enabled
**Severity:** MEDIUM  
**CVSS:** 5.3  
**Endpoint:** `https://marketplace.atlassian.com/gateway/api/graphql`  
**Type:** Information Disclosure  

**Impact Assessment:**  
Apollo tracing exposes resolver-level performance metrics including execution times per field. This reveals internal architecture, resolver complexity, and potential timing attacks on sensitive fields. Not directly exploitable without additional vulnerabilities.

**Reproduction Steps:**
```bash
curl -s -X POST 'https://marketplace.atlassian.com/gateway/api/graphql' \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __typename }"}'
# Check response headers for 'apollo tracing' or trace data in extensions
```

---

### Finding 2 — GraphQL Introspection Enabled (25,796 Types)
**Severity:** INFO  
**CVSS:** 0.0  
**Endpoint:** `https://marketplace.atlassian.com/gateway/api/graphql`  
**Type:** Information Disclosure  

**Impact Assessment:**  
Schema enumeration reveals entire API structure including internal types (AVP*, AI*, etc.). Useful for reconnaissance but P5 only — program notes explicitly exclude "cyclic hydration & large payload processing". No direct exploit path without authentication.

---

### Finding 3 — SDL Type Enumeration
**Severity:** INFO  
**CVSS:** 0.0  
**Endpoint:** `https://marketplace.atlassian.com/gateway/api/graphql`  
**Type:** Information Disclosure  

**Impact Assessment:**  
SDL enumeration reveals base GraphQL types. Standard introspection result. P5.

---

## CVE Weaponization

| CVE | CVSS | Status | Notes |
|-----|------|--------|-------|
| CVE-2023-22515 (Confluence RCE) | 9.1 | ⚠️ NO TARGET | Confluence not accessible in scan scope |
| CVE-2024-3400 (Palo Alto RCE) | 10.0 | ❌ OOS | Not in scope |
| CVE-2024-21762 (Fortinet VPN RCE) | 9.8 | ❌ OOS | Not in scope |
| CVE-2024-27198 (TeamCity RCE) | 9.1 | ❌ OOS | Not in scope |

---

## Session Hijacker Results
- **Cookies Found:** 0  
- **Auth Bypass:** Not applicable (endpoint requires HTTPS)  
- **IDOR Chain:** Not testable without valid session

---

## Summary

| Metric | Value |
|--------|-------|
| Total Findings | 3 |
| P1/P2 | 0 |
| P3/P4 | 1 (Apollo Tracing) |
| P5 | 2 |
| Est. Bounty | $0 |
| Action | Need authenticated test instance for P1/P2 |

---

## Recommendations

**Immediate:**
- Need test instance: `bugbounty-test-<bugcrowd-username>.atlassian.net`
- Forge Platform SSRF attack requires deployment access
- Cross-workspace IDOR requires valid session + workspace context

**For Next Hunt:**
- Provision test instance via Bugcrowd program
- Deploy test Forge app to probe `forge.fetch()` SSRF
- Focus on Rovo AI Agent prompt injection vectors
