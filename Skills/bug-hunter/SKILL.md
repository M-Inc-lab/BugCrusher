---
name: bug-hunter
description: Bug bounty hunting playbooks and exploitation frameworks for web, mobile, API, and infrastructure targets. Use when conducting authorized security assessments or bug bounty research.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# BUG HUNTER SKILL

Autonomous vulnerability discovery and exploitation system.

## Usage

Triggered when:
- User wants to find vulnerabilities in a target
- Bug bounty assessment requested
- Security assessment of web/mobile/API/infrastructure
- Looking for specific exploit paths

---

## PHASE 1 — SEVERITY-FIRST TRIAGE

**Before ANY testing, assess what severity level is achievable:**

| Auth Level | Max Severity Achievable |
|------------|------------------------|
| None | P5 (info disclosures) |
| Basic (username/password) | P3/P4 |
| Valid session/API token | P1/P2 |
| Admin session | P1 (full takeover) |

**Rule: If program only accepts P1/P2 and you have no auth, STOP recon. Get credentials first.**

---

## PHASE 2 — Target Acquisition

```
1. Scope Definition
   - Define in-scope domains, IPs, mobile apps
   - Identify attack surface (web, mobile, API, network)
   - Map business logic and data flows
   - Identify high-value targets (auth, payments, user data)
   - Check for test instance / bug bounty sandbox URLs

2. Reconnaissance
   - Run passive recon (subdomains, DNS, WHOIS, Shodan)
   - Google dorking, GitHub scraping
   - Technology fingerprinting
   - Secret discovery (API keys, tokens in public repos)
   - S3 bucket enumeration
   - Check for GraphQL endpoints (/graphql, /api/graphql)

3. Surface Mapping
   - Spider all web endpoints
   - Map all API endpoints (Swagger, Postman collections)
   - Identify mobile app endpoints
   - Enumerate hidden parameters
```

---

## PHASE 3 — Vulnerability Discovery

### Web Attacks (by CVSS priority)

**P1/P2 Attacks:**
- SQL Injection → data extraction / OS command
- SSRF → cloud metadata / internal services
- IDOR → cross-user/cross-tenant data access
- Auth bypass → account takeover
- RCE → command execution
- XXE → SSRF / RCE
- Deserialization → RCE

**P3/P4 Attacks:**
- XSS (stored/reflected) — with meaningful impact
- CSRF — state-changing actions
- Open redirect — with phishing risk
- Broken authentication — session management
- Path traversal — file read (not RCE)

**P5 (Skip unless explicitly accepted):**
- GraphQL introspection enabled
- Apollo Tracing enabled
- Public enumeration (issue types, status codes)
- Missing security headers
- TRACE method enabled

### API Attacks (Priority Order)

1. **BOLA/BIDLA** — object enumeration across users/tenants
2. **Auth bypass** — fake tokens, alg:none JWT, missing auth on mutations
3. **Mass assignment** — modify protected fields
4. **SSRF via API** — URL parameters that trigger server-side fetches
5. **GraphQL injection** — batch queries, alias attacks
6. **Rate limiting bypass** — batch queries to enumerate
7. **API versioning attacks** — old versions may be unpatched

### GraphQL Testing Protocol

```bash
# Step 1: Full introspection
curl -s "https://target/graphql" -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name kind } } } } } }"}'

# Step 2: Assess severity
# - Introspection only = P5 (skip)
# - Mutations need auth = cannot test without credentials
# - Query fields expose PII without auth = P3/P4 IDOR

# Step 3: If auth available
# - Test ALL mutations with valid session
# - Test IDOR in query fields
# - Test batch queries for rate limit bypass
```

### Mobile Attacks
- APK reversing (jadx, ghidra)
- MITM traffic analysis
- Root detection bypass
- SSL pinning bypass (Frida)
- Hardcoded secrets extraction
- Insecure storage detection

### Network/Infrastructure
- SMB lateral movement
- VPN exploitation
- LDAP enumeration
- Default credentials
- AD CS exploitation
- NTLM relay attacks

---

## PHASE 4 — Exploitation

### High-Priority Exploits (P1/P2)

```
SSRF → AWS metadata (169.254.169.254) → steal credentials → pivot
IDOR → sequential IDs → cross-tenant data access
Auth bypass → mutations without credentials → admin actions
Forge SSRF → Atlassian-specific: forge.fetch() → internal access
```

### Exploitation Toolkit
```bash
# Subdomain enum
amass enum -passive -d target.com

# Directory fuzzing
ffuf -w wordlist.txt -u https://target.com/FUZZ

# SQL injection test
sqlmap -u "https://target.com/api?id=1" --batch --dbs

# XSS discovery
dalfox url "https://target.com/search?q=test"

# API fuzzing
ffuf -w params.txt -u "https://target.com/api/FUZZ" -X POST -d "@payload.json"

# GraphQL full test
python3 graphql_assassin.py https://target/graphql --full

# Mobile APK analysis
jadx -d output.apk target.apk
```

---

## PHASE 5 — Validation & Reporting

Every finding must:
1. Be reproducible with steps
2. Have CVSS score assigned (use cvss.calc.io)
3. Show real-world impact
4. Include remediation
5. Include PoC (curl, HTTP request, screenshot)

### VRT Category Reference (Bugcrowd)

| Finding | VRT Category | Subcategory |
|---------|-------------|-------------|
| GraphQL Introspection | Server Security Misconfig | GraphQL Introspection Enabled |
| Apollo Tracing | Server Security Misconfig | SSRF (Low impact) |
| SSRF Localhost | Server Security Misconfig | SSRF (Low impact) |
| SSRF Cloud Meta | Server Security Misconfig | SSRF (Internal High Impact) |
| IDOR Same Tenant | Broken Access Control | Insecure Direct Object Reference |
| IDOR Cross-Tenant | Broken Access Control | IDOR (Critical) |
| Auth Bypass | Broken Authentication | Auth Bypass |
| XSS | Cross-Site Scripting | XSS (Various) |
| SQLi | Injection | SQL Injection |

---

## SEVERITY ESCALATION GUIDE

### How to Escalate P5 → P1

| P5 Finding | Escalation Path |
|-----------|----------------|
| GraphQL Introspection | Find hidden mutations via schema that ARE vulnerable |
| Apollo Tracing | Use timing data to find IDOR (fast=safe, slow=exists) |
| Public Enumeration | Find sequential IDs → test cross-tenant access |
| Missing Headers | Chain with XSS or phishing for account takeover |

### When to Give Up and Move On

```
1. No auth + mature program + all endpoints secured = P5 only
2. Mutations all require auth + no IDOR in query fields = move on
3. Program explicitly says "no automated scanning" = manual recon only
4. Test instance not provisioned = cannot test Forge SSRF
```

**Rule: Spend time where P1/P2 is achievable. Don't bang on P5 findings.**

---

## Atlassian-Specific Playbook

### Test Instance Setup
```
URL: https://bugbounty-test-<bugcrowd-username>.atlassian.net
Forge: npm install -g @forge/cli
Deploy: forge create app && forge deploy
```

### Priority Attack Surface
1. Forge SSRF (forge.fetch()) → AWS metadata → cross-tenant
2. Cross-workspace IDOR (sequential workspace IDs)
3. Rovo AI Agent injection (prompt injection in AI commands)
4. Session hijacking via XSS → account takeover

### What to Test
```
admin.atlassian.com: REST API IDOR (user/project enumeration)
id.atlassian.com: GraphQL mutation auth bypass
bitbucket.org: Repository access control
Forge apps: SSRF via forge.fetch()
```

### What Is P5 at Atlassian
- Apollo Tracing enabled (information disclosure)
- GraphQL introspection (schema exposure)
- Public enumeration of issue types/resolutions

---

*Authorized testing only. Confirm scope before testing.*
