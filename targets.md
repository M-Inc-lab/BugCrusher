# BugCrusher — Target Programs

## Active Targets

## OpenAI Safety Bug Bounty
- **Platform:** Bugcrowd
- **Scope:**
  - in-scope: Agentic Tools Including MCP, Connectors and MCP, Account and Platform Integrity, Other Novel Abuse, OpenAI Proprietary Information, \*.openai.com
  - out-of-scope: Content/model response issues, third-party services without OpenAI-side remediation
- **Rewards:** P1 $5,500-$75,000 | P2 $2,500-$35,000 | P3 $750-$1,500 | P4 $250-$500 (bonuses for IDORs up to $13,000)
- **Focus Areas:** Agentic tools, MCP connectors, authorization bypasses, cross-tenant data exposure, prompt injection, unauthorized data access, IDOR on agentic products
- **Last Scan:** 2026-04-26
- **Status:** ACTIVE
- **Notes:** Test only against your own test accounts. Prompt injection must not be hosted on public surfaces. No automated scanners. Use safe-target.com equivalents for safe testing. Report via Bugcrowd Safety Bug Bounty engagement.

## Atlassian Bug Bounty Program
- **Platform:** Bugcrowd
- **Scope:** 
  - in-scope: admin.atlassian.com, id.atlassian.com, start.atlassian.com, bitbucket.org, \*.atlassian.net, \*.atlastunnel.com, \*.atl-paas.net, marketplace.atlassian.com, compass.atlassian.com, atlas.atlassian.com, \*.loom.com, admin.atlassian.com/atlassian-guard
  - out-of-scope: shop.atlassian.com, bytebucket.org, \*.bitbucket.io, blog.bitbucket.org, support.atlassian.com, customer \*.atlassian.net or \*.jira.com instances
- **Rewards:** P1 $12,000 | P2 $4,000 | P3 $325 | P4 $250 (Tier 1)
- **Focus Areas:** RCE, SSRF, XSS, CSRF, SQLi, XXE, IDOR, Path Traversal, Cross Instance Data Leakage, AI Agent vulnerabilities
- **Last Scan:** 2026-04-26
- **Status:** ACTIVE
- **Notes:** Use bugbounty-test-<bugcrowd-name>.atlassian.net for cloud testing. No pivoting/post-exploitation. GraphQL, cyclic hydration & large payload processing OOS. Forge Platform in scope with GraphQL endpoint at /gateway/api/graphql

---

## Scan History

| Date | Target | Findings | Status |
|------|--------|----------|--------|
| 2026-04-26 | OpenAI Safety Bug Bounty | Hunt #1 — Reconnaissance against openai.com attack surface. Focus on MCP connectors, agentic tool abuse paths, and authorization bypass vectors. | ACTIVE |
| 2026-04-26 | Atlassian Bug Bounty | Hunt #59 — 1 INFO (SDL Enum), 1 LOW (Auth Bypass Public Read). All GraphQL mutations require auth. No Confluence. Worm: CLEAN. Est. Bounty: $0. Need test instance for P1/P2. | ACTIVE |
