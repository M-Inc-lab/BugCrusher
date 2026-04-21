# BugCrusher — Target Programs

## Active Targets

Add your bug bounty programs here in this format:

```markdown
## [Program Name]
- **Platform:** HackerOne / Bugcrowd / Private
- **Scope:** 
  - in-scope: api.target.com, *.target.com
  - out-of-scope: admin.target.com, *.internal.target.com
- **Rewards:** $500 - $10,000 (Critical)
- **Last Scan:** YYYY-MM-DD
- **Status:** ACTIVE / PAUSED
- **Notes:** Any program-specific rules
```

## Example

```markdown
## Example Corp API Program
- **Platform:** HackerOne
- **Scope:** 
  - in-scope: api.example.com, *.api.example.com
  - out-of-scope: www.example.com, admin.example.com
- **Rewards:** $1,000 - $15,000 (Critical), $500 - $2,500 (High)
- **Last Scan:** 2026-04-16
- **Status:** ACTIVE
- **Notes:** No automated scanning allowed, manual testing only
```

---

## Scan History

| Date | Target | Findings | Status |
|------|--------|----------|--------|
| 2026-04-17 | Atlassian Bug Bounty | 1 MEDIUM (Apollo Tracing), 2 INFO | ACTIVE |
| 2026-04-17 | Atlassian Bug Bounty | Hunt #2 — 0 new findings. GraphQL requires auth. Confluence RCE needs test instance. Status: PAUSED. | PAUSED |
| 2026-04-18 | Atlassian Bug Bounty | Hunt #3 — 1 MEDIUM (Apollo Tracing), 1 INFO (GraphQL Introspection). Marketplace GraphQL accessible (25,747 types). All findings P5. | ACTIVE |
| 2026-04-18 | Atlassian Bug Bounty | Hunt #4 — 2 MEDIUM (Apollo Tracing x2), 1 INFO (GraphQL Introspection). All findings P5. CloudFront WAF blocks nuclei. GraphQL mutations require auth. Est. Bounty: $0. | ACTIVE |
| 2026-04-18 | Atlassian Bug Bounty | Hunt #6 — 3 P5 (GraphQL Introspection, Apollo Tracing, SDL Enum). Marketplace GraphQL has 25,791 types + AI types. Est. Bounty: $0. Need test instance for P1/P2. | ACTIVE |
| 2026-04-19 | Atlassian Bug Bounty | Hunt #7 — 3 P5 (Apollo Tracing, GraphQL Introspection 25,791 types, SDL Enum). CVE-2023-22515 weaponized but no Confluence accessible. All GraphQL mutations require auth. Est. Bounty: $0. Need test instance for P1/P2. | ACTIVE |
| 2026-04-19 | Atlassian Bug Bounty | Hunt #8 — 1 MEDIUM (Apollo Tracing), 2 INFO (GraphQL Introspection 25,791 types, SDL Enum). CVE-2023-22515 weaponized but no Confluence accessible. All GraphQL mutations require auth. Est. Bounty: $0. Need test instance for P1/P2. | ACTIVE |
| 2026-04-20 | Atlassian Bug Bounty | Hunt #10 — 1 MEDIUM (Apollo Tracing), 2 INFO (GraphQL Introspection 25,796 types, SDL Enum). Marketplace GraphQL has 25,796 types + AI/Rovo types. CVE-2023-22515 weaponized but no Confluence accessible. All GraphQL mutations require auth. Est. Bounty: $0. | ACTIVE |
| 2026-04-20 | Atlassian Bug Bounty | Hunt #11 — 1 MEDIUM (Apollo Tracing), 2 INFO (GraphQL Introspection 25,796 types, SDL Enum). Marketplace GraphQL has 25,796 types + AI/Rovo types. CVE-2023-22515 weaponized but no Confluence accessible. All GraphQL mutations require auth. Est. Bounty: $0. | ACTIVE |
| 2026-04-20 | Atlassian Bug Bounty | Hunt #12 — 1 MEDIUM (Apollo Tracing), 2 INFO (GraphQL Introspection 25,796 types, SDL Enum). Marketplace GraphQL has 25,796 types + AI/Rovo types. CVE-2023-22515 weaponized but no Confluence accessible. All GraphQL mutations require auth. Est. Bounty: $0. | ACTIVE |
| 2026-04-20 | Atlassian Bug Bounty | Hunt #13 — 1 MEDIUM (Apollo Tracing), 2 INFO (GraphQL Introspection 25,796 types, SDL Enum). Auth bypass detected on /gateway/api/graphql (public read access). All GraphQL mutations require auth. Est. Bounty: $0. Need test instance for P1/P2. | ACTIVE |
| 2026-04-21 | Atlassian Bug Bounty | Hunt #14 — 1 MEDIUM (Apollo Tracing), 2 INFO (GraphQL Introspection 25,796 types, SDL Enum). All findings P5. Need test instance for P1/P2. CVE-2023-22515 weaponized but no Confluence accessible. | ACTIVE |
| 2026-04-21 | Atlassian Bug Bounty | Hunt #15 — 1 MEDIUM (Apollo Tracing), 3 INFO (GraphQL Introspection 25,802 types, SDL Enum, Auth Bypass Public Read). CVE weapons ready but no Confluence. Need test instance for P1/P2. Est. Bounty: $325. | ACTIVE |
| 2026-04-21 | Atlassian Bug Bounty | Hunt #16 — 1 MEDIUM (Apollo Tracing), 2 INFO (GraphQL Introspection 50+ fields, SDL Enum). All GraphQL mutations require auth. CVE-2023-22515 weaponized but no Confluence accessible. Estimated Bounty: $0. Need test instance for P1/P2. | ACTIVE |

## Atlassian Bug Bounty Program
- **Platform:** Bugcrowd
- **Scope:** 
  - in-scope: admin.atlassian.com, id.atlassian.com, start.atlassian.com, bitbucket.org, *.atlassian.net, *.atlastunnel.com, *.atl-paas.net, marketplace.atlassian.com, compass.atlassian.com, atlas.atlassian.com, *.loom.com, admin.atlassian.com/atlassian-guard
  - out-of-scope: shop.atlassian.com, bytebucket.org, *.bitbucket.io, blog.bitbucket.org, support.atlassian.com, customer *.atlassian.net or *.jira.com instances
- **Rewards:** P1 $12,000 | P2 $4,000 | P3 $325 | P4 $250 (Tier 1) / P1 $7,000 | P2 $2,500 | P3 $250 | P4 $175 (Tier 2) / P1 $4,000 | P2 $1,500 | P3 $175 | P4 $100 (Tier 3)
- **Focus Areas:** RCE, SSRF, XSS, CSRF, SQLi, XXE, IDOR, Path Traversal, Cross Instance Data Leakage, AI Agent vulnerabilities
- **Last Scan:** 2026-04-21
- **Status:** ACTIVE
- **Notes:** Use bugbounty-test-<bugcrowd-name>.atlassian.net for cloud testing. No pivoting/post-exploitation. GraphQL, cyclic hydration & large payload processing OOS. Forge Platform in scope with GraphQL endpoint at /gateway/api/graphql
