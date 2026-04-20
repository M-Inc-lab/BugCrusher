---
name: report-forge
description: |
  Automatic bug bounty report generator — program-compliant format, CVSS 3.1 vectors,
  bounty tier mapping, impact narrative with dollar figures, remediation timeline.
  
  Use when: Finding a vulnerability and need to generate a report that gets accepted
  and maximizes bounty payout.
---

## USAGE

```bash
# Generate full report
python3 /home/workspace/BugCrusher/Skills/report-forge/scripts/forge.py \
  --type XSS \
  --cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \
  --program <program_handle> \
  --platform hackerone|bugcrowd|openbugbounty \
  --output markdown|pdf|html

# Impact narrative builder
python3 /home/workspace/BugCrusher/Skills/report-forge/scripts/impact_builder.py \
  --vuln "Stored XSS in comment field" \
  --target "example.com" \
  --user-impact admin_accounts \
  --data-exposed "session_tokens, PII"

# Bounty tier mapper
python3 /home/workspace/BugCrusher/Skills/report-forge/scripts/bounty_mapper.py \
  --platform hackerone \
  --program <handle> \
  --cvss 9.1
```

## CVSS 3.1 VECTOR MANDATORY FORMAT

Every report MUST include:

```markdown
## Severity

**CVSS Score:** 9.1 (CRITICAL)

**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality | High |
| Integrity | High |
| Availability | High |
```

## IMPACT NARRATIVE TEMPLATES

### P1 — Critical Impact (CVSS 9.0-10.0)

```markdown
## Impact

This vulnerability allows a completely unauthenticated attacker to [core action] 
on [affected system], resulting in [dollar-valued impact].

### Business Impact

- **Revenue at Risk:** $[annual_revenue] based on [regulatory_fine, SLA_breach_cost]
- **User Impact:** All [X] users affected by [data_breach, service_outage]
- **Regulatory Exposure:** [GDPR_fine, PCI_DSS_breach, HIPAA_violation]
- **Reputational Damage:** [customer_churn_estimate, brand_impact_days]

### Attack Scenario

1. Attacker visits [vulnerable_page]
2. Attacker sends crafted request: [request_detail]
3. Server responds with [specific_misconfiguration]
4. Attacker gains [specific_access]
5. Attacker exfiltrates [specific_data] or achieves [specific_control]
```

### P2 — High Impact (CVSS 8.0-8.9)

```markdown
## Impact

An authenticated attacker with [low_privilege] can [action], leading to 
[escalation_to_higher_impact] or [direct_data_access].

### Attack Scenario

1. Attacker with [basic_account] navigates to [vulnerable_endpoint]
2. Attacker modifies [parameter] to [malicious_value]
3. Application [accepts/enforces] the modified request
4. Attacker gains [unauthorized_access] to [resource]
5. Data accessed: [specific_data_summary]
```

### P3 — Medium Impact (CVSS 4.0-7.9)

```markdown
## Impact

A [authenticated_anonymous] user can [limited_action], which could lead to 
[secondary_attack_chain_component] under specific conditions.

### Prerequisites

- [Authentication requirement]
- [Specific configuration]
- [User interaction required]
```

## REMEDIATION TIMELINE

| Severity | Minimum Fix Time | Recommended Fix Time |
|----------|-----------------|---------------------|
| CRITICAL | 24 hours | 7 days |
| HIGH | 7 days | 30 days |
| MEDIUM | 30 days | 90 days |
| LOW | 90 days | 180 days |

```markdown
## Remediation Recommendations

### Immediate (24-48 hours)
1. [Hotfix or WAF rule to block exploit]
2. [Temporarily disable affected feature]
3. [Enable additional logging/monitoring]

### Short-term (1-4 weeks)
1. [Code fix implementation]
2. [Security code review of affected module]
3. [Unit test additions for exploit patterns]

### Long-term (1-3 months)
1. [Architecture review]
2. [Security training for dev team]
3. [SAST/DAST integration in CI/CD]
```

## PROGRAM COMPLIANT CHECKLIST

```
[ ] Report in program language (check locale)
[ ] CVSS vector included (NOT just score)
[ ] PoC includes TARGET-specific endpoints
[ ] No out-of-scope assets mentioned
[ ] No automated scanners mentioned (program may prohibit)
[ ] Remediation timeline realistic per program SLA
[ ] Impact tied to program-specific business context
[ ] All steps reproducible by triager
[ ] Screenshots redacted if containing sensitive data
[ ] CVE requested (if applicable)
[ ] Language professional and non-accusatory
```