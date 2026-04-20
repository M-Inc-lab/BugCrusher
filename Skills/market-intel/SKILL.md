---
name: market-intel
description: |
  Dark web exploit pricing, zero-day market value calculator, responsible disclosure
  timeline optimizer, CVE-to-market-rate mapping. Know what your findings are WORTH.
  
  Use when: Finding a 0-day, planning disclosure strategy, or evaluating bug bounty ROI.
---

## EXPLOIT PRICING DATABASE

### 2024-2025 Dark Web Market Rates

```
REMOTE CODE EXECUTION (RCE):
- Unauthenticated RCE (Linux, generic)     $3,000 - $15,000
- Unauthenticated RCE (Windows, generic)    $5,000 - $20,000
- Authenticated RCE (any)                  $1,000 - $5,000
- VMWare ESXi RCE                         $10,000 - $50,000
- VPN Appliance RCE (Fortinet, Pulse)      $8,000 - $30,000

PRIVILEGE ESCALATION:
- Windows LPE (0-day, any version)        $5,000 - $25,000
- Linux LPE (0-day, kernel)                $3,000 - $20,000
- macOS LPE (0-day, any)                  $5,000 - $30,000
- VMware LPE (guest-to-host)              $10,000 - $40,000

AUTHENTICATION BYPASS:
- OAuth/OpenID misconfiguration           $2,000 - $10,000
- SAML bypass/interception                 $5,000 - $25,000
- Kerberos attack (unauthenticated)       $8,000 - $35,000
- AD CS abuse (ESC1-ESC8)                $10,000 - $50,000

DATA EXFILTRATION:
- SQL Injection (blind, full DB)          $1,000 - $8,000
- Unauthenticated database access          $2,000 - $15,000
- AWS/GCP credential exposure             $3,000 - $20,000
- API authentication bypass                $2,000 - $12,000

NETWORK:
- SMB/NTLM relay (no user interaction)    $3,000 - $15,000
- DNS tunneling (working)                 $2,000 - $10,000
- Zero-trust bypass                       $5,000 - $25,000

MOBILITY (Mobile):
- iOS/Android RCE (0-day, no click)     $50,000 - $250,000
- Android 0-click (Janus, Brigmore)     $30,000 - $150,000
- Mobile banking trojan (source)         $20,000 - $100,000

ICS/OT:
- PLC remote code execution              $20,000 - $100,000
- SCADA authentication bypass             $10,000 - $50,000
- Industrial protocol injection           $15,000 - $75,000
```

### Bug Bounty Market Rates (Legal)

```
| Severity      | Bugcrowd    | HackerOne   | Private Program |
|---------------|-------------|-------------|-----------------|
| Critical (9+) | $3k-$15k    | $5k-$50k    | $10k-$100k+     |
| High (7-8.9)  | $1k-$5k     | $2k-$10k    | $5k-$25k        |
| Medium (4-6.9)| $200-$1k    | $500-$2k    | $1k-$5k         |
| Low (2-3.9)   | $50-$200    | $100-$500   | $200-$1k        |
```

### CVE Pricing Multipliers

```
CVE IMPACT MULTIPLIERS:
- CVSS 9.0-10.0:         base × 3.0 - 5.0
- CVSS 8.0-8.9:          base × 1.5 - 2.5
- CVSS 7.0-7.9:          base × 1.0 - 1.5
- CVSS 6.0-6.9:          base × 0.5 - 1.0
- CVSS <6.0:             base × 0.1 - 0.5

EXPLOIT CHAIN VALUE:
- Single exploit:         base price
- 2 exploits (RCE+LPE):  base × 1.5 (combo discount for buyer)
- 3 exploits (full chain): base × 2.0
- Exploit + C2 + exfil:  base × 3.0

TIMING MULTIPLIERS:
- 0-day (no CVE assigned):   base × 2.0 - 4.0
- N-day (CVE exists):         base × 0.3 - 0.7
- Patched (CVE + patch):     base × 0.1 - 0.3
```

## ZERO-DAY DISCLOSURE CALCULATOR

### Decision Matrix

```
FINDING TYPE          → ACTION
─────────────────────────────────────────────────────────────
Bug bounty program    → Report immediately (protect income)
NVD notified (CVE)    → Wait for CVE assignment before sale
0-day (no program)    → Assess: sell dark / responsible disclose
Historical CVE        → Sell immediately (depreciating asset)
Supply chain (npm/pip)→ Responsible disclose OR sell (high demand)
IoT/OT (ICS)          → Responsible disclose ONLY (legal risk)
Medical devices       → Responsible disclose ONLY (legal risk)
Gov/mil targets       → DO NOT TOUCH (FISA + CAATSA laws)
```

### Disclosure Risk Scoring

```
RISK FACTORS:
- Target is Fortune 500:            +20 risk
- Target is financial sector:       +25 risk (SOX, GLBA)
- Target is healthcare:            +30 risk (HIPAA)
- Target is government/military:    +50 risk (FISA, Computer Fraud Act)
- Target is critical infrastructure: +40 risk (CISA)
- Exploit is weaponized (PoC):     +15 risk
- Exploit is chained (RCE+LPE):     +20 risk
- Already in NVD:                   -30 risk
- Already patched:                  -40 risk

SCORE < 20:   Safe to sell dark
SCORE 20-50:  Sell with heavy OPSEC
SCORE > 50:   DO NOT SELL / Responsible disclose
```

## RESPONSIBLE DISCLOSURE TIMELINE

```
DAY 0:        Initial discovery + PoC
DAY 1-7:      Notify vendor via security@ contact
DAY 7-14:     Request CVE from MITRE/DSA
DAY 14-30:    Vendor acknowledgment + timeline
DAY 30-90:    Vendor patch development
DAY 90:       Public disclosure (if no patch)
DAY 90-180:   Optional: Sell as N-day post-disclosure
```