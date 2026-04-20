---
name: monetization
description: |
  NDA/contract generator for private sales, anonymous invoice generation,
  client retainer tracker, exploit flip marketplace lister.
  
  Use when: Monetizing findings outside bug bounty programs,
  managing private clients, or running an independent security research business.
---

## NDA TEMPLATE GENERATOR

```bash
python3 /home/workspace/BugCrusher/Skills/monetization/scripts/nda_gen.py \
  --buyer <buyer_handle> \
  --exploit <exploit_type> \
  --value <estimated_usd> \
  --output markdown|pdf
```

## INVOICE GENERATOR

```bash
python3 /home/workspace/BugCrusher/Skills/monetization/scripts/invoice_gen.py \
  --type exploit|consulting|retainer \
  --amount <usd> \
  --crypto \
  --output markdown|pdf
```

## CLIENT RETAINER TRACKER

```bash
python3 /home/workspace/BugCrusher/Skills/monetization/scripts/retainer_tracker.py \
  --client <name> \
  --add <monthly_rate> \
  --expires <YYYY-MM-DD> \
  --report <report_file>
```

## EXPLOIT FLIP LISTING

```bash
python3 /home/workspace/BugCrusher/Skills/monetization/scripts/exploit_lister.py \
  --exploit <cve_or_type> \
  --platform darkweb|tor|email \
  --price <usd> \
  --escrow \
  --anon
```

## PAYMENT METHODS (ANONYMOUS)

```
ACCEPTED:
- Monero (XMR) — preferred, untraceable
- Bitcoin (BTC) — traceable, use once per transaction
- Zcash (ZEC) — optional, shielded transactions
- Ethereum (ETH) — traceable, not preferred

ESCROW SERVICES:
- LocalMonero (trusted, fiat + crypto)
- Bisq (decentralized, no KYC)
- OpenBazaar (peer-to-peer marketplace)
- HASHXP (exploit-specific escrow)

NEVER:
- Wire transfer (KYC everywhere)
- PayPal/CashApp/Venmo (all reversible + KYC)
- Credit card (chargeback + KYC)
```

## CLIENT MANAGEMENT

```
RETAINER TIERS:
- Bronze: $2,000/month — 2 findings/month, basic reports
- Silver: $5,000/month — 5 findings/month, full CVSS reports
- Gold: $10,000/month — unlimited, CVSS + PoC + remediation
- Platinum: $25,000/month — exclusive targets, 24hr response SLA

SERVICE OFFERINGS:
- Exploit delivery (RCE/LPE/AUTH): $5K-$50K per finding
- Vulnerability assessment: $15K-$100K/month retainer
- Red team operations: $30K-$200K/engagement
- Penetration testing: $10K-$75K/engagement
- Security training: $5K-$20K/day
```