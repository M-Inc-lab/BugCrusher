---
name: bounty-calculator
description: Real-time bounty ROI engine. Maps CVSS scores, program asset weights, historical payment data, and program rules to rank findings by ACTUAL dollar value. Prevents hunters from wasting weeks on low-value bugs.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# BOUNTY CALCULATOR — Real Dollar Value Engine

**Rule #3: Know what a bug is worth before you hunt it.**

Every vulnerability type has a real dollar value. BugCrusher calculates it before you waste 40 hours.

---

## PAYMENT MATRIX

```python
class BountyCalculator:
    def __init__(self):
        # Historical bounty data from public disclosures
        self.payment_patterns = {
            "CRITICAL": {
                "IDOR with PII exposure": (5000, 15000),
                "SQL Injection": (5000, 25000),
                "Auth Bypass (Full Account Takeover)": (10000, 50000),
                "Remote Code Execution": (20000, 100000),
                "SSRF → Cloud Metadata Access": (5000, 20000),
                "Broken Crypto (confidentiality loss)": (5000, 30000)
            },
            "HIGH": {
                "Stored XSS (DOM-based, multi-user)": (500, 3000),
                "Self-XSS (requires user interaction)": (50, 200),
                "Open Redirect (pre-auth)": (100, 500),
                "CSRF (state-changing action)": (100, 500),
                "Misconfigured Cloud Storage (no auth)": (500, 5000),
                "Horizontal IDOR (data access own level)": (200, 1500),
                "Race Condition (financial impact)": (1000, 10000)
            },
            "MEDIUM": {
                "Reflected XSS (single user, no persistence)": (100, 500),
                "Information Disclosure (verbose errors)": (50, 300),
                "Missing Rate Limiting (DoS potential)": (100, 500),
                "Weak JWT Implementation": (200, 1000),
                "OAuth Misconfiguration (non-critical)": (200, 1000)
            },
            "LOW": {
                "Self-XSS in deprecated feature": (0, 50),
                "Informational disclosure (version info)": (0, 25),
                "Missing security headers": (0, 25),
                "Inactive email confirmation link": (0, 25)
            }
        }
        
        # Program tier multipliers
        self.program_multipliers = {
            "google": 1.5,
            "apple": 2.0,
            "microsoft": 1.4,
            "facebook/meta": 1.6,
            "shopify": 1.3,
            "uber": 1.2
        }
```

## BOUNTY ROI ENGINE

```python
def calculate_bounty_roi(self, vuln_type, endpoint, program, cvss_score):
    """
    Returns: (min_bounty, max_bounty, roi_rank, recommendation)
    """
    
    # 1. Base range from payment matrix
    base_min, base_max = self.payment_patterns[cvss_score].get(
        vuln_type, (50, 500)
    )
    
    # 2. Program multiplier
    program_multiplier = self.program_multipliers.get(
        program['publisher'], 1.0
    )
    
    # 3. Asset criticality
    asset_weights = program.get('asset_weights', {})
    endpoint_weight = asset_weights.get(endpoint, 1.0)
    
    # 4. Scope bonus (certain assets pay more)
    if self.is_critical_asset(endpoint, program):
        base_min *= 1.5
        base_max *= 2.0
        
    # 5. Time sensitivity (end of program = higher bounties)
    program_age = days_since(program['launch_date'])
    if program_age > 180:
        base_min *= 1.3
        base_max *= 1.4
    elif program_age < 30:
        base_min *= 0.8
        base_max *= 0.9  # new programs pay less initially
        
    # 6. Calculate final range
    final_min = int(base_min * program_multiplier * endpoint_weight)
    final_max = int(base_max * program_multiplier * endpoint_weight)
    
    # 7. ROI Score (bounty per hour estimated)
    estimated_hours = self.get_historical_effort(vuln_type, endpoint)
    roi_score = (final_min + final_max) / 2 / max(estimated_hours, 1)
    
    return {
        "min": final_min,
        "max": final_max,
        "median": (final_min + final_max) // 2,
        "roi_score": roi_score,
        "rank": self.rank_against_all_programs(final_max),
        "recommendation": self.get_recommendation(roi_score)
    }
```

## FINDING PRIORITY RANKING

```python
def rank_findings(self, candidate_findings, program):
    """
    Given N potential findings, rank by actual bounty value
    """
    ranked = []
    
    for finding in candidate_findings:
        roi = self.calculate_bounty_roi(
            vuln_type=finding['type'],
            endpoint=finding['endpoint'],
            program=program,
            cvss_score=finding['cvss']
        )
        ranked.append({**finding, **roi})
    
    return sorted(ranked, key=lambda x: x['roi_score'], reverse=True)
```

---

## PRACTICAL EXAMPLE

```
INPUT:
vuln_type: "IDOR in billing endpoint"
endpoint: "/api/v2/billing/update"
program: "shopify"
cvss: "HIGH"
endpoint_criticality: "billing" (high)

OUTPUT:
{
    "min_bounty": "$3,200",
    "max_bounty": "$9,800",
    "median": "$6,500",
    "roi_score": 42.3,  // $6,500 per hour of effort
    "rank": 4,  // 4th highest ROI bug type in Shopify program
    "recommendation": "HUNT FIRST - High ROI, low competition, critical asset"
}
```

---

## USAGE

```bash
> analyze-program shopify

BugCrusher responds:
[PROGRAM ANALYSIS] Shopify Security Bug Bounty
├── Top ROI Targets:
│   1. OAuth misconfig → $8,000-$25,000 (ROI: 78.2) 🔥🔥🔥
│   2. Auth bypass on /account → $10,000-$50,000 (ROI: 65.4) 🔥🔥🔥
│   3. IDOR in billing → $3,200-$9,800 (ROI: 42.3) 🔥🔥
│   4. SSRF in image upload → $2,000-$7,500 (ROI: 31.7) 🔥🔥
│   5. Stored XSS in reviews → $500-$2,000 (ROI: 12.1) 🔥
│   ...
├── Scope Heatmap: 67% of subdomains are SATURATED (avoid)
├── Under-hunted Gold: staging-legacy-inventory.shopify.com (0 disclosures)
├── Dup Alert: 14 SQLi submissions this week on /api/products (avoid)
└── RECOMMENDED HUNT PATH: [OAuth → Auth bypass → billing IDOR]
```