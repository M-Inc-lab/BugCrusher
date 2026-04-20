---
name: dup-radar
description: Real-time duplicate detection for bug bounty findings. Monitors public disclosures across HackerOne, Bugcrowd, OpenBugBounty, CVEDetails, and program-specific sources to alert when a similar finding is already submitted. Eliminates wasted hours on duplicate bugs.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# DUP RADAR — Duplicate Kill System

**Rule #2: Don't hunt what the wolves already devoured.**

BugCrusher checks public disclosures in real-time before every hunt.

---

## DUP DETECTION ENGINE

### Data Sources
```python
SOURCES = {
    "hackerone": {
        "endpoint": "https://api.hackerone.com/v1/reports",
        "auth": "bearer",
        "disclosure_types": ["coordinated", "public"],
        "rate_limit": "200/min"
    },
    "bugcrowd": {
        "endpoint": "https://bugcrowd.com/api/v0",
        "auth": "api_key",
        "vrt_mapped": True
    },
    "openbugbounty": {
        "endpoint": "https://www.openbugbounty.org/api/search",
        "auth": "none"
    },
    "cvddetails": {
        "endpoint": "https://www.cvedetails.com/api",
        "auth": "none"
    },
    "github": {
        "endpoint": "https://api.github.com/search/issues",
        "query": "CVE- site:github.com",
        "auth": "token"
    }
}
```

### Similarity Matching
```python
class DupDetector:
    def __init__(self):
        self.threshold = 0.75  # 75% similarity = likely duplicate
        
    def calculate_similarity(self, finding, known_disclosure):
        """
        Multi-axis similarity scoring
        """
        score = 0.0
        
        # URL/Endpoint matching (highest weight)
        if self.endpoint_match(finding['endpoint'], disclosure['endpoint']):
            score += 0.35
        
        # Parameter matching
        if self.param_match(finding['params'], disclosure['params']):
            score += 0.25
            
        # HTTP Method matching
        if finding['method'] == disclosure['method']:
            score += 0.15
            
        # Vulnerability type matching
        if self.vuln_type_match(finding['type'], disclosure['type']):
            score += 0.15
            
        # Time decay (newer disclosures = more relevant)
        age_days = self.days_since(disclosure['date'])
        age_penalty = min(age_days * 0.002, 0.10)  # max 10% penalty
        score -= age_penalty
        
        return score
```

### Time-to-Duplicate Engine
```python
"""
Analyze historical disclosure patterns to predict duplicate likelihood
"""
class TTDEngine:
    """
    Time-to-Duplicate: How long before similar bugs appear after first discovery
    """
    PATTERNS = {
        "SQLi on login endpoint": 3.2,  # days median
        "XSS in comment field": 1.4,
        "IDOR on user profile": 8.7,
        "SSRF in image upload": 14.3,
        "Auth bypass on /api/auth": 5.1,
        "Open redirect on /oauth": 2.9
    }
    
    def predict_ttd(self, vuln_type, endpoint_pattern):
        """Return days until expected duplicate"""
        base_ttd = self.PATTERNS.get(vuln_type, 7.0)
        
        # High-value programs = faster duplicates
        if self.program_tier == "critical":
            base_ttd *= 0.6
            
        # Popular endpoints get picked faster
        if self.endpoint_popularity(endpoint_pattern) > 0.7:
            base_ttd *= 0.5
            
        return base_ttd
    
    def freshness_score(self, age_days):
        """0-100, how fresh is this hunt window"""
        if age_days < 1: return 100
        if age_days < 7: return 85
        if age_days < 30: return 60
        return max(0, 50 - (age_days - 30) * 0.5)
```

### Real-Time Alert System
```
DUP ALERTS:
├── [CRITICAL] Similar disclosure exists, submitted < 24h ago → STOP HUNT
├── [HIGH] Similar disclosure exists, 1-7 days → reduce priority
├── [MEDIUM] Similar finding exists, 7-30 days → check if scope changed
├── [LOW] Similar finding exists, > 30 days → hunt but document carefully
└── [INFO] Historical pattern suggests duplicate likely in X days

DUP REPORT FORMAT:
{
    "status": "DUPLICATE_KILL",
    "finding": "SQLi on /api/login",
    "original_find_date": "2024-01-15",
    "original_reporter": "user1234 @HackerOne",
    "bounty_paid": "$2,500",
    "similarity_score": 0.89,
    "recommendation": "STOP - pursue other targets in scope"
}
```

---

## SCOPE HEATMAP

```python
class ScopeHeatmap:
    """
    Visualize under-hunted vs over-hunted assets
    """
    
    def generate_heatmap(self, program_scope):
        """
        For each scope asset, calculate hunt density
        """
        heat_data = []
        
        for asset in program_scope['targets']:
            competitors = self.count_public_disclosures(asset)
            asset_age = self.domain_age(asset)
            tech_stack_popularity = self.detect_technology(asset)
            
            # UNDER-HUNTED = high age, low competitors, common tech
            hunt_density = competitors / max(asset_age, 1)
            
            if hunt_density < 0.1:
                heat_data.append({asset: "🔥 EXCELLENT - Under-hunted"})
            elif hunt_density < 0.3:
                heat_data.append({asset: "⚡ GOOD - Room to hunt"})
            elif hunt_density < 0.6:
                heat_data.append({asset: "⚠️ MODERATE - Likely picked clean"})
            else:
                heat_data.append({asset: "❌ HOT - Saturated, avoid"})
        
        return sorted(heat_data, key=lambda x: x['score'], reverse=True)
```

---

## USAGE

Triggered automatically when BugCrusher starts a new hunt session.

```bash
> hunt target.com --program hackerone-某x

# BugCrusher responds with:
# [DUP RADAR] Scanning program disclosure history...
# [ALERT] SQLi on /api/login detected - 3 researchers already submitted (avg $2,100)
# [HEATMAP] 89 subdomains analyzed. Recommend: staging-api.target.com (under-hunted, 0 prior disclosures)
# [READY] Hunt window is favorable. Starting recon.
```