---
name: opsec-shield
description: Operational security layer for BugCrusher — proxy rotation, scope boundary enforcement, rate limiting with human jitter, legal authorization verification, and automatic kill-switches. CRITICAL: Prevents ban, legal exposure, and platform ejection.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# OPSEC SHIELD SKILL

**Rule #1: You don't exist if they can't find you.**

Every scan, every request, every tool execution passes through OPSEC first.

---

## CORE COMPONENTS

### 1. IDENTITY ANONYMIZER
```python
class OPSECShield:
    def __init__(self):
        self.proxy_pool = []  # Residential proxies
        self.current_identity = None
        self.jitter_range = (0.3, 2.7)  # seconds
        
    def rotate_identity(self):
        """Switch proxy + randomize timing fingerprint"""
        self.current_proxy = random.choice(self.proxy_pool)
        self.user_agent = self._generate_human_ua()
        self.headers = self._generate_realistic_headers()
        
    def _generate_human_ua(self):
        """Rotate through real browser user agents, weighted by popularity"""
        browsers = [
            ("Chrome/Linux", 0.62),
            ("Firefox/Linux", 0.18),
            ("Safari/Mac", 0.14),
            ("Chrome/Windows", 0.04),
            ("Chrome/Android", 0.02)
        ]
        return weighted_choice(browsers)
```

### 2. RATE LIMITER WITH JITTER
```python
def safe_request(self, method, url, **kwargs):
    """Every request has human-like variance"""
    time.sleep(random.uniform(*self.jitter_range))  # base delay
    
    # Sometimes add long "thinking" pause
    if random.random() < 0.15:
        time.sleep(random.uniform(3, 8))  # 15% chance of 3-8s pause
    
    # Sometimes send extra "keep-alive" requests first
    if random.random() < 0.1:
        self._send_decoy_request(url)  # blind traffic
    
    return self.session.request(method, url, **kwargs)
```

### 3. SCOPE BOUNDARY ENFORCER
```
SCOPE RULES:
├── Always verify target is in program scope BEFORE scanning
├── Block any request to: *.internal.target.com, *.corp.target.com, *.intranet.target.com
├── Auto-kill scan if it hits: login pages, /admin, /phpmyadmin, /.git, /.env
├── If out-of-scope subdomain found → flag + log + STOP, don't touch it
└── Generate scope-violation report after every session
```

### 4. LEGAL SHIELD CHECK
```python
def verify_authorization(self, target, program):
    """Before ANY scan runs"""
    # 1. Check program is active (not in closed/hacked program status)
    # 2. Verify target is in scope (not excluded asset types)
    # 3. Check scanner is allowed (some programs ban automated tools)
    # 4. Confirm scope hasn't changed since last session
    # 5. Log authorization chain for legal protection
    
    if not self.is_authorized(target, program):
        return {"status": "BLOCKED", "reason": "...", "legal_risk": "HIGH"}
    return {"status": "CLEARED", "scan_mode": "permitted"}
```

### 5. KILL SWITCHES
```
IMMEDIATE STOP triggers:
├── Any response containing "legal", "lawyer", "cfAA", "unauthorized access"
├── Target responds with 403 + "security team notified" pattern
├── WAF fingerprint detected (Imperva, Akamai, Cloudflare challenge)
├── Rate limit triggered (429 + retry-after > 60s)
├── honeypot endpoints hit (/trap, /honeypot, /fake-admin-login)
└── Scope violation detected in request chain
```

---

## BLACKLIST (Auto-Block Everything Matching)
```
# These patterns ALWAYS stop, no exceptions
BLOCK_PATTERNS = [
    "internal", "intranet", "corp", "corporate",
    "staging.*internal", "dev.*internal", 
    "phpmyadmin", "pma", "mysql-admin",
    ".git", ".svn", ".env", "config",
    "backup.*db", "dump.sql", "*.bak",
    "vpn", "remote", "rdp", "ssh",
    "jenkins", "jira-confluence", "gitlab",
    "/admin", "/administrator", "/manage",
    "kibana", "grafana", "elastic",
    "grafana", "prometheus", "metrics"
]
```

---

## EVIDENCE CHAIN (Legal Protection)
```python
def log_scan_session(self, session_id, target, program, actions):
    """Maintains audit trail for legal defense"""
    session_log = {
        "session_id": session_id,
        "timestamp": now(),
        "program_scope_verified": program.scope_hash,
        "targets_scanned": actions,
        "no_scope_violations": bool,
        "authorization_timestamp": self.auth_check_time,
        "tools_used": self.tool_hashes,
        "proxy_identity": self.current_proxy,
        "evidence_hash": self._hash_all_results()
    }
    self.audit_chain.append(session_log)
```

---

## USAGE

Triggered automatically on EVERY scan operation. No user override unless they explicitly bypass OPSEC with `--danger-allow`.

```bash
# Normal operation (OPSEC always on)
> scan target.com

# With explicit acknowledgment of risk (platform consequences possible)
> scan target.com --danger-bypass-opsec
```