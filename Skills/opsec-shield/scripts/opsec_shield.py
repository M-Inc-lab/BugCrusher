#!/usr/bin/env python3
"""
BugCrusher — OPSEC SHIELD: Operational Security Layer
Prevents bans, legal exposure, and platform ejection.
"""

import requests
import json
import time
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from urllib.parse import urlencode

class OpsecShield:
    """
    OPSEC for bug bounty operations.
    
    Key protections:
    1. Rate limiting with human jitter
    2. Proxy rotation for recon
    3. Scope boundary enforcement
    4. Legal authorization tracking
    5. Platform-specific rules
    """
    
    def __init__(self):
        self.rate_limits = {
            'nuclei': {'requests': 30, 'per_seconds': 60},
            'amass': {'requests': 100, 'per_seconds': 60},
            'ffuf': {'requests': 50, 'per_seconds': 60},
            'sqlmap': {'requests': 20, 'per_seconds': 60},
            'default': {'requests': 30, 'per_seconds': 60},
        }
        self.last_request_times = {}
        self.proxy_list = []
        self.current_proxy_index = 0
        self.authorized_targets = {}
        
    def load_proxies(self, proxy_file: str):
        """Load proxy list from file (http://ip:port format)"""
        with open(proxy_file, 'r') as f:
            self.proxy_list = [line.strip() for line in f if line.strip()]
        return f"Loaded {len(self.proxy_list)} proxies"
    
    def get_proxy(self) -> Optional[Dict]:
        """Get next proxy in rotation"""
        if not self.proxy_list:
            return None
        proxy = self.proxy_list[self.current_proxy_index % len(self.proxy_list)]
        self.current_proxy_index += 1
        return {
            'http': f'http://{proxy}',
            'https': f'http://{proxy}',
        }
    
    def human_delay(self, base_ms: int = 1000, variance_ms: int = 500):
        """
        Add random delay to mimic human behavior.
        This is what stops you from getting banned.
        """
        variance = random.randint(-variance_ms, variance_ms)
        actual = max(100, base_ms + variance)
        time.sleep(actual / 1000)
    
    def rate_check(self, tool: str) -> bool:
        """
        Check if we're within rate limits for a tool.
        Returns True if we can proceed, False if we need to wait.
        """
        limits = self.rate_limits.get(tool, self.rate_limits['default'])
        key = f"{tool}_last"
        
        now = datetime.now()
        if key in self.last_request_times:
            elapsed = (now - self.last_request_times[key]).total_seconds()
            if elapsed < limits['per_seconds']:
                sleep_time = limits['per_seconds'] - elapsed + random.uniform(0.1, 0.5)
                time.sleep(sleep_time)
        
        self.last_request_times[key] = now
        return True
    
    def scope_check(self, target: str, scope_file: str = None, 
                   scope_domains: List[str] = None) -> bool:
        """
        CRITICAL: Verify target is in scope before any interaction.
        Out-of-scope = legal liability, instant ban.
        """
        target_lower = target.lower()
        
        if scope_domains:
            allowed = scope_domains
        elif scope_file:
            with open(scope_file, 'r') as f:
                allowed = [line.strip().lower() for line in f]
        else:
            # Default: assume unrestricted (USER ASSUMES RISK)
            return True
        
        # Check exact match or subdomain
        for domain in allowed:
            if target_lower == domain.lower():
                return True
            if target_lower.endswith(f".{domain}"):
                return True
            # Wildcard scope like *.target.com
            if domain.startswith('*.'):
                base = domain[2:]
                if target_lower.endswith(f".{base}"):
                    return True
        
        return False
    
    def record_authorization(self, program: str, target: str, 
                           authorized_by: str, date: str):
        """
        Track legal authorization for audit trail.
        NEVER skip this. This is what protects you legally.
        """
        self.authorized_targets[target] = {
            'program': program,
            'authorized_by': authorized_by,
            'date': date,
            'timestamp': datetime.now().isoformat()
        }
        return "Authorization recorded"
    
    def generate_report_id(self, prefix: str = "BC") -> str:
        """Generate unique report ID for tracking"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        return f"{prefix}-{timestamp}-{random_suffix}"

    def platform_rules(self, platform: str) -> Dict:
        """
        Return platform-specific rules and limits.
        Violate these = instant ban.
        """
        rules = {
            'hackerone': {
                'max_requests_per_minute': 60,
                'allowed_test_types': ['web', 'api', 'mobile'],
                'forbidden': ['automated_sqli_on_production', 'ddos', 'physical'],
                'rate_limit_grace': 1.2,  # 20% grace period
            },
            'bugcrowd': {
                'max_requests_per_minute': 30,
                'allowed_test_types': ['web', 'api'],
                'forbidden': ['automated_sql_injection', 'dos', 'social_engineering'],
                'rate_limit_grace': 1.0,
            },
            'infosecgroups': {
                'max_requests_per_minute': 20,
                'allowed_test_types': ['web'],
                'forbidden': ['sqlmap', 'automated_scanning'],
                'rate_limit_grace': 1.0,
            },
            'openbugbounty': {
                'max_requests_per_minute': 10,
                'allowed_test_types': ['web'],
                'forbidden': ['any_automated'],
                'rate_limit_grace': 1.0,
            },
        }
        return rules.get(platform.lower(), rules['hackerone'])

if __name__ == "__main__":
    shield = OpsecShield()
    
    # Demo
    print("[*] OPSEC Shield initialized")
    print(f"[*] Rate limits: {shield.rate_limits}")
    
    # Test scope check
    print(shield.scope_check("api.target.com", scope_domains=["target.com", "api.target.com"]))  # True
    print(shield.scope_check("evil.com", scope_domains=["target.com"]))  # False