#!/usr/bin/env python3
"""
BugCrusher - Session Hijacker
Authentication chain tester - extracts tokens, maintains sessions, tests post-auth.
"""
import requests
import re
import json
import browsercookie
import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

class SessionHijacker:
    def __init__(self):
        self.session = requests.Session()
        self.tokens = {}
        self.db_path = "/home/workspace/BugCrusher/sessions.db"
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT, cookie_name TEXT, cookie_value TEXT,
                token_type TEXT, extracted_at TEXT, tested INTEGER DEFAULT 0,
                valid INTEGER DEFAULT 0, auth_bypass INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()
    
    def extract_from_browser(self, domain: str = None) -> List[Dict]:
        """Extract cookies from browser - firefox/chrome."""
        cookies = []
        try:
            cj = browsercookie.firefox()
            for cookie in cj:
                if domain is None or domain in cookie.domain:
                    cookies.append({
                        "name": cookie.name, "value": cookie.value,
                        "domain": cookie.domain, "path": cookie.path,
                        "expires": cookie.expires
                    })
        except:
            pass
        try:
            cj = browsercookie.chrome()
            for cookie in cj:
                if domain is None or domain in cookie.domain:
                    cookies.append({
                        "name": cookie.name, "value": cookie.value,
                        "domain": cookie.domain, "path": cookie.path,
                        "expires": cookie.expires
                    })
        except:
            pass
        return cookies
    
    def extract_from_header(self, header_value: str, token_type: str = "Bearer") -> Dict:
        """Parse auth header into token."""
        if token_type == "Bearer" and header_value.startswith("Bearer "):
            return {"type": "Bearer", "token": header_value[7:], "raw": header_value}
        if token_type == "Basic":
            return {"type": "Basic", "token": header_value, "raw": header_value}
        return {"type": token_type, "token": header_value, "raw": header_value}
    
    def store_session(self, domain: str, cookie_name: str, cookie_value: str, token_type: str = "Cookie"):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT INTO sessions (domain, cookie_name, cookie_value, token_type, extracted_at)
            VALUES (?, ?, ?, ?, ?)
        """, (domain, cookie_name, cookie_value, token_type, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    def test_auth_bypass(self, target: str, endpoint: str, method="GET") -> Dict:
        """Test if auth is properly enforced."""
        headers = {}
        if self.tokens.get(target):
            headers["Authorization"] = self.tokens[target]
        url = f"{target}{endpoint}"
        try:
            if method == "GET":
                r = self.session.get(url, headers=headers, timeout=10)
            else:
                r = self.session.post(url, headers=headers, timeout=10)
            if r.status_code == 200:
                return {"auth_bypass": True, "status": r.status_code, "response_len": len(r.text)}
            elif r.status_code == 401:
                return {"auth_bypass": False, "status": 401, "protected": True}
            else:
                return {"auth_bypass": False, "status": r.status_code, "may_be_bypass": True}
        except Exception as e:
            return {"auth_bypass": False, "error": str(e)}
        return {"auth_bypass": False}
    
    def test_idor(self, target: str, endpoint: str, resource_ids: List[int]) -> List[Dict]:
        """Test for IDOR - access other users resources."""
        findings = []
        for rid in resource_ids:
            url = f"{target}{endpoint.format(id=rid)}"
            r = self.session.get(url, timeout=10)
            if r.status_code == 200 and "error" not in r.text.lower():
                findings.append({"type": "IDOR", "url": url, "resource_id": rid, "leaked": True})
        return findings
    
    def test_jwt(self, token: str) -> Dict:
        """Analyze JWT for weaknesses."""
        parts = token.split(".")
        result = {"valid": True, "algos": [], "exposed_claims": []}
        if len(parts) != 3:
            return {"valid": False, "error": "not a JWT"}
        try:
            import base64
            header = json.loads(base64.b64decode(parts[0] + "==").decode())
            payload = json.loads(base64.b64decode(parts[1] + "==").decode())
            result["algos"].append(header.get("alg", "none"))
            if header.get("alg") == "none":
                result["exposed_claims"].append("alg:none - signature stripped")
            for key in ["sub", "email", "role", "admin", "user_id"]:
                if key in payload:
                    result["exposed_claims"].append(f"{key}={payload[key]}")
            if "exp" not in payload:
                result["exposed_claims"].append("no expiration - token valid forever")
        except:
            result["valid"] = False
        return result
    
    def full_chain_test(self, target: str) -> Dict:
        """Run full authentication chain test."""
        print(f"[*] Session Hijacker: Testing auth chain on {target}")
        results = {
            "target": target, "timestamp": datetime.now().isoformat(),
            "cookies_found": len(self.extract_from_browser(target)),
            "auth_bypass": self.test_auth_bypass(target, "/admin"),
            "findings": []
        }
        print(f"[*] Cookies: {results['cookies_found']} | Auth bypass: {results['auth_bypass']}")
        return results

if __name__ == "__main__":
    import sys
    h = SessionHijacker()
    if len(sys.argv) > 1:
        r = h.full_chain_test(sys.argv[1])
        print(json.dumps(r, indent=2, default=str))
    else:
        print("Usage: python session_hijacker.py <target_url>")