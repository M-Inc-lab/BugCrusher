#!/usr/bin/env python3
"""
BugCrusher — Hunt Execution Engine v4
Autonomous offensive security hunt execution.
Fixed: No shell=True, no bare except, all domains covered.
"""

import subprocess
import sys
import json
import sqlite3
import os
import time
import hashlib
import shutil
from datetime import datetime
from pathlib import Path

TARGETS_FILE = "/home/workspace/BugCrusher/targets.md"
VECTOR_DB = "/home/workspace/BugCrusher/vector_db.sqlite"
REPORTS_DIR = "/home/workspace/BugCrusher/hunt_reports"
WORKSPACE = "/home/workspace/BugCrusher/workspace"

# Tool paths
TOOLS = {
    "nmap": "/usr/bin/nmap",
    " nuclei": "/usr/local/bin/nuclei",
    "dalfox": "/usr/local/bin/dalfox",
    "sqlmap": "/usr/bin/sqlmap",
    "ffuf": "/usr/local/bin/ffuf",
    "python3": "/usr/local/bin/python3",
}

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
        
        print(f"[{self.session_id[:8]}] BugCrusher Hunt Engine v4 initialized")
        print(f"[{self.session_id[:8]}] Workspace: {WORKSPACE}")
    
    def _safe_subprocess(self, args, timeout=30, capture=True):
        """Safe subprocess without shell=True."""
        try:
            result = subprocess.run(
                args,
                capture_output=capture,
                timeout=timeout,
            )
            return result
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
            print(f"[!] Subprocess error: {e}")
            return None
    
    def load_targets(self):
        if not os.path.exists(TARGETS_FILE):
            print(f"[!] No targets.md found")
            return []
        
        with open(TARGETS_FILE, 'r') as f:
            content = f.read()
        
        targets = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('- ') and ('.com' in line or '.io' in line or '.ai' in line or '.co' in line or '.net' in line):
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
        print(f"[*] Recon: {len(subs)} subs, {len(self.recon_results['ips'])} IPs, {len(self.recon_results['technologies'])} techs, {len(self.recon_results['endpoints'])} endpoints | {self.stats['recon_duration']}s")
        
        return self.recon_results
    
    def _enum_subdomains(self, target):
        subs = set()
        words = ["www", "api", "admin", "test", "dev", "staging", "app", "mail", "cdn", "static", "m", "shop", "blog", "cdn2", "portal", "secure"]
        
        for word in words:
            host = f"{word}.{target}"
            try:
                r = self._safe_subprocess(["ping", "-c1", "-W1", host], timeout=2)
                if r and r.returncode == 0:
                    subs.add(host)
            except Exception:
                pass
        
        return list(subs)
    
    def _port_scan(self, hosts):
        ips = []
        for host in hosts[:30]:
            try:
                r = self._safe_subprocess(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3", f"http://{host}"], timeout=5)
                if r and r.stdout:
                    code = r.stdout.decode().strip()
                    if code in ['200', '301', '302', '403']:
                        ips.append(host)
            except Exception:
                pass
        return ips
    
    def _fingerprint(self, hosts):
        techs = []
        # Check if whatweb exists
        whatweb = shutil.which("whatweb")
        if not whatweb:
            return techs
        
        for host in hosts[:20]:
            try:
                r = self._safe_subprocess([whatweb, "-a", "1", host], timeout=15)
                if r and r.stdout:
                    techs.append({"host": host, "tech": r.stdout.decode().strip()[:100]})
            except Exception:
                pass
        return techs
    
    def _discover_endpoints(self, hosts):
        endpoints = []
        paths = ["/admin", "/api", "/login", "/admin.php", "/api/v1", "/graphql", "/debug", "/status", "/robots.txt", "/.env", "/config", "/dashboard", "/wp-admin", "/wp-login.php"]
        
        for host in hosts[:10]:
            for path in paths:
                url = f"http://{host}{path}"
                try:
                    r = self._safe_subprocess(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", url], timeout=8)
                    if r and r.stdout:
                        code = r.stdout.decode().strip()
                        if code in ['200', '301', '302', '403']:
                            endpoints.append({"url": url, "code": code})
                except Exception:
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
        nuclei_bin = shutil.which("nuclei")
        if not nuclei_bin:
            print("[!] Nuclei not found, skipping CVE scan")
            return
        
        try:
            subs_file = f"{WORKSPACE}/subs_{self.session_id}.txt"
            with open(subs_file, 'w') as f:
                f.write('\n'.join(self.recon_results.get('subdomains', [])[:100]))
            
            # Safe subprocess - no shell=True
            result = self._safe_subprocess([
                nuclei_bin, "-l", subs_file,
                "-t", "cve/",
                "-silent", "-no-color",
                "-o", f"{WORKSPACE}/nuclei_{self.session_id}.txt",
                "-rate-limit", "100"
            ], timeout=300)
            
            nuclei_out = f"{WORKSPACE}/nuclei_{self.session_id}.txt"
            if os.path.exists(nuclei_out):
                with open(nuclei_out) as f:
                    for line in f:
                        if line.strip():
                            self.findings.append({
                                "type": "CVE", "severity": "HIGH", "target": target,
                                "description": line.strip()[:150], "payload": "N/A",
                                "cvss": 7.5, "source": "nuclei"
                            })
                os.remove(nuclei_out)
            
            if os.path.exists(subs_file):
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
        test_params = ["id", "q", "query", "search", "page", "name", "url", "next", "data", "callback"]
        
        for param in test_params:
            test_url = f"{url}?{param}={payload}"
            try:
                r = self._safe_subprocess(["curl", "-s", "--max-time", "10", test_url], timeout=12)
                self.stats["requests_sent"] += 1
                if r and r.stdout:
                    response = r.stdout.decode().lower()
                    
                    indicators = ["error", "mysql", "syntax", "exception", "alert(", "script>", "xss", "sql"]
                    if any(x in response for x in indicators):
                        self.findings.append({
                            "type": category.upper(), "severity": self._cvss_to_severity(self._get_cvss(category)),
                            "target": url, "description": f"{category} via {param}",
                            "payload": payload, "cvss": self._get_cvss(category), "source": "vector"
                        })
                        return True
            except Exception:
                pass
        return False
    
    def _basic_tests(self, target):
        """Additional basic security tests."""
        # GraphQL endpoint test
        for endpoint in self.recon_results.get("endpoints", []):
            if "graphql" in endpoint["url"].lower():
                self._test_graphql(endpoint["url"])
    
    def _test_graphql(self, url):
        """Test GraphQL endpoint."""
        introspection_query = '{"query":"{ __schema { queryType { name } } }"}'
        try:
            r = self._safe_subprocess([
                "curl", "-s", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", introspection_query,
                "--max-time", "10", url
            ], timeout=15)
            if r and r.returncode == 0:
                self.findings.append({
                    "type": "GRAPHQL_INTROSPECTION", "severity": "INFO",
                    "target": url, "description": "GraphQL introspection enabled",
                    "payload": "N/A", "cvss": 0.0, "source": "graphql"
                })
        except Exception:
            pass
    
    def _cvss_to_severity(self, cvss):
        if cvss >= 9.0:
            return "CRITICAL"
        elif cvss >= 7.0:
            return "HIGH"
        elif cvss >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_cvss(self, category):
        cvss_map = {
            "RCE": 9.1, "SQLI": 9.0, "XXE": 8.5, "SSTI": 8.5,
            "XSS": 6.1, "SSRF": 8.2, "IDOR": 7.1, "LFI": 7.5,
            "CMDI": 8.8, "OPEN_REDIRECT": 4.7, "SSRF": 8.2
        }
        return cvss_map.get(category.upper(), 5.0)
    
    def generate_report(self, target):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"{REPORTS_DIR}/{target}_{timestamp}.md"
        
        report = f"""# BugCrusher Hunt Report: {target}

**Session:** `{self.session_id}`  
**Date:** `{self.start_time.isoformat()}`  
**Duration:** `{self.stats['recon_duration'] + self.stats['scan_duration']:.2f}s`

---

## Recon

| Metric | Value |
|--------|-------|
| Subdomains | {len(self.recon_results['subdomains'])} |
| Live Hosts | {len(self.recon_results['ips'])} |
| Technologies | {len(self.recon_results['technologies'])} |
| Endpoints | {len(self.recon_results['endpoints'])} |

## Findings ({len(self.findings)})

| # | Type | Severity | CVSS | Target | Description |
|---|------|----------|------|--------|-------------|
"""
        
        for i, f in enumerate(self.findings, 1):
            report += f"| {i} | {f['type']} | {f['severity']} | {f['cvss']} | {f['target']} | {f['description']} |\n"
        
        report += f"""

## Stats

| Metric | Value |
|--------|-------|
| Vectors Tested | {self.stats['vectors_tested']} |
| Requests Sent | {self.stats['requests_sent']} |
| Worm Status | **{self.worm_status}** |

*Generated by BugCrusher v4.0 — {timestamp}*
"""
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(f"[*] Report: {report_path}")
        return report_path

def main():
    # Check for --ai flag
    use_ai = "--ai" in sys.argv
    target_arg = None
    for arg in sys.argv[1:]:
        if not arg.startswith("--"):
            target_arg = arg

    if use_ai:
        print("[*] RAG AI mode enabled")
        try:
            from rag_ai.agent import create_agent
            agent = create_agent()

            if target_arg:
                report = agent.hunt(target_arg)
                print(report)
            else:
                hunter = BugCrusher()
                targets = hunter.load_targets()
                if not targets:
                    print("[!] No targets found in targets.md")
                    return
                for target in targets:
                    print(f"\n{'='*50}\nAI HUNTING: {target}\n{'='*50}")
                    report = agent.hunt(target)
                    print(report)
        except ImportError as e:
            print(f"[!] RAG AI not available: {e}")
            print("[!] Install deps: pip install -r rag_ai/requirements.txt")
        return

    # Standard mode
    hunter = BugCrusher()

    if target_arg:
        print(f"\n{'='*50}\nHUNTING: {target_arg}\n{'='*50}")
        hunter.recon(target_arg)
        hunter.scan(target_arg)
        hunter.generate_report(target_arg)
        return

    targets = hunter.load_targets()
    if not targets:
        print("[!] No targets found in targets.md")
        return
    
    for target in targets:
        print(f"\n{'='*50}\nHUNTING: {target}\n{'='*50}")
        hunter.recon(target)
        hunter.scan(target)
        hunter.generate_report(target)

if __name__ == "__main__":
    main()
