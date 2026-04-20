#!/usr/bin/env python3
"""
BugCrusher - Execution Hive v5
Real tools: nmap, nuclei, dalfox, sqlmap, ffuf
"""
import subprocess
import json
import sys
import os
from datetime import datetime

TOOLS = {
    "nmap": "/usr/bin/nmap",
    "nuclei": "/usr/local/bin/nuclei",
    "dalfox": "/usr/local/bin/dalfox",
    "sqlmap": "/usr/bin/sqlmap",
    "ffuf": "/usr/local/bin/ffuf"
}

class ExecutionHive:
    def __init__(self):
        self.results = {"nmap": [], "nuclei": [], "dalfox": [], "sqlmap": [], "ffuf": [], "findings": []}
        self._check_tools()
    
    def _check_tools(self):
        missing = [k for k, v in TOOLS.items() if not os.path.exists(v)]
        if missing:
            print(f"[!] Missing tools: {missing}")
        print(f"[*] Execution Hive v5 ready")
    
    def run_nmap(self, target, mode="full"):
        print(f"[*] Nmap scanning {target}...")
        args = ["-sV", "-sC", "-O"] if mode == "full" else ["-T4", "-F"]
        r = subprocess.run([TOOLS["nmap"], "-oX", "-"] + args + [target], capture_output=True, text=True, timeout=600)
        self.results["nmap"] = r.stdout.split("\n")
        print(f"[*] Nmap done: {len(self.results['nmap'])} lines")
        return self.results["nmap"]
    
    def run_nuclei(self, target):
        print(f"[*] Nuclei scanning {target}...")
        out_file = f"/tmp/nuclei_{datetime.now().strftime('%s')}.jsonl"
        r = subprocess.run([TOOLS["nuclei"], "-u", target, "-jsonl", "-silent", "-je", out_file], capture_output=True, text=True, timeout=300)
        findings = []
        try:
            with open(out_file) as f:
                for line in f:
                    try:
                        j = json.loads(line)
                        findings.append(j)
                        sev = j.get("info", {}).get("severity", "")
                        if sev in ["critical", "high"]:
                            self.results["findings"].append({"type": "nuclei", "name": j["info"]["name"], "severity": sev, "url": j.get("host", target)})
                    except:
                        pass
        except Exception as e:
            print(f"[!] Nuclei parse error: {e}")
        self.results["nuclei"] = findings
        os.unlink(out_file)
        return findings
    
    def run_dalfox(self, target):
        print(f"[*] Dalfox XSS scanning {target}...")
        out_file = f"/tmp/dalfox_{datetime.now().strftime('%s')}.json"
        r = subprocess.run([TOOLS["dalfox"], "url", target, "-o", out_file], capture_output=True, text=True, timeout=300)
        findings = []
        try:
            with open(out_file) as f:
                for line in f:
                    try:
                        j = json.loads(line)
                        findings.append(j)
                        if j.get("type") == "found":
                            self.results["findings"].append({"type": "XSS", "severity": "high", "url": j.get("url", target)})
                    except:
                        pass
        except Exception as e:
            print(f"[!] Dalfox parse error: {e}")
        self.results["dalfox"] = findings
        return findings
    
    def run_sqlmap(self, target):
        print(f"[*] Sqlmap testing {target}...")
        r = subprocess.run([TOOLS["sqlmap"], "-u", target, "--batch", "--level=3", "--risk=3"], capture_output=True, text=True, timeout=600)
        if "vulnerable" in r.stdout.lower() or "is likely vulnerable" in r.stdout.lower():
            self.results["findings"].append({"type": "SQLi", "severity": "critical", "url": target})
        self.results["sqlmap"] = r.stdout.split("\n")
        return self.results["sqlmap"]
    
    def run_ffuf(self, target):
        print(f"[*] Ffuf fuzzing {target}...")
        wordlists = ["/usr/share/wordlists/dirb/common.txt", "/usr/share/wordlists/rockyou.txt"]
        wl = next((w for w in wordlists if os.path.exists(w)), "/usr/share/wordlists/rockyou.txt")
        out_file = f"/tmp/ffuf_{datetime.now().strftime('%s')}.json"
        r = subprocess.run([TOOLS["ffuf"], "-u", f"{target}/FUZZ", "-w", wl, "-mc", "200,204,301,302,307,401,403", "-t", "50", "-jsonl", "-o", out_file], capture_output=True, text=True, timeout=300)
        results = []
        try:
            with open(out_file) as f:
                for line in f:
                    try:
                        j = json.loads(line)
                        if "results" in j:
                            for res in j["results"]:
                                results.append({"url": res.get("url", ""), "status": res.get("status", 0)})
                    except:
                        pass
        except Exception as e:
            print(f"[!] Ffuf parse error: {e}")
        self.results["ffuf"] = results
        return results
    
    def full_scan(self, target):
        print(f"\n{'='*50}\nEXECUTION HIVE v5 - {target}\n{'='*50}")
        self.run_nmap(target)
        self.run_nuclei(target)
        self.run_dalfox(target)
        self.run_ffuf(target)
        print(f"\n[*] Total findings: {len(self.results['findings'])}")
        for f in self.results["findings"]:
            print(f"  [{f['severity'].upper()}] {f['type']} @ {f.get('url', target)}")
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python exec_hive.py <target>")
        sys.exit(1)
    hive = ExecutionHive()
    hive.full_scan(sys.argv[1])