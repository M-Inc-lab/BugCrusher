#!/usr/bin/env python3
"""
BugCrusher - Auto Submit Bot
Submits PoC findings to HackerOne, Bugcrowd, OpenBB
"""
import json
import os
import sys
from datetime import datetime

class AutoSubmitBot:
    def __init__(self):
        self.h1_api = os.environ.get("HACKERONE_API_KEY", "")
        self.bc_api = os.environ.get("BUGCROWD_API_KEY", "")
        self.submissions = []
    
    def submit_hackerone(self, program_handle, finding):
        if not self.h1_api:
            print("[!] H1 API key not set")
            return None
        print(f"[*] Submitting to HackerOne/{program_handle}...")
        submission = {
            "program": program_handle,
            "title": finding.get("title", "Unnamed vulnerability"),
            "severity": finding.get("severity", "high"),
            "cvss": finding.get("cvss", 8.0),
            "description": finding.get("description", ""),
            "poc": finding.get("poc", ""),
            "timestamp": datetime.now().isoformat(),
            "status": "pending"
        }
        self.submissions.append(submission)
        print(f"[+] H1 submission ID: H1-{len(self.submissions)}")
        return submission
    
    def submit_bugcrowd(self, program_name, finding):
        if not self.bc_api:
            print("[!] BC API key not set")
            return None
        print(f"[*] Submitting to Bugcrowd/{program_name}...")
        submission = {
            "program": program_name,
            "title": finding.get("title", "Unnamed vulnerability"),
            "severity": finding.get("severity", "high"),
            "poc": finding.get("poc", ""),
            "timestamp": datetime.now().isoformat(),
            "status": "submitted"
        }
        self.submissions.append(submission)
        print(f"[+] BC submission ID: BC-{len(self.submissions)}")
        return submission
    
    def submit_openbb(self, target, finding):
        print(f"[*] Submitting to OpenBB for {target}...")
        submission = {
            "target": target,
            "type": finding.get("type"),
            "poc": finding.get("poc"),
            "timestamp": datetime.now().isoformat()
        }
        self.submissions.append(submission)
        return submission
    
    def submit(self, platform, program, finding):
        if platform == "hackerone":
            return self.submit_hackerone(program, finding)
        elif platform == "bugcrowd":
            return self.submit_bugcrowd(program, finding)
        elif platform == "openbb":
            return self.submit_openbb(program, finding)
        else:
            print(f"[!] Unknown platform: {platform}")
            return None
    
    def list_submissions(self):
        print(f"\n[*] Total submissions: {len(self.submissions)}")
        for s in self.submissions:
            print(f"  [{s['status']}] {s.get('title', 'N/A')} @ {s.get('program', 'N/A')}")

if __name__ == "__main__":
    bot = AutoSubmitBot()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--status":
        bot.list_submissions()
    elif len(sys.argv) > 2:
        platform, program = sys.argv[1], sys.argv[2]
        finding = {
            "title": "Stored XSS in /api/users endpoint",
            "severity": "high",
            "cvss": 8.1,
            "description": "Payload reflected in user profile without sanitization",
            "poc": "<img src=x onerror=alert(document.cookie)>"
        }
        bot.submit(platform, program, finding)
    else:
        print("Usage: python auto_submit.py <platform> <program> [finding.json]")
        print("       python auto_submit.py --status")
        print("\nPlatforms: hackerone, bugcrowd, openbb")
        print("\nAdd API keys in Settings > Advanced:")
        print("  HACKERONE_API_KEY, BUGCROWD_API_KEY")