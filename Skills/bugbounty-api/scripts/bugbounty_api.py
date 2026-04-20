#!/usr/bin/env python3
import sys
"""
BugCrusher - BugBounty API Integration
HackerOne + Bugcrowd program sync
"""
import requests
import json
import os
from datetime import datetime

class BugBountyAPI:
    def __init__(self):
        self.h1_token = os.environ.get("HACKERONE_API_KEY", "")
        self.bc_token = os.environ.get("BUGCROWD_API_KEY", "")
        self.programs = []
    
    def fetch_hackerone(self):
        if not self.h1_token:
            print("[!] HACKERONE_API_KEY not set in secrets")
            return []
        print("[*] Fetching HackerOne programs...")
        headers = {"Authorization": f"Bearer {self.h1_token}"}
        try:
            resp = requests.get(
                "https://api.hackerone.com/v1/reports",
                headers=headers, timeout=30
            )
            if resp.status_code == 200:
                print(f"[*] HackerOne: {len(resp.json().get('data', []))} reports")
            else:
                print(f"[!] HackerOne API: {resp.status_code}")
        except Exception as e:
            print(f"[!] HackerOne error: {e}")
        return []
    
    def fetch_bugcrowd(self):
        if not self.bc_token:
            print("[!] BUGCROWD_API_KEY not set in secrets")
            return []
        print("[*] Fetching Bugcrowd programs...")
        return []
    
    def add_target(self, program_name, in_scope, out_scope):
        target_entry = {
            "program": program_name,
            "in_scope": in_scope,
            "out_scope": out_scope,
            "added": datetime.now().isoformat()
        }
        self.programs.append(target_entry)
        print(f"[+] Added: {program_name} ({len(in_scope)} targets)")
        return target_entry
    
    def sync_targets(self):
        print("\n[*] Syncing all programs...")
        self.fetch_hackerone()
        self.fetch_bugcrowd()
        return self.programs

if __name__ == "__main__":
    api = BugBountyAPI()
    
    # Demo: add a program manually
    if len(sys.argv) > 1 and sys.argv[1] == "--sync":
        api.sync_targets()
    else:
        print("Usage: python bugbounty_api.py --sync")
        print("\nAdd API keys in Settings > Advanced:")
        print("  HACKERONE_API_KEY")
        print("  BUGCROWD_API_KEY")
        print("\n[*] Demo mode: Adding sample program")
        api.add_target(
            "sample-program",
            ["https://api.sample.com/*", "https://app.sample.com/*"],
            ["https://dev.sample.com/*"]
        )