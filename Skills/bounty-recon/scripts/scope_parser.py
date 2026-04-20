#!/usr/bin/env python3
"""
BugCrusher — Program Scope Parser
Parses HackerOne + Bugcrowd program scopes from API/graphQL.
"""

import requests, json, sys, os, argparse
from datetime import datetime

H1_API = "https://api.hackerone.com/v1"
BC_API = "https://bugcrowd.com"

def parse_hackerone(handle: str, api_key: str = None) -> dict:
    """Parse HackerOne program scope."""
    result = {
        "program": handle,
        "platform": "hackerone",
        "asset_types": {"api": [], "web": [], "mobile": [], "code": [], "infrastructure": []},
        "out_of_scope": [],
        "rewards": {},
        "last_activity": None,
        "bounty_availability": True
    }
    try:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        resp = requests.get(f"{H1_API}/programs/{handle}", headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            result["last_activity"] = attrs.get("last_activity_at")
            result["bounty_availability"] = attrs.get("offers_bounties", True)
            # Parse structured scopes
            for asset in attrs.get("structured_scopes", []):
                a = asset.get("asset_identifier", "")
                at = asset.get("asset_type", "").lower()
                in_scope = asset.get("eligible_for_submission", True)
                if in_scope:
                    if "api" in at:
                        result["asset_types"]["api"].append(a)
                    elif "url" in at or "website" in at:
                        result["asset_types"]["web"].append(a)
                    elif "mobile" in at:
                        result["asset_types"]["mobile"].append(a)
                    elif "source" in at or "github" in at:
                        result["asset_types"]["code"].append(a)
                    else:
                        result["asset_types"]["infrastructure"].append(a)
                else:
                    result["out_of_scope"].append(a)
            # Rewards
            for tier in attrs.get("reward_ranges", []):
                sev = tier.get("severity", "").lower()
                result["rewards"][sev] = {"min": tier.get("min_award", 0), "max": tier.get("max_award", 0)}
    except Exception as e:
        result["error"] = str(e)
    return result

def parse_bugcrowd(handle: str) -> dict:
    """Parse Bugcrowd program scope via web scraping + API."""
    result = {
        "program": handle,
        "platform": "bugcrowd",
        "asset_types": {"api": [], "web": [], "mobile": [], "code": [], "infrastructure": []},
        "out_of_scope": [],
        "rewards": {},
        "last_activity": None,
        "bounty_availability": True
    }
    try:
        resp = requests.get(f"{BC_API}/api/v1/programs/{handle}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            result["bounty_availability"] = data.get("bounty_available", True)
            result["last_activity"] = data.get("last_activity")
            for asset in data.get("targets", []):
                a = asset.get("url", "")
                at = asset.get("category", "").lower()
                in_scope = asset.get("in_scope", True)
                if in_scope:
                    if "api" in at:
                        result["asset_types"]["api"].append(a)
                    elif "web" in at:
                        result["asset_types"]["web"].append(a)
                    elif "mobile" in at:
                        result["asset_types"]["mobile"].append(a)
                    else:
                        result["asset_types"]["infrastructure"].append(a)
                else:
                    result["out_of_scope"].append(a)
    except Exception as e:
        result["error"] = str(e)
    return result

if __name__ == '__main__':
    p = argparse.ArgumentParser(description="BugCrusher Scope Parser")
    p.add_argument("--platform", "--program", dest="platform", choices=["hackerone", "bugcrowd"], required=True)
    p.add_argument("--handle", required=True, help="Program handle (e.g. 'shopify')")
    p.add_argument("--api-key", default=os.environ.get("HACKERONE_API_KEY"))
    p.add_argument("--output", choices=["json", "text"], default="json")
    args = p.parse_args()
    if "hackerone" in args.platform:
        r = parse_hackerone(args.handle, args.api_key)
    else:
        r = parse_bugcrowd(args.handle)
    if args.output == "json":
        print(json.dumps(r, indent=2))
    else:
        print(f"Program: {r['program']} ({r['platform']})")
        print(f"Bounty Available: {r['bounty_availability']}")
        print(f"\nIn-Scope Assets:")
        for cat, assets in r['asset_types'].items():
            if assets:
                print(f"  [{cat.upper()}]")
                for a in assets:
                    print(f"    - {a}")
        print(f"\nOut-of-Scope ({len(r['out_of_scope'])}):")
        for a in r['out_of_scope'][:10]:
            print(f"  - {a}")
        print(f"\nRewards: {r['rewards']}")
