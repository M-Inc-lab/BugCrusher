#!/usr/bin/env python3
"""
AUTONOMOUS HUNT AGENT — Scheduled Bug Bounty Hunter
Runs every 4 hours via cron/automation
Usage: python3 hunt_agent.py [target]
"""
import sys, sqlite3, datetime, subprocess, os, hashlib
from pathlib import Path

TARGETS_FILE = "/home/workspace/BugCrusher/targets.md"
VECTOR_DB = "/home/workspace/BugCrusher/vector_db.sqlite"
HUNT_STATS_DB = "/home/workspace/BugCrusher/hunt_stats.db"
REPORTS_DIR = "/home/workspace/BugCrusher/hunt_reports"

class HuntAgent:
    def __init__(self):
        self.session_id = hashlib.sha256(str(datetime.datetime.now().timestamp()).encode()).hexdigest()[:12]
        self.start = datetime.datetime.now()
        self.hunt_id = None
    
    def log_hunt(self, target, p1=0, p2=0, p3=0, bounty=0.0, worm_status="CLEAN"):
        conn = sqlite3.connect(HUNT_STATS_DB)
        conn.execute("""INSERT INTO hunts (target, session_id, date, p1_count, p2_count, p3_count, bounty_est, worm_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (target, self.session_id, self.start.isoformat(), p1, p2, p3, bounty, worm_status))
        conn.commit()
        self.hunt_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
    
    def get_next_target(self):
        with open(TARGETS_FILE) as f:
            content = f.read()
        for line in content.split('\n'):
            if 'in-scope:' in line:
                target = line.split('in-scope:')[1].split(',')[0].strip()
                return target
        return None
    
    def run_hunt(self, target):
        print(f"[*] Starting hunt: {target}")
        # Import and run hunt engine
        sys.path.insert(0, '/home/workspace/BugCrusher')
        try:
            from hunt_engine import BugCrusher
            hunter = BugCrusher()
            hunter.target = target
            hunter.recon(target)
            findings = hunter.scan(target)
            print(f"[*] Found {len(findings)} vulnerabilities")
            return findings
        except Exception as e:
            print(f"[!] Hunt failed: {e}")
            return []
    
    def generate_report(self, target, findings):
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = f"{REPORTS_DIR}/{target.replace('.', '_')}_{timestamp}.md"
        p1 = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        p2 = sum(1 for f in findings if f.get('severity') == 'HIGH')
        p3 = sum(1 for f in findings if f.get('severity') in ['MEDIUM', 'LOW'])
        
        with open(report_path, 'w') as f:
            f.write(f"# Hunt Report: {target}\n\n")
            f.write(f"**Date:** {self.start.isoformat()}\n")
            f.write(f"**Session:** {self.session_id}\n")
            f.write(f"**Findings:** {len(findings)}\n\n")
            f.write(f"| Severity | Count |\n|---------|-------|\n")
            f.write(f"| P1/Critical | {p1} |\n")
            f.write(f"| P2/High | {p2} |\n")
            f.write(f"| P3/Low | {p3} |\n")
        print(f"[*] Report: {report_path}")
        return report_path, p1, p2, p3
    
    def main(self):
        target = self.get_next_target()
        if not target:
            print("[!] No targets found in targets.md")
            sys.exit(1)
        
        findings = self.run_hunt(target)
        _, p1, p2, p3 = self.generate_report(target, findings)
        
        bounty = p1 * 10000 + p2 * 4000 + p3 * 500
        self.log_hunt(target, p1, p2, p3, bounty)
        print(f"[*] Hunt complete: P1={p1}, P2={p2}, P3={p3}, Est. Bounty=${bounty}")

if __name__ == '__main__':
    agent = HuntAgent()
    agent.main()