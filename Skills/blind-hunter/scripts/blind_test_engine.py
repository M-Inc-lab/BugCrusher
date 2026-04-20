#!/usr/bin/env python3
"""
BugCrusher — Blind Test Engine
Autonomous vulnerability testing WITHOUT seeing responses.
Uses timing, status codes, size deltas, and side-channel data.
"""

import sqlite3
import time
import hashlib
import statistics
import json
import urllib.parse
import requests
from datetime import datetime
from typing import Optional, Callable

class BlindTester:
    def __init__(self, target_url: str, db_path: str = "/home/workspace/BugCrusher/vector_db.sqlite"):
        self.target = target_url
        self.db_path = db_path
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*'
        })
        self.baseline = {}
        self.findings = []
        
    def measure_baseline(self, param: str, base_value: str = "test") -> dict:
        """Establish baseline response metrics for a parameter."""
        timings = []
        sizes = []
        statuses = []
        
        for _ in range(5):
            start = time.perf_counter()
            try:
                r = self.session.get(self.target, params={param: base_value}, timeout=10)
                elapsed = time.perf_counter() - start
                timings.append(elapsed)
                sizes.append(len(r.content))
                statuses.append(r.status_code)
            except:
                timings.append(999)
                sizes.append(0)
                statuses.append(0)
        
        self.baseline[param] = {
            'avg_time': statistics.mean(timings),
            'std_time': statistics.stdev(timings) if len(timings) > 1 else 0,
            'avg_size': statistics.mean(sizes),
            'std_size': statistics.stdev(sizes) if len(sizes) > 1 else 0,
            'status': statistics.mode(statuses)
        }
        return self.baseline[param]
    
    def test_payload(self, param: str, payload: str, baseline: dict) -> dict:
        """Test a single payload using blind inference."""
        result = {
            'payload': payload,
            'param': param,
            'confidence': 0.0,
            'indicators': [],
            'type_guesses': []
        }
        
        try:
            start = time.perf_counter()
            r = self.session.get(self.target, params={param: payload}, timeout=15)
            elapsed = time.perf_counter() - start
            size = len(r.content)
            status = r.status_code
            
            # Indicator 1: Response time anomaly (for time-based blind injection)
            if elapsed > baseline['avg_time'] + (3 * baseline['std_time']) + 2:
                result['indicators'].append(f"TIME_ANOMALY: {elapsed:.2f}s (baseline: {baseline['avg_time']:.2f}s)")
                result['confidence'] += 0.4
                result['type_guesses'].append('TIME_BLIND_SQLi')
            
            # Indicator 2: Status code deviation
            if status != baseline['status']:
                result['indicators'].append(f"STATUS_CHANGE: {status} (baseline: {baseline['status']})")
                result['confidence'] += 0.25
                result['type_guesses'].append(f'HTTP_{status}')
            
            # Indicator 3: Size anomaly
            size_delta = abs(size - baseline['avg_size'])
            if size_delta > baseline['std_size'] * 3 + 100:
                result['indicators'].append(f"SIZE_ANOMALY: {size} bytes (delta: {size_delta})")
                result['confidence'] += 0.2
                result['type_guesses'].append('DATA_LEAK')
            
            # Indicator 4: Known error signatures in response
            error_sigs = [
                ('sql', 'SQL_SYNTAX_ERROR'),
                ('mysql', 'MYSQL_ERROR'),
                ('postgresql', 'POSTGRES_ERROR'),
                ('syntax', 'SYNTAX_ERROR'),
                ('exception', 'UNHANDLED_EXCEPTION'),
                ('traceback', 'PYTHON_TRACEBACK'),
                ('error', 'GENERIC_ERROR'),
                ('warning', 'PHP_WARNING'),
                ('fatal', 'FATAL_ERROR'),
                ('xss', 'XSS_DETECTED'),
                ('script>', 'XSS_REFLECTED'),
                ('<img', 'XSS_HTML_TAG'),
            ]
            content_lower = r.text.lower()
            for sig, vuln_type in error_sigs:
                if sig in content_lower:
                    result['indicators'].append(f"ERROR_SIG: '{sig}' → {vuln_type}")
                    result['confidence'] = max(result['confidence'], 0.7)
                    if vuln_type not in result['type_guesses']:
                        result['type_guesses'].append(vuln_type)
                    break
            
            # Indicator 5: Header anomalies
            for header in ['X-Powered-By', 'Server', 'X-AspNet-Version']:
                if header in r.headers:
                    result['indicators'].append(f"HEADER_LEAK: {header}={r.headers[header]}")
            
            result['confidence'] = min(1.0, result['confidence'])
            
        except requests.exceptions.Timeout:
            result['indicators'].append("TIMEOUT — possible time-based blind injection")
            result['confidence'] = 0.6
            result['type_guesses'].append('TIME_BLIND_INJECTION')
        except Exception as e:
            result['indicators'].append(f"ERROR: {str(e)[:50]}")
            
        return result
    
    def run_blind_scan(self, params: list, categories: list = None) -> list:
        """Run blind scan across parameters using all relevant vectors."""
        conn = sqlite3.connect(self.db_path)
        
        query = "SELECT * FROM vectors WHERE fitness_score >= 0.3"
        if categories:
            placeholders = ','.join('?' * len(categories))
            query += f" AND category IN ({placeholders})"
            rows = conn.execute(query, categories).fetchall()
        else:
            rows = conn.execute(query).fetchall()
        
        vectors = [dict(r) for r in rows]
        conn.close()
        
        print(f"[*] Testing {len(vectors)} vectors against {len(params)} params on {self.target}")
        print(f"[*] Categories: {categories or 'ALL'}")
        
        all_results = []
        
        for param in params:
            print(f"\n[*] Establishing baseline for param: {param}")
            baseline = self.measure_baseline(param)
            print(f"[*] Baseline: {baseline['avg_time']:.3f}s, {baseline['avg_size']} bytes, status={baseline['status']}")
            
            for vec in vectors:
                result = self.test_payload(param, vec['payload'], baseline)
                result['vector_id'] = vec['id']
                result['category'] = vec['category']
                result['fitness'] = vec['fitness_score']
                
                if result['confidence'] >= 0.4:
                    self.findings.append(result)
                    print(f"  [!] FINDING [{result['confidence']:.0%}] {vec['category']}: {vec['payload'][:40]}...")
                    for ind in result['indicators']:
                        print(f"      → {ind}")
                
                all_results.append(result)
        
        return all_results
    
    def save_findings(self, session_id: str):
        """Persist findings to database."""
        conn = sqlite3.connect(self.db_path)
        for f in self.findings:
            finding_id = hashlib.md5(f"{session_id}{f['payload']}{f['param']}".encode()).hexdigest()[:12]
            conn.execute("""
                INSERT OR REPLACE INTO findings 
                (id, session_id, vector_id, vulnerability_type, severity, target_url, target_param, PoC_request, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id, session_id, f.get('vector_id', ''),
                '/'.join(f['type_guesses']) or 'UNKNOWN',
                'CRITICAL' if f['confidence'] >= 0.7 else 'MEDIUM',
                self.target, f['param'], f['payload'], f['confidence']
            ))
        conn.commit()
        conn.close()
        print(f"[*] Saved {len(self.findings)} findings to DB")

def run_quick_blind_test(target_url: str, params: list, categories: list = None) -> list:
    """One-shot blind test. Usage: python blind_test_engine.py <url> <param1,param2> [cat1,cat2]"""
    tester = BlindTester(target_url)
    results = tester.run_blind_scan(params, categories)
    session_id = hashlib.md5(target.encode()).hexdigest()[:8]
    tester.save_findings(session_id)
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python blind_test_engine.py <url> <param1,param2> [XSS,SQLi,SSRF,...]")
        print("Example: python blind_test_engine.py http://target.com/search q,query,search XSS,SQLi")
        sys.exit(1)
    
    target = sys.argv[1]
    params = sys.argv[2].split(',')
    categories = sys.argv[3].split(',') if len(sys.argv) > 3 else None
    
    print(f"[*] BugCrusher Blind Test Engine")
    print(f"[*] Target: {target}")
    print(f"[*] Params: {params}")
    print(f"[*] Categories: {categories or 'ALL'}")
    
    results = run_quick_blind_test(target, params, categories)
    print(f"\n[*] Scan complete. Tested {len(results)} combinations.")
