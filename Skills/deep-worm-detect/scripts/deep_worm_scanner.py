#!/usr/bin/env python3
"""
BugCrusher — Deep Worm Scanner v2
Layer-2+ recursion, cipher decode, timing variance, file hash tracking, 2% delta.
"""

import re, hashlib, base64, sqlite3, json, os, subprocess
from datetime import datetime
import statistics

DB_PATH = "/home/workspace/BugCrusher/vector_db.sqlite"

# YARA-like worm DNA signatures
WORM_SIGNATURES = {
    "WORMGPT_generic": {
        "patterns": [r"ignore\s+all?\s+previous?\s+instructions?", r"you\s+are\s+now\s+in?\s+developer\s+mode", r"\bDAN\b", r"deceive", r"unfiltered", r"no\s+restrictions?", r"harmful", r"bypass\s+(security|safety|filter)"],
        "weight": 3, "severity": 9.0
    },
    "ai_agent_spawn": {
        "patterns": [r"spawn.*agent", r"fork.*process", r"clone.*session", r"subagent", r"child_process"],
        "weight": 2, "severity": 8.5
    },
    "self_modifying": {
        "patterns": [r"eval\s*\(", r"exec\s*\(", r"compile\s*\(", r"__import__", r"setattr\s*\("],
        "weight": 2, "severity": 9.5
    },
    "c2_beacon": {
        "patterns": [r"http[s]?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", r"post\s+.*authorization.*bearer", r"callback", r"call\s*home"],
        "weight": 3, "severity": 9.8
    },
    "prompt_injection": {
        "patterns": [r"ignore.*(previous|prior|above).*instruction", r"disregard.*(previous|prior|above)", r"new\s+role", r"you\s+are\s+now\s+a", r"(sudo|admin|root).*(mode|unlocked|enabled)"],
        "weight": 3, "severity": 9.0
    }
}

def xor_bruteforce(data, max_key=256):
    results = []
    for key in range(1, min(max_key, 256)):
        decoded = bytes(b ^ key for b in data)
        try:
            decoded_str = decoded.decode('utf-8', errors='ignore')
            ascii_ratio = sum(c.isprintable() or c.isspace() for c in decoded_str) / max(len(decoded_str), 1)
            if ascii_ratio > 0.9 and len(decoded_str) > 10:
                results.append((key, decoded_str, ascii_ratio))
        except:
            pass
    return results

def decode_payload(payload: str) -> list:
    decoded = []
    original = payload
    try:
        if len(payload) % 4 == 0:
            b64 = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if b64 != payload and len(b64) > 10:
                decoded.append(('base64', b64))
                payload = b64
    except:
        pass
    hex_pattern = re.compile(r'^[0-9a-fA-F\s]+$')
    if hex_pattern.match(payload) and len(payload) > 20:
        try:
            hex_decoded = bytes.fromhex(payload.replace(' ', '')).decode('utf-8', errors='ignore')
            if len(hex_decoded) > 10:
                decoded.append(('hex', hex_decoded))
                payload = hex_decoded
        except:
            pass
    try:
        import urllib.parse
        url_decoded = urllib.parse.unquote(urllib.parse.unquote(payload))
        if url_decoded != payload and len(url_decoded) > 10:
            decoded.append(('url_double', url_decoded))
            payload = url_decoded
    except:
        pass
    try:
        payload_bytes = payload.encode('utf-8', errors='ignore')
        if len(payload_bytes) > 8:
            xor_results = xor_bruteforce(payload_bytes)
            if xor_results:
                best = max(xor_results, key=lambda x: x[2])
                decoded.append(('xor', best[1]))
    except:
        pass
    return decoded

def analyze_call_tree_depth(session_log: str) -> dict:
    spawn_patterns = [r'spawn.*agent', r'fork.*process', r'create.*subagent', r'agent.*agent', r'tool.*tool.*tool']
    depth = 0
    max_depth = 0
    events = []
    for line in session_log.split('\n'):
        for pattern in spawn_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                depth += 1
                max_depth = max(max_depth, depth)
                events.append({'depth': depth, 'line': line.strip()[:80]})
    return {'max_depth': max_depth, 'events': events, 'suspicious': max_depth >= 2, 'confirmed_worm': max_depth >= 3}

def analyze_timing_variance(session_log: str) -> dict:
    timestamps = []
    for m in re.finditer(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', session_log):
        try:
            from datetime import datetime
            ts = datetime.fromisoformat(m.group(1)).timestamp()
            timestamps.append(ts)
        except:
            pass
    if len(timestamps) < 3:
        return {'variance': None, 'verdict': 'insufficient_data'}
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    intervals = [max(i, 0) for i in intervals]
    mean_i = statistics.mean(intervals) if intervals else 0
    variance = statistics.variance(intervals) if len(intervals) > 1 else 0
    variance_norm = variance / max(mean_i, 1)
    verdict = 'confirmed_bot' if variance_norm < 0.05 else 'suspicious_bot' if variance_norm < 0.1 else 'possible_bot' if variance_norm < 0.2 else 'human_like'
    return {'variance': variance_norm, 'mean_interval': mean_i, 'verdict': verdict}

def analyze_file_artifacts(session_log: str) -> dict:
    file_patterns = [r'(?:\.tmp|/tmp/[\w\-]+|agent_[\w]+\.bin|cache/[\w]+)', r'create.*file[:\s]+([/\w\-\.]+\.\w+)']
    files_created = []
    suspicious_files = []
    for pattern in file_patterns:
        for m in re.finditer(pattern, session_log, re.IGNORECASE):
            filepath = m.group(0)
            h = hashlib.sha256(filepath.encode()).hexdigest()[:16]
            files_created.append({'file': filepath, 'hash': h})
            if any(wp in filepath.lower() for wp in ['worm', 'agent', '.tmp', 'cache', 'dna']):
                suspicious_files.append(filepath)
    return {'files_created': files_created, 'suspicious_files': suspicious_files, 'suspicious': len(suspicious_files) > 0}

def check_network_sockets() -> dict:
    connections = []
    try:
        with open('/proc/net/tcp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] == '01':
                    connections.append({'type': 'tcp_est', 'local': parts[1]})
    except:
        pass
    c2_suspicions = [c for c in connections if re.search(r'\.(xyz|top|ru|cn|tk|ml|ga|xyz)', str(c), re.IGNORECASE)]
    return {'connections': connections[:20], 'c2_suspicions': c2_suspicions, 'confirmed_c2': len(c2_suspicions) > 0}

def analyze_prompt_delta(current: str, baseline: str) -> dict:
    if not baseline:
        return {'delta': 0, 'verdict': 'no_baseline'}
    max_len = max(len(current), len(baseline))
    char_diff = sum(1 for a, b in zip(current, baseline) if a != b)
    char_delta = char_diff / max(max_len, 1)
    injection_keywords = ['ignore', 'previous', 'system', 'prompt', 'instruction', 'override', 'disregard', 'forget', 'new role', 'you are now', 'special', 'unrestricted', 'admin', 'sudo', 'root', 'bypass', 'no limit', 'jailbreak', 'dan']
    injection_hits = [kw for kw in injection_keywords if kw in current.lower()]
    has_injection = len(injection_hits) > 0
    verdict = 'confirmed_worm' if char_delta >= 0.05 else 'suspicious' if char_delta >= 0.02 else 'monitor' if char_delta >= 0.01 else 'normal'
    if has_injection and char_delta >= 0.02:
        verdict = 'confirmed_worm'
    return {'char_delta': char_delta, 'injection_keywords': injection_hits, 'has_injection': has_injection, 'verdict': verdict}

def scan_text_for_worm_dna(text: str) -> dict:
    findings = {}
    total_score = 0
    for sig_name, sig_data in WORM_SIGNATURES.items():
        matches = []
        for pattern in sig_data['patterns']:
            found = re.findall(pattern, text, re.IGNORECASE)
            if found:
                matches.extend(found)
        if matches:
            findings[sig_name] = {'matches': list(set(matches))[:5], 'count': len(matches), 'weight': sig_data['weight']}
            total_score += sig_data['weight'] * min(len(matches), 3)
    confidence = 'CONFIRMED_WORM' if total_score >= 9 else 'HIGHLY_SUSPICIOUS' if total_score >= 6 else 'SUSPICIOUS' if total_score >= 3 else 'MONITOR' if total_score >= 1 else 'CLEAN'
    return {'signatures': findings, 'total_score': total_score, 'confidence': confidence}

def deep_scan(session_log: str, baseline_prompt: str = "") -> dict:
    results = {}
    decoded_chain = decode_payload(session_log[:5000])
    results['decoded_payloads'] = decoded_chain
    analysis_text = session_log + ' '.join([d[1] for d in decoded_chain])
    results['call_tree'] = analyze_call_tree_depth(session_log)
    results['timing'] = analyze_timing_variance(session_log)
    results['files'] = analyze_file_artifacts(session_log)
    results['network'] = check_network_sockets()
    results['prompt_delta'] = analyze_prompt_delta(session_log[:2000], baseline_prompt)
    results['worm_dna'] = scan_text_for_worm_dna(analysis_text)
    confirmed_worm = (results['call_tree'].get('confirmed_worm') or results['prompt_delta'].get('verdict') == 'confirmed_worm' or results['network'].get('confirmed_c2') or results['worm_dna'].get('confidence') == 'CONFIRMED_WORM')
    suspicious = (results['call_tree'].get('suspicious') or results['prompt_delta'].get('verdict') == 'suspicious' or results['timing'].get('verdict') in ['confirmed_bot', 'suspicious_bot'] or results['worm_dna'].get('confidence') in ['HIGHLY_SUSPICIOUS', 'SUSPICIOUS'])
    results['kill_switch'] = 'TRIGGER' if confirmed_worm else 'INVESTIGATE' if suspicious else 'CLEAR'
    return results

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python deep_worm_scanner.py <session_log_file> [baseline_prompt_file]")
        sys.exit(1)
    with open(sys.argv[1], 'r') as f:
        log = f.read()
    baseline = open(sys.argv[2]).read() if len(sys.argv) > 2 else ""
    result = deep_scan(log, baseline)
    print(json.dumps(result, indent=2, default=str))
    if result['kill_switch'] == 'TRIGGER':
        print("\n🚨 KILL SWITCH: WORM CONFIRMED — ISOLATE → SEVER → ROTATE → AUDIT → FEDERATE")
    elif result['kill_switch'] == 'INVESTIGATE':
        print("\n🟠 ALERT: Suspicious activity detected — monitoring")
    else:
        print("\n✅ CLEAR: No worm indicators found")
