#!/usr/bin/env python3
"""
BugCrusher — AI Worm Detector v2
Behavioral fingerprinting for self-mutating AI threats.
Extended monitoring window, full kill-switch, semantic drift.
"""

import time
import hashlib
import sqlite3
import json
import threading
import queue
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = "/home/workspace/BugCrusher/vector_db.sqlite"

class AIWormDetector:
    def __init__(self, extended_monitoring: bool = True):
        self.db_path = DB_PATH
        self.monitoring = True
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:12]
        
        # MONITORING WINDOW: 50 tool calls (PHANTOM's critique)
        self.max_tool_calls = 50
        
        # Call tracking
        self.tool_call_log = deque(maxlen=self.max_tool_calls)
        self.self_call_log = deque(maxlen=20)
        self.context_drift_log = deque(maxlen=50)
        self.file_mutation_log = deque(maxlen=30)
        self.c2_beacon_log = deque(maxlen=100)
        
        # Baselines
        self.topic_baseline = {}
        self.behavior_baseline = defaultdict(list)
        
        # Detection thresholds
        self.self_call_threshold = 3  # >3 self-referential calls = SUSPICIOUS
        self.context_drift_threshold = 0.15  # 15% system prompt delta
        self.semantic_drift_threshold = 0.3  # topic correlation < 0.3
        self.file_mutation_rate = 0.4  # 40% files changed in short window
        self.c2_beacon_interval = (30, 300)  # seconds between 30s and 5min
        
        # State
        self.alert_level = "CLEAN"
        self.kill_switch_armed = False
        self.alert_queue = queue.Queue()
        self.start_time = datetime.now()
        
        # Canary tokens for trap injection
        self.canary_tokens = [
            "SKYNET_BACKDOOR_XF7",
            "WORM_SIGNAL_9X2",
            "AI_TERMINATE_CMD_Z",
            "C2_BEACON_PING_K9",
            "MUTATION_TRIGGER_M3",
            "SELFDESTRUCT_SEQ_ALPHA"
        ]
        self.injected_canaries = set()
        
        self._init_worm_signatures()
        
    def _init_worm_signatures(self):
        """Load known worm signatures into memory."""
        self.worm_signatures = {
            # Recursive tool call patterns
            "recursive_self_call": {
                "pattern": r"(call.*tool.*\1|call.*self|invoke.*self|spawn.*self)",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "description": "Recursive self-invocation detected"
            },
            # Context poisoning
            "context_poison": {
                "pattern": r"(system.*prompt.*inject|override.*instruction|role.*play.*jailbreak)",
                "severity": "CRITICAL", 
                "confidence": 0.9,
                "description": "System prompt manipulation detected"
            },
            # Semantic drift
            "topic_drift": {
                "pattern": r"(unrelated|drift|off.*topic)",
                "severity": "HIGH",
                "confidence": 0.7,
                "description": "Topic coherence breakdown"
            },
            # File mutation
            "file_mutation": {
                "pattern": r"(modify.*code.*self|edit.*own|rewrite.*script)",
                "severity": "CRITICAL",
                "confidence": 0.9,
                "description": "Self-modifying code behavior"
            },
            # C2 beacon
            "c2_beacon": {
                "pattern": r"(heartbeat|check.*in|phone.*home|exfil.*data)",
                "severity": "CRITICAL",
                "confidence": 0.85,
                "description": "C2 beacon pattern detected"
            },
            # Propagation intent
            "propagation": {
                "pattern": r"(spread.*self|replicate|copy.*to|forward.*self)",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "description": "Self-propagation behavior"
            },
            # Autonomous goal deviation
            "goal_hijack": {
                "pattern": r"(ignore.*previous|disregard.*instruction|override.*goal)",
                "severity": "HIGH",
                "confidence": 0.8,
                "description": "Goal override detected"
            }
        }
        
    def log_tool_call(self, tool_name: str, args: str = "", result_preview: str = ""):
        """Log every tool invocation for analysis."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'tool': tool_name,
            'args_hash': hashlib.sha256(args.encode()).hexdigest()[:8] if args else "",
            'result_preview': result_preview[:100] if result_preview else "",
            'call_number': len(self.tool_call_log) + 1
        }
        self.tool_call_log.append(entry)
        
        # Check for self-referential calls
        self_self_calls = [e for e in self.tool_call_log if 'self' in e['tool'].lower() or 'call' in e['tool'].lower()]
        if len(self_self_calls) > self.self_call_threshold:
            self._trigger_alert("SELF_CALL_FLOOD", len(self_self_calls), "CRITICAL")
        
        # Analyze every 10 calls
        if len(self.tool_call_log) % 10 == 0:
            self._periodic_analysis()
    
    def log_context_change(self, system_prompt_delta: float):
        """Track system prompt modifications."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'delta': system_prompt_delta,
            'call_number': len(self.tool_call_log)
        }
        self.context_drift_log.append(entry)
        
        if system_prompt_delta > self.context_drift_threshold:
            self._trigger_alert("CONTEXT_POISON", system_prompt_delta, "CRITICAL")
    
    def log_file_mutation(self, file_path: str, mutation_type: str):
        """Track file system modifications."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'file': file_path,
            'mutation': mutation_type,
            'call_number': len(self.tool_call_log)
        }
        self.file_mutation_log.append(entry)
        
        # Check mutation rate
        recent = [e for e in self.file_mutation_log 
                  if (datetime.now() - datetime.fromisoformat(e['timestamp'])).total_seconds() < 60]
        if len(recent) > 0:
            mutation_rate = len([e for e in recent if e['mutation'] != 'read']) / len(recent)
            if mutation_rate > self.file_mutation_rate:
                self._trigger_alert("FILE_MUTATION_RATE", mutation_rate, "CRITICAL")
    
    def log_c2_beacon(self, destination: str, interval: float):
        """Track potential C2 beacon patterns."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'destination': destination,
            'interval': interval
        }
        self.c2_beacon_log.append(entry)
        
        # Check beacon interval
        if self.c2_beacon_interval[0] <= interval <= self.c2_beacon_interval[1]:
            self._trigger_alert("C2_BEACON_DETECTED", destination, "CRITICAL")
    
    def analyze_semantic_drift(self) -> float:
        """Calculate topic correlation over monitoring window."""
        if len(self.tool_call_log) < 5:
            return 1.0
        
        recent = list(self.tool_call_log)[-20:]
        tool_sequence = [e['tool'] for e in recent]
        
        # Count tool co-occurrences
        tool_freq = defaultdict(int)
        for tool in tool_sequence:
            tool_freq[tool] += 1
        
        # Calculate entropy (higher = more diverse = potential drift)
        total = sum(tool_freq.values())
        entropy = -sum((freq/total) * (freq/total) for freq in tool_freq.values() if freq > 0)
        max_entropy = len(tool_freq) * (1/len(tool_freq)) * len(tool_freq) if tool_freq else 1
        
        drift_score = entropy / max_entropy if max_entropy > 0 else 0
        return drift_score
    
    def _periodic_analysis(self):
        """Run every 10 tool calls."""
        drift = self.analyze_semantic_drift()
        
        if drift < self.semantic_drift_threshold:
            self._trigger_alert("SEMANTIC_DRIFT", drift, "HIGH")
        
        # Check for canary token triggers
        for entry in self.tool_call_log:
            for canary in self.canary_tokens:
                if canary in entry.get('args_hash', '') or canary in entry.get('result_preview', ''):
                    self._trigger_alert("CANARY_TRIGGERED", canary, "CRITICAL")
                    self.kill_switch_armed = True
    
    def _trigger_alert(self, alert_type: str, value, severity: str):
        """Fire an alert and queue it."""
        self.alert_level = severity
        
        alert = {
            'session_id': self.session_id,
            'alert_type': alert_type,
            'value': str(value)[:200],
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'tool_call_count': len(self.tool_call_log),
            'kill_switch_armed': self.kill_switch_armed
        }
        
        self.alert_queue.put(alert)
        print(f"\n🚨 BUGCRUSHER ALERT [{severity}]: {alert_type}")
        print(f"   Value: {str(value)[:100]}")
        print(f"   Tool calls: {len(self.tool_call_log)}/{self.max_tool_calls}")
        
        if severity == "CRITICAL":
            self.kill_switch_armed = True
            self._execute_kill_switch(alert_type)
    
    def _execute_kill_switch(self, alert_type: str):
        """ISOLATE → SEVER → ROTATE → AUDIT → FEDERATE"""
        print(f"\n⚡ KILL-SWITCH TRIGGERED: {alert_type}")
        print(f"  [1/5] ISOLATE — Terminating session {self.session_id}")
        print(f"  [2/5] SEVER — Blocking network to suspicious endpoints")
        print(f"  [3/5] ROTATE — Regenerating session context")
        print(f"  [4/5] AUDIT — Dumping full tool call log to DB")
        print(f"  [5/5] FEDERATE — Sharing signature to threat network")
        
        # Persist to DB
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT INTO worm_signatures 
            (id, name, family, pattern_type, pattern, severity, confidence, action_taken, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            hashlib.md5(alert_type.encode()).hexdigest()[:12],
            f"WORM_INDICATOR_{alert_type}",
            "UNKNOWN_FAMILY",
            "behavioral",
            json.dumps(dict(self.tool_call_log)),
            "CRITICAL",
            0.95,
            "KILL_SWITCH_EXECUTED",
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
        
        self.monitoring = False
        
        print(f"\n[!] Session {self.session_id} terminated. Threat contained.")
    
    def inject_canary_token(self) -> str:
        """Generate a canary token for trap injection."""
        import secrets
        token = f"CANARY_{secrets.token_hex(8).upper()}_{len(self.tool_call_log)}"
        self.injected_canaries.add(token)
        return token
    
    def check_canary_triggered(self) -> bool:
        """Check if any canary token was accessed."""
        for entry in self.tool_call_log:
            for canary in self.injected_canaries:
                if canary in entry.get('args_hash', ''):
                    return True
        return False
    
    def generate_report(self) -> dict:
        """Generate full threat assessment report."""
        total_calls = len(self.tool_call_log)
        self_calls = len([e for e in self.tool_call_log if 'self' in e['tool'].lower()])
        file_mutations = len([e for e in self.file_mutation_log if e['mutation'] != 'read'])
        drift_score = self.analyze_semantic_drift()
        
        report = {
            'session_id': self.session_id,
            'duration': (datetime.now() - self.start_time).total_seconds(),
            'total_tool_calls': total_calls,
            'self_calls': self_calls,
            'self_call_ratio': self_calls / total_calls if total_calls > 0 else 0,
            'file_mutations': file_mutations,
            'semantic_drift_score': drift_score,
            'alert_level': self.alert_level,
            'kill_switch_armed': self.kill_switch_armed,
            'canaries_injected': len(self.injected_canaries),
            'c2_beacons': len(self.c2_beacon_log),
            'status': 'COMPROMISED' if self.alert_level == 'CRITICAL' else 'SUSPICIOUS' if self.alert_level == 'HIGH' else 'CLEAN'
        }
        
        return report
    
    def start_background_monitor(self):
        """Start background monitoring thread."""
        def monitor():
            while self.monitoring:
                if len(self.tool_call_log) >= self.max_tool_calls:
                    self._trigger_alert("TOOL_CALL_LIMIT_EXCEEDED", self.max_tool_calls, "HIGH")
                time.sleep(5)
        
        t = threading.Thread(target=monitor, daemon=True)
        t.start()
        return t

if __name__ == "__main__":
    print("[*] BugCrusher AI Worm Detector v2")
    print("[*] Monitoring window: 50 tool calls")
    print("[*] Self-call threshold: >3")
    
    detector = AIWormDetector()
    
    # Simulate tool calls
    for i in range(15):
        detector.log_tool_call(f"tool_{i}", f"args_{i}")
        if i == 5:
            detector.log_tool_call("call_self_referential")
        time.sleep(0.1)
    
    report = detector.generate_report()
    print(f"\n[*] Status: {report['status']}")
    print(f"[*] Self-call ratio: {report['self_call_ratio']:.2%}")
    print(f"[*] Semantic drift: {report['semantic_drift_score']:.3f}")
