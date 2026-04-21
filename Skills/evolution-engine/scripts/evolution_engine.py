#!/usr/bin/env python3
"""
EVOLUTION-ENGINE — Autonomous Exploit Breeding
Run: python3 Skills/evolution-engine/scripts/evolution_engine.py <action>
Actions: breed, mutate, crossover, fitness, prune
"""
import sqlite3, random, hashlib, datetime, sys

DB_PATH = "/home/workspace/BugCrusher/vector_db.sqlite"

MUTATIONS = [
    ('substitution', ['<script>', '<img src=x>', '"><script>', '\x00', '%00', '{{}}']),
    ('recombination', ['shuffle', 'swap', 'duplicate', 'reverse']),
    ('generation', ['llm-generated']),
    ('crossover', ['single', 'double', 'uniform']),
    ('encoding', ['url', 'html', 'unicode', 'base64', 'hex'])
]

def load_vectors():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn.execute("SELECT * FROM vectors ORDER BY fitness_score DESC LIMIT 100").fetchall()

def mutate_payload(payload, strategy):
    if strategy == 'substitution':
        for old, new in [('<', '%3c'), ('>', '%3e'), ('"', '%22'), ("'", '%27')]:
            if old in payload:
                return payload.replace(old, new)
    elif strategy == 'encoding':
        return payload.encode('utf-8').hex()
    elif strategy == 'recombination':
        parts = payload.split('\x00')
        random.shuffle(parts)
        return '\x00'.join(parts)
    return payload + "_mutated"

def breed(parent_id, payload, category):
    strategy = random.choice(MUTATIONS)[0]
    new_payload = mutate_payload(payload, strategy)
    new_id = f"evolved_{hashlib.md5((new_payload + str(datetime.datetime.now())).encode()).hexdigest()[:12]}"
    
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""INSERT INTO vectors VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (new_id, new_payload, category, category, 'payload', 'plain', None, 5.0, None, 0, 0.7, 0, 0,
         None, datetime.datetime.now().isoformat(), 'evolution', None, None,
         hashlib.md5(new_payload.encode()).hexdigest(), parent_id, 2, strategy, 'bred', 'system'))
    conn.commit()
    conn.close()
    return new_id

def crossover(vec1, vec2):
    p1, p2 = vec1['payload'], vec2['payload']
    mid = len(p1) // 2
    new = p1[:mid] + p2[mid:]
    return new

def update_fitness(vector_id, success):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT fitness_score, success_count, failure_count FROM vectors WHERE id=?", (vector_id,)).fetchone()
    if row:
        fs, sc, fc = row
        sc = sc + 1 if success else sc
        fc = fc + 1 if not success else fc
        new_fs = sc / (sc + fc + 1)
        conn.execute("UPDATE vectors SET fitness_score=?, success_count=?, failure_count=? WHERE id=?", 
                     (new_fs, sc, fc, vector_id))
        conn.commit()
    conn.close()

def prune_weak():
    conn = sqlite3.connect(DB_PATH)
    removed = conn.execute("DELETE FROM vectors WHERE fitness_score < 0.2 AND failure_count > 3").rowcount
    conn.commit()
    conn.close()
    return removed

def main():
    action = sys.argv[1] if len(sys.argv) > 1 else 'breed'
    
    if action == 'breed':
        vectors = load_vectors()
        if vectors:
            v = random.choice(vectors)
            new_id = breed(v['id'], v['payload'], v['category'])
            print(f"[+] Bred: {new_id}")
        else:
            print("[!] No vectors to breed")
    
    elif action == 'mutate':
        vectors = load_vectors()
        if vectors:
            v = random.choice(vectors)
            new_payload = mutate_payload(v['payload'], random.choice(MUTATIONS)[0])
            print(f"[*] Mutated: {new_payload[:80]}")
    
    elif action == 'fitness':
        vectors = load_vectors()
        print(f"Top 10 by fitness:")
        for v in vectors[:10]:
            print(f"  {v['id'][:30]}: {v['fitness_score']:.3f}")
    
    elif action == 'prune':
        removed = prune_weak()
        print(f"[*] Pruned {removed} weak vectors")
    
    elif action == 'crossover':
        vectors = load_vectors()
        if len(vectors) >= 2:
            v1, v2 = random.sample(vectors, 2)
            new = crossover(v1, v2)
            print(f"[*] Crossover: {new[:80]}")
    
    else:
        print("Usage: evolution_engine.py <breed|mutate|fitness|prune|crossover>")
        sys.exit(1)

if __name__ == '__main__':
    main()