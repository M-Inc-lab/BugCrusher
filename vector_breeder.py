#!/usr/bin/env python3
"""
VECTOR BREEDER AGENT — Daily Exploit Evolution
Mutates top vectors, breeds new payloads, updates vector_db
"""
import sys, sqlite3, random, hashlib, datetime

DB = "/home/workspace/BugCrusher/vector_db.sqlite"

MUTATIONS = [
    ('substitution', ['<', '>', '"', "'", '&']),
    ('encoding', ['url', 'html', 'unicode', 'base64']),
    ('recombination', ['shuffle', 'swap', 'duplicate']),
]

def load_top_vectors(n=20):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn.execute("SELECT * FROM vectors ORDER BY fitness_score DESC LIMIT ?", (n,)).fetchall()

def mutate(payload, strategy):
    for old, new in [('<','%3c'),('>','%3e'),('"','%22')]:
        if old in payload:
            return payload.replace(old, new)
    if strategy == 'encoding':
        return payload.encode('utf-8').hex()
    return payload + "_evolved"

def breed():
    vectors = load_top_vectors()
    new_count = 0
    conn = sqlite3.connect(DB)
    for v in vectors[:10]:
        strategy = random.choice(MUTATIONS)[0]
        new_payload = mutate(v['payload'], strategy)
        new_id = f"evo_{hashlib.md5((new_payload+str(datetime.datetime.now())).encode()).hexdigest()[:12]}"
        conn.execute("""INSERT INTO vectors VALUES 
            (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (new_id, new_payload, v['category'], v['subcategory'], 'payload', 'plain',
             None, v['cvss'], None, 0, 0.5, 0, 0, None, datetime.datetime.now().isoformat(),
             'evolution', None, None, hashlib.md5(new_payload.encode()).hexdigest(),
             v['id'], 2, strategy, 'bred', 'system'))
        new_count += 1
    conn.commit()
    conn.close()
    return new_count

def prune():
    conn = sqlite3.connect(DB)
    removed = conn.execute("DELETE FROM vectors WHERE fitness_score < 0.2 AND failure_count > 3").rowcount
    conn.commit()
    conn.close()
    return removed

if __name__ == '__main__':
    action = sys.argv[1] if len(sys.argv) > 1 else 'breed'
    if action == 'breed':
        count = breed()
        print(f"[+] Bred {count} new vectors")
    elif action == 'prune':
        count = prune()
        print(f"[*] Pruned {count} weak vectors")
    else:
        print("Usage: vector_breeder.py [breed|prune]")