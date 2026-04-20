#!/usr/bin/env python3
import json
import sqlite3
from pathlib import Path

DB = Path('/home/workspace/BugCrusher/vector_db.sqlite')
CVE_DB = Path('/home/workspace/BugCrusher/cve_weapons.db')
REPORTS = Path('/home/workspace/BugCrusher/hunt_reports')

def get_stats():
    stats = {}
    if DB.exists():
        conn = sqlite3.connect(str(DB))
        conn.row_factory = sqlite3.Row
        stats['total_vectors'] = conn.execute('SELECT COUNT(*) FROM vectors').fetchone()[0]
        stats['avg_fitness'] = conn.execute('SELECT AVG(fitness_score) FROM vectors').fetchone()[0] or 0
        rows = conn.execute('SELECT category, COUNT(*) as cnt FROM vectors GROUP BY category').fetchall()
        stats['category_dist'] = [dict(r) for r in rows]
        top = conn.execute('SELECT payload, category, fitness_score FROM vectors ORDER BY fitness_score DESC LIMIT 5').fetchall()
        stats['top_vectors'] = [dict(r) for r in top]
        conn.close()
    else:
        stats = {'total_vectors': 0, 'category_dist': [], 'top_vectors': [], 'avg_fitness': 0}
    
    stats['critical_findings'] = len(list(REPORTS.glob('*CRITICAL*'))) if REPORTS.exists() else 0
    stats['total_reports'] = len(list(REPORTS.glob('*.md'))) if REPORTS.exists() else 0
    stats['active_programs'] = len([l for l in Path('/home/workspace/BugCrusher/targets.md').read_text().split('\n') if l.startswith('-')]) if Path('/home/workspace/BugCrusher/targets.md').exists() else 0
    
    return stats

print(json.dumps(get_stats()))