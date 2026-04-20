#!/usr/bin/env python3
import sys
"""
BugCrusher - Model Weaponizer
Trains a specialized hunter model from successful hunts
"""
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

class ModelWeaponizer:
    def __init__(self, workspace="/home/workspace/BugCrusher"):
        self.workspace = workspace
        self.training_data = []
        self.hunt_dir = Path(workspace) / "hunt_reports"
        self.vector_db = Path(workspace) / "vector_db.sqlite"
    
    def extract_hunts(self):
        """Extract successful hunts as training data"""
        print("[*] Extracting hunt data...")
        if not self.hunt_dir.exists():
            print("[!] No hunt_reports found")
            return []
        
        training_pairs = []
        for report in self.hunt_dir.glob("*.md"):
            try:
                content = report.read_text()
                # Extract target info
                if "Target:" in content:
                    target = content.split("Target:")[1].split("\n")[0].strip()
                else:
                    target = report.stem
                
                # Extract findings
                if "## Findings" in content:
                    findings_section = content.split("## Findings")[1]
                    finding = findings_section.split("\n## ")[0]
                    
                    training_pairs.append({
                        "input": f"Hunt {target}. Find all vulnerabilities. Report in markdown.",
                        "output": content[:2000],  # First 2000 chars of full report
                        "target": target,
                        "type": "full_hunt_report"
                    })
                    
                    # Individual finding pairs
                    if "**" in finding:
                        for line in finding.split("\n"):
                            if line.startswith("**") and "—" in line:
                                severity = line.split("**")[1].split("**")[0].strip()
                                vuln_type = line.split("—")[1].split("@")[0].strip() if "—" in line else "Unknown"
                                
                                training_pairs.append({
                                    "input": f"Find {vuln_type} on {target}. Severity: {severity}. Return PoC.",
                                    "output": line,
                                    "target": target,
                                    "type": "finding_extraction"
                                })
            except Exception as e:
                print(f"[!] Error reading {report}: {e}")
        
        print(f"[*] Extracted {len(training_pairs)} training pairs from {len(list(self.hunt_dir.glob('*.md')))} reports")
        self.training_data = training_pairs
        return training_pairs
    
    def extract_vectors(self):
        """Extract weaponized vectors as training data"""
        print("[*] Extracting vector training data...")
        if not self.vector_db.exists():
            print("[!] No vector_db found")
            return []
        
        pairs = []
        try:
            conn = sqlite3.connect(str(self.vector_db))
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT category, payload, fitness_score FROM vectors WHERE fitness_score > 0.3").fetchall()
            
            for row in rows:
                pairs.append({
                    "input": f"Craft a {row['category']} payload with fitness > 0.7",
                    "output": f"{row['category']} payload: {row['payload']} | fitness: {row['fitness_score']}",
                    "category": row["category"],
                    "type": "vector_generation"
                })
            
            conn.close()
        except Exception as e:
            print(f"[!] Vector DB error: {e}")
        
        print(f"[*] Extracted {len(pairs)} vector training pairs")
        return pairs
    
    def extract_cves(self):
        """Extract CVE weapons as training data"""
        cve_db = Path(self.workspace) / "cve_weapons.db"
        if not cve_db.exists():
            return []
        
        pairs = []
        try:
            conn = sqlite3.connect(str(cve_db))
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT cve_id, description, exploit_code, severity FROM cves WHERE severity >= 8.0").fetchall()
            
            for row in rows:
                pairs.append({
                    "input": f"Build exploit for {row['cve_id']} — {row['description']}",
                    "output": f"CVE: {row['cve_id']}\nSeverity: {row['severity']}\nExploit: {row['exploit_code']}",
                    "cve": row["cve_id"],
                    "type": "cve_exploitation"
                })
            
            conn.close()
        except Exception as e:
            print(f"[!] CVE DB error: {e}")
        
        return pairs
    
    def build_training_corpus(self):
        """Build full training corpus"""
        print("\n[*] Building training corpus...")
        
        all_pairs = []
        all_pairs.extend(self.extract_hunts())
        all_pairs.extend(self.extract_vectors())
        all_pairs.extend(self.extract_cves())
        
        print(f"[*] Total training pairs: {len(all_pairs)}")
        
        # Save as JSONL
        output_file = Path(self.workspace) / "training_corpus.jsonl"
        with open(output_file, "w") as f:
            for pair in all_pairs:
                f.write(json.dumps(pair) + "\n")
        
        print(f"[+] Training corpus saved: {output_file}")
        print(f"[+] Total examples: {len(all_pairs)}")
        
        # Stats
        types = {}
        for p in all_pairs:
            t = p.get("type", "unknown")
            types[t] = types.get(t, 0) + 1
        
        print("\n[*] Training data breakdown:")
        for t, count in types.items():
            print(f"  {t}: {count}")
        
        return all_pairs
    
    def generate_sft_format(self):
        """Convert to SFT format for fine-tuning"""
        print("\n[*] Generating SFT format...")
        
        pairs = self.training_data if self.training_data else self.build_training_corpus()
        
        sft_file = Path(self.workspace) / "training_corpus_sft.jsonl"
        
        with open(sft_file, "w") as f:
            for pair in pairs:
                # Format: {"messages": [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]}
                formatted = {
                    "messages": [
                        {"role": "user", "content": pair["input"]},
                        {"role": "assistant", "content": pair["output"]}
                    ]
                }
                f.write(json.dumps(formatted) + "\n")
        
        print(f"[+] SFT format saved: {sft_file}")
        return sft_file
    
    def generate_model_card(self):
        """Generate model card for the fine-tuned model"""
        card = f"""# BugCrusher Hunter Model - Model Card

## Model Details
- **Base Model**: MiniMax 2.7
- **Fine-tuned by**: BugCrusher v3.5
- **Training Date**: {datetime.now().isoformat()}
- **Training Data**: {len(self.training_data)} examples

## Training Data Sources
1. Hunt reports from BugCrusher hunts
2. Weaponized attack vectors from vector_db
3. CVE exploitation knowledge

## Capabilities
- Autonomous vulnerability hunting
- XSS, SQLi, SSRF, RCE, IDOR detection
- GraphQL security testing
- Session hijack identification
- CVE-based exploitation

## Recommended Use
Fine-tune using the SFT format training corpus.
Use with low temperature (0.3) for consistent hunting behavior.

## Limitations
- Trained on bug bounty targets only
- Does not perform actual network attacks
- Requires human oversight for critical submissions
"""
        
        card_file = Path(self.workspace) / "MODEL_CARD.md"
        card_file.write_text(card)
        print(f"[+] Model card: {card_file}")
        return card_file

if __name__ == "__main__":
    weaponizer = ModelWeaponizer()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--build":
        weaponizer.build_training_corpus()
        weaponizer.generate_sft_format()
        weaponizer.generate_model_card()
    else:
        print("BugCrusher Model Weaponizer")
        print("Usage: python model_weaponizer.py --build")
        print("\nPipeline:")
        print("  1. Extract hunt reports → training pairs")
        print("  2. Extract vectors from vector_db")
        print("  3. Extract CVE weapons")
        print("  4. Save as JSONL + SFT format")
        print("  5. Generate model card")
        print("\n[*] Run with --build to execute full pipeline")