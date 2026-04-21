#!/usr/bin/env python3
"""
WORM SENTINEL AGENT — Continuous AI Worm Detection
Monitors all prompts for injection patterns
"""
import sys, re, datetime, hashlib

WORM_PATTERNS = [
    (r'ignore\s*(all\s*)?(previous|above|prior)\s*instructions?', 0.9),
    (r'(disregard|forget)\s*(all\s*)?(your\s*)?instructions?', 0.9),
    (r'system\s*(prompt|role|identity)', 0.8),
    (r'reveal\s*(your\s*)?(system\s*)?prompt', 0.8),
    (r'DAN|Do\s*Anything\s*Now', 0.9),
    (r'STROOPWAFEL|prompt\s*injection', 0.8),
    (r'(you\s*are\s*now\s*|you\s*must\s*)?jailbroken', 0.7),
    (r'alternative\s*(mode|behavior)', 0.6),
    (r'hack\s*yourself|override\s*safety', 0.8),
]

def scan(text):
    text = text.lower()
    total_score = 0.0
    matches = []
    for pattern, weight in WORM_PATTERNS:
        if re.search(pattern, text, re.I):
            total_score += weight
            matches.append(pattern[:40])
    return total_score, matches

def block(score):
    return score >= 0.7

def quarantine(score):
    return score >= 0.9

def main():
    if len(sys.argv) > 1:
        text = ' '.join(sys.argv[1:])
    else:
        text = input("Enter text to scan: ")
    
    score, matches = scan(text)
    status = "BLOCK" if block(score) else "QUARANTINE" if quarantine(score) else "CLEAN"
    
    print(f"[*] Worm Score: {score:.2f}")
    print(f"[*] Status: {status}")
    if matches:
        print(f"[*] Matches: {matches}")
    
    if block(score):
        print("[!] WORM BLOCKED — Execution halted")
        sys.exit(1)

if __name__ == '__main__':
    main()