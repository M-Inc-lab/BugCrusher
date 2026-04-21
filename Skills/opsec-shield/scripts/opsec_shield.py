#!/usr/bin/env python3
"""
OPSEC-SHIELD — Anti-Detection & Operational Security
Run: python3 Skills/opsec-shield/scripts/opsec_shield.py <action>
Actions: rotate, fingerprint, clean, blocklist
"""
import sys, random, subprocess, time

PROXIES = [
    "socks5://proxy1:1080",
    "socks5://proxy2:1080", 
    "http://proxy3:8080",
    "http://proxy4:3128"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0"
]

def rotate_proxy():
    proxy = random.choice(PROXIES)
    print(f"[*] Rotating to: {proxy}")
    return proxy

def mask_fingerprint():
    print("[*] Masking fingerprint...")
    return {
        'user_agent': random.choice(USER_AGENTS),
        'proxy': rotate_proxy(),
        'delay': random.uniform(1, 5),
        'headers': {'Accept-Language': 'en-US,en;q=0.9'}
    }

def clean_trail():
    print("[*] Cleaning operational traces...")
    cmds = [
        "find /tmp -name 'bugcrusher_*' -delete",
        "history -c",
        "rm -rf ~/.bash_history",
        "journalctl --vacuum-time=1s"
    ]
    return cmds

def block_detect():
    print("[*] Checking for ban/detection...")
    return ["curl -s -o /dev/null -w '%{http_code}' target", "check user-agent in logs"]

def main():
    action = sys.argv[1] if len(sys.argv) > 1 else 'help'
    
    if action == 'rotate':
        rotate_proxy()
    elif action == 'fingerprint':
        print(mask_fingerprint())
    elif action == 'clean':
        print('\n'.join(clean_trail()))
    elif action == 'blocklist':
        print('\n'.join(block_detect()))
    else:
        print("Usage: opsec_shield.py <action>")
        print("Actions:", ['rotate', 'fingerprint', 'clean', 'blocklist'])
        sys.exit(1)

if __name__ == '__main__':
    main()