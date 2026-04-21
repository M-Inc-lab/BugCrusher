#!/usr/bin/env python3
"""
RECON AGENT — Continuous Reconnaissance
Passive + active subdomain/port discovery
"""
import sys, sqlite3, subprocess, time, hashlib, datetime, socket

TARGETS_DB = "/home/workspace/BugCrusher/targets.md"
RECON_DB = "/home/workspace/BugCrusher/recon_cache.db"

SUBS = ['www','api','admin','test','dev','staging','app','mail','cdn','static','m','shop','blog','portal','secure']
PORTS = [21,22,23,25,80,443,445,1433,3306,3389,5432,8080,8443,27017]

def passive_recon(target):
    print(f"[*] Passive recon: {target}")
    found = []
    for sub in SUBS:
        host = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(host)
            found.append((host, ip))
            print(f"  [+] {host} -> {ip}")
        except:
            pass
    return found

def port_scan(host, ports=PORTS):
    print(f"[*] Port scanning: {host}")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
            print(f"  [+] Port {port} open")
        sock.close()
    return open_ports

def store_recon(target, subs, ports):
    conn = sqlite3.connect(RECON_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS recon 
        (id INTEGER PRIMARY KEY, target TEXT, subdomain TEXT, ip TEXT, port INTEGER, timestamp TEXT)""")
    for sub, ip in subs:
        conn.execute("INSERT INTO recon VALUES (?,?,?,?,?,?)",
            (None, target, sub, ip, None, datetime.datetime.now().isoformat()))
    for port in ports:
        conn.execute("INSERT INTO recon VALUES (?,?,?,?,?,?)",
            (None, target, None, None, port, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

def main():
    if len(sys.argv) < 2:
        print("Usage: recon_agent.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    subs = passive_recon(target)
    
    for sub, ip in subs[:5]:
        ports = port_scan(ip)
    
    store_recon(target, subs, [])
    print(f"[*] Recon complete: {len(subs)} subdomains found")

if __name__ == '__main__':
    main()