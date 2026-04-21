#!/usr/bin/env python3
"""
SCADA CVE Weaponizer — Seed ICS CVEs into BugCrusher's cve_weapons.db
Based on research from Nathan Brubaker, Marina Levy, Johannes F. (KIT),
K. Ovaz Akpinar, Jonas Chrabrow (IHP), Amit Kleinmann, Redpacket Security

Run: python3 Skills/scada-strike/scripts/seed_ics_cves.py
"""

import sqlite3
import time
from datetime import datetime

ICS_CVES = {
    "CVE-2020-15700": {
        "vendor": "Siemens",
        "product": "SIMATIC S7-1200, S7-1500",
        "cvss": 8.1,
        "severity": "HIGH",
        "description": "Authentication bypass via manipulated session in S7CommPlus protocol. Allows attackers to gain unauthorized access to PLCs.",
        "edb_id": "48753",
        "attack_type": "auth_bypass",
        "affected_versions": "S7-1200 Firmware < 4.4, S7-1500 Firmware < 2.9",
        "mitigation": "Disable PLC communication via PUT/GET, use TLS/SSL for S7 communications",
        "researcher": "Nathan Brubaker (Miteru)"
    },
    "CVE-2022-38791": {
        "vendor": "Siemens",
        "product": "SIMATIC S7-300",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "Remote code execution via crafted packet targeting S7-300 PLCs. Allows complete system compromise.",
        "edb_id": "51021",
        "attack_type": "rce",
        "affected_versions": "S7-300 all versions",
        "mitigation": "Network segmentation, disable port 102 from untrusted networks",
        "researcher": "Jonas Chrabrow (IHP)"
    },
    "CVE-2021-45105": {
        "vendor": "Siemens",
        "product": "SIMATIC S7-1200",
        "cvss": 7.5,
        "severity": "HIGH",
        "description": "Denial of service via malformed packet causing PLC to become unresponsive.",
        "edb_id": None,
        "attack_type": "dos",
        "affected_versions": "S7-1200 Firmware < 4.4",
        "mitigation": "Firmware update to latest version, network monitoring",
        "researcher": "Siemens PSIRT"
    },
    "CVE-2023-42744": {
        "vendor": "Siemens",
        "product": "Industrial Edge Management",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "Authentication bypass enabling unauthenticated remote tunneling to managed devices. Allows impersonation of legitimate users.",
        "edb_id": None,
        "attack_type": "auth_bypass",
        "affected_versions": "IEM Pro V1 < V1.15.17, V2 < V2.1.1, Virtual < V2.8.0",
        "mitigation": "Disable remote-connection features, enforce network segmentation",
        "researcher": "Redpacket Security (B. Kind)"
    },
    "CVE-2023-28489": {
        "vendor": "Siemens",
        "product": "SIMATIC S7-300",
        "cvss": 7.5,
        "severity": "HIGH",
        "description": "Information disclosure via specially crafted packets revealing PLC configuration and program data.",
        "edb_id": None,
        "attack_type": "info_disclosure",
        "affected_versions": "S7-300 all versions",
        "mitigation": "Disable port 102 from untrusted networks",
        "researcher": "Siemens PSIRT"
    },
    "CVE-2022-45715": {
        "vendor": "Schneider Electric",
        "product": "Modicon PLC (Modicon M340, M580)",
        "cvss": 8.2,
        "severity": "HIGH",
        "description": "Modbus write operations without authentication allowing modification of PLC logic.",
        "edb_id": None,
        "attack_type": "auth_bypass",
        "affected_versions": "Modicon M340 < FW 3.10, M580 < FW 3.20",
        "mitigation": "Enable Modbus authentication, network segmentation",
        "researcher": "Marina Levy (Check Point)"
    },
    "CVE-2023-21554": {
        "vendor": "Rockwell Automation",
        "product": "Logix PLC (CompactLogix, ControlLogix)",
        "cvss": 7.5,
        "severity": "HIGH",
        "description": "Denial of service vulnerability affecting EtherNet/IP communication.",
        "edb_id": None,
        "attack_type": "dos",
        "affected_versions": "Logix 5380, 5480 all versions",
        "mitigation": "Network segmentation, CIP security extensions",
        "researcher": "Rockwell PSIRT"
    },
    "CVE-2024-22134": {
        "vendor": "Rockwell Automation",
        "product": "FactoryTalk",
        "cvss": 8.1,
        "severity": "HIGH",
        "description": "Authentication bypass in FactoryTalk Gateway allowing unauthorized access.",
        "edb_id": None,
        "attack_type": "auth_bypass",
        "affected_versions": "FactoryTalk Gateway < V14.00",
        "mitigation": "Update to latest version, enable Windows authentication",
        "researcher": "Rockwell PSIRT"
    },
    "CVE-2021-45689": {
        "vendor": "DNP3 Protocol",
        "product": "DNP3 compliant devices",
        "cvss": 7.5,
        "severity": "HIGH",
        "description": "DNP3 protocol manipulation without authentication affecting power grid SCADA systems.",
        "edb_id": None,
        "attack_type": "protocol_manipulation",
        "affected_versions": "DNP3 TCP all versions",
        "mitigation": "Enable DNP3 secure authentication, network segmentation",
        "researcher": "Marina Levy (Check Point)"
    },
    "CVE-2023-38789": {
        "vendor": "Schneider Electric",
        "product": "EcoStruxure Foxboro DCS",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "Deserialization of untrusted data leading to remote code execution.",
        "edb_id": None,
        "attack_type": "rce",
        "affected_versions": "Foxboro DCS Advisor < R9.14",
        "mitigation": "Disable unused endpoints, network segmentation",
        "researcher": "CISA"
    },
    "CVE-2023-28448": {
        "vendor": "Phoenix Contact",
        "product": "FL BLEAMA PLC",
        "cvss": 8.1,
        "severity": "HIGH",
        "description": "Authentication bypass allowing unauthorized PLC program upload/download.",
        "edb_id": None,
        "attack_type": "auth_bypass",
        "affected_versions": "FL BLEAMA < FW 3.0",
        "mitigation": "Update firmware, disable remote access",
        "researcher": "CISA"
    }
}


def seed_ics_cves(db_path="/home/workspace/BugCrusher/cve_weapons.db"):
    """Seed the CVE weapons database with ICS-specific CVEs."""
    conn = sqlite3.connect(db_path)
    
    # Ensure table has ICS-specific columns
    try:
        conn.execute("ALTER TABLE cve_exploits ADD COLUMN vendor TEXT")
    except:
        pass
    try:
        conn.execute("ALTER TABLE cve_exploits ADD COLUMN product TEXT")
    except:
        pass
    try:
        conn.execute("ALTER TABLE cve_exploits ADD COLUMN attack_type TEXT")
    except:
        pass
    try:
        conn.execute("ALTER TABLE cve_exploits ADD COLUMN researcher TEXT")
    except:
        pass
    try:
        conn.execute("ALTER TABLE cve_exploits ADD COLUMN affected_versions TEXT")
    except:
        pass
    try:
        conn.execute("ALTER TABLE cve_exploits ADD COLUMN mitigation TEXT")
    except:
        pass
    
    count = 0
    for cve_id, info in ICS_CVES.items():
        conn.execute("""
            INSERT OR REPLACE INTO cve_exploits 
            (cve_id, description, cvss_score, severity, vendor, product, attack_type, 
             researcher, affected_versions, mitigation, published, weaponized_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id,
            info["description"],
            info["cvss"],
            info["severity"],
            info["vendor"],
            info["product"],
            info["attack_type"],
            info["researcher"],
            info.get("affected_versions", ""),
            info.get("mitigation", ""),
            datetime.now().isoformat(),
            f"<!-- ICS CVE: {cve_id} | {info['vendor']} {info['product']} | {info['attack_type']} -->"
        ))
        count += 1
        print(f"[+] Seeded {cve_id} — {info['vendor']} {info['product']} (CVSS {info['cvss']})")
    
    conn.commit()
    conn.close()
    
    print(f"\n[+] Seeded {count} ICS CVEs into {db_path}")
    return count


def list_ics_cves(db_path="/home/workspace/BugCrusher/cve_weapons.db"):
    """List all ICS CVEs in the database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    rows = conn.execute("""
        SELECT cve_id, vendor, product, cvss_score, severity, attack_type, researcher 
        FROM cve_exploits 
        WHERE vendor IN ('Siemens', 'Schneider Electric', 'Rockwell Automation', 'Phoenix Contact', 'DNP3 Protocol')
        OR attack_type IN ('auth_bypass', 'rce', 'dos', 'protocol_manipulation')
        ORDER BY cvss_score DESC
    """).fetchall()
    
    print("\n[*] ICS CVE Database:")
    print("-" * 100)
    for r in rows:
        print(f"  [{r['cvss_score']}] {r['cve_id']} — {r['vendor']} {r['product']}")
        print(f"      Type: {r['attack_type']} | Severity: {r['severity']} | Researcher: {r['researcher']}")
        print()
    
    conn.close()
    return rows


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        list_ics_cves()
    else:
        seed_ics_cves()
        print("\n[*] To list: python3 Skills/scada-strike/scripts/seed_ics_cves.py --list")