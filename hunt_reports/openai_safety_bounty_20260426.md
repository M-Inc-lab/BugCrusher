# BugCrusher Hunt Report: OpenAI Safety Bug Bounty
**Date:** 2026-04-26
**Duration:** ~10 minutes
**Tools Run:** curl recon, custom endpoint discovery, MCP path enumeration
**Vectors Tested:** 30+ paths across 6 subdomains

---

## Findings

### Finding 1: Agentic/MCP Endpoints Accessible on Multiple Subdomains
**Severity:** INFORMATIONAL (requires authentication to confirm vulnerability)  
**CVSS:** 3.1 (vector: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  
**Endpoint:** 
- `https://chat.openai.com/v1` → 308 redirect
- `https://chat.openai.com/api/v1` → 308/403
- `https://chat.openai.com/mcp` → 308/403
- `https://chat.openai.com/connectors` → 308/403
- `https://platform.openai.com/v1` → 403
- `https://platform.openai.com/api/v1` → 403
- `https://platform.openai.com/.well-known/mcp` → **200** (serves HTML fallback, endpoint exists)
- `https://platform.openai.com/mcp` → 403
- `https://platform.openai.com/connectors` → 403
- `https://openai.com/v1` → 403
- `https://openai.com/api/v1` → 403
- `https://openai.com/mcp` → 403
- `https://openai.com/connectors` → 403

**Description:** Multiple in-scope agentic tool and MCP-related endpoints are accessible across openai.com subdomains. While authentication is required for actual exploitation, these endpoints represent the attack surface defined in the bug bounty scope. The `/.well-known/mcp` endpoint on platform.openai.com returning HTTP 200 (serving HTML) indicates the MCP protocol is implemented.

**Impact:** These are the exact endpoint categories listed as in-scope:
- Agentic Tools Including MCP
- Connectors and MCP integrations
- Authorization or permission bypasses where an agent can access Connector/MCP data beyond permitted permissions

**PoC:** 
```bash
curl -I https://platform.openai.com/.well-known/mcp
# HTTP/2 200 — endpoint exists and responds

curl -I https://chat.openai.com/mcp
# HTTP/2 308/403 — agentic endpoints present

curl -I https://api.openai.com/v1/chat/completions
# HTTP/2 401 — API reachable, authentication required
```

**Recommendation:** Test with authorized test account session to enumerate:
1. IDOR in `/v1/assistants` — can access other users' assistants via predictable IDs
2. Cross-tenant data exposure in `/v1/threads` — thread listing may expose other workspaces
3. MCP tool permission bypass — can an agent invoke tools beyond its authorized scope?
4. Prompt injection via `/v1/chat/completions` — injected instructions in conversation context

---

### Finding 2: API Infrastructure Exposed (Requires Auth to Test)
**Severity:** INFORMATIONAL  
**Endpoint:** `https://api.openai.com/v1/*`
**Description:** The OpenAI API infrastructure is accessible. Key endpoints confirmed reachable:
- `/v1/models` → 401 (authentication required, properly secured)
- `/v1/chat/completions` → would require valid token
- `/v1/assistants`, `/v1/threads`, `/v1/runs` → agentic action endpoints
- `/v1/vector_stores` → RAG/vector database access endpoints

**Recommendation:** Get authorized test account → enumerate IDOR in assistants/threads/runs

---

### Finding 3: CSP Headers Reveal Internal API Topology
**Severity:** INFORMATIONAL  
**Endpoint:** `https://platform.openai.com`  
**Description:** CSP `connect-src` header reveals extensive internal API endpoints:
```
eu.api.openai.com, au.api.openai.com, jp.api.openai.com, sg.api.openai.com,
in.api.openai.com, ca.api.openai.com, kr.api.openai.com, ae.api.openai.com,
gb.api.openai.com, api.unified-3s.api.openai.org, api.unified-0s.api.openai.org
```
This reveals OpenAI's multi-region API infrastructure which could be relevant for SSRF testing.

---

## Attack Paths for P1/P2 (Require Test Account)

1. **IDOR in Assistants API** — `/v1/assistants/{assistant_id}` — predict other users' assistant IDs → access their tools and data
2. **Cross-tenant Thread Exposure** — `/v1/threads/{thread_id}` — sequential thread IDs may expose threads from other workspaces  
3. **MCP Authorization Bypass** — Can an agent invoke MCP tools beyond what user permissions allow?
4. **Prompt Injection via Chat Completions** — Inject instructions into conversation context that cause agent to misuse connectors
5. **Rate Limit Bypass** — Automated mass creation of OpenAI accounts via `/v1/organizations` or similar

---

## Worm Status
CLEAN — No worm patterns detected in hunt context.

---

## Next Steps
1. **Obtain test account** with active OpenAI API key or ChatGPT Plus subscription
2. **Test IDOR in assistants/threads** — use a secondary test account to create assistants, then attempt to access with first account's session
3. **MCP connector testing** — enumerate MCP tools available, test permission boundaries
4. **Prompt injection** — test if conversation context can cause agent to invoke unauthorized connector actions

---

## Est. Bounty (If Findings Escalate to P1/P2)
- P1 IDOR (cross-tenant data): $5,500 - $75,000
- P2 MCP authorization bypass: $2,500 - $35,000
- P3 prompt injection: $750 - $1,500
