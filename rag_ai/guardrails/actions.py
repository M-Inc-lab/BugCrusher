"""
BugCrusher RAG AI — NeMo Guardrails Custom Actions

Custom action handlers for the NeMo Guardrails execution engine.
These bridge the guardrails to the vector store and tool execution layer.
"""

import logging
import re
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Action: retrieve_context
# ---------------------------------------------------------------------------

async def retrieve_context(query: str, top_k: int = 5) -> str:
    """Retrieve relevant vulnerability context from the vector store.

    Called by NeMo Guardrails as an execution action.
    Returns formatted context string for LLM augmentation.
    """
    try:
        # Import locally to avoid circular deps
        parent = str(Path(__file__).resolve().parent.parent)
        if parent not in sys.path:
            sys.path.insert(0, parent)
        from rag_ai.vector_store import VulnVectorStore

        store = VulnVectorStore()
        results = store.query(query, top_k=top_k)

        if not results:
            return "No relevant vulnerability data found in knowledge base."

        context_parts = []
        for i, hit in enumerate(results, 1):
            meta = hit.get("metadata", {})
            context_parts.append(
                f"[{i}] {meta.get('category', 'Unknown')} "
                f"(Severity: {meta.get('severity', 'N/A')})\n"
                f"{hit['document'][:500]}"
            )

        return "\n\n---\n\n".join(context_parts)

    except Exception as e:
        logger.error(f"retrieve_context failed: {e}")
        return f"Error retrieving context: {e}"


# ---------------------------------------------------------------------------
# Action: validate_cve_id
# ---------------------------------------------------------------------------

_CVE_PATTERN = re.compile(r"CVE-(\d{4})-(\d{4,})")


async def validate_cve_id(cve_id: str) -> dict[str, Any]:
    """Validate a CVE ID format and basic plausibility.

    Returns dict with 'valid' bool and 'reason' string.
    """
    match = _CVE_PATTERN.match(cve_id)
    if not match:
        return {
            "valid": False,
            "reason": f"Invalid CVE format: {cve_id}. Expected CVE-YYYY-NNNNN.",
        }

    year = int(match.group(1))
    if year < 1999 or year > 2027:
        return {
            "valid": False,
            "reason": f"CVE year {year} is outside plausible range (1999-2027).",
        }

    return {"valid": True, "reason": f"{cve_id} has valid format."}


# ---------------------------------------------------------------------------
# Action: gate_tool_execution
# ---------------------------------------------------------------------------

_ALLOWED_TOOLS = {
    "nmap", "nuclei", "dalfox", "sqlmap", "ffuf", "curl",
    "httpx", "subfinder", "search_vulnerabilities",
    "check_cve", "generate_report", "run_scan",
}


async def gate_tool_execution(
    tool_name: str, tool_args: dict | None = None
) -> dict[str, Any]:
    """Check if a tool is allowed to execute.

    Returns dict with 'allowed' bool and 'reason' string.
    """
    if tool_name not in _ALLOWED_TOOLS:
        logger.warning(f"Tool execution blocked: {tool_name}")
        return {
            "allowed": False,
            "reason": (
                f"Tool '{tool_name}' is not in the approved toolset. "
                f"Allowed: {', '.join(sorted(_ALLOWED_TOOLS))}"
            ),
        }

    # Additional safety checks for destructive args
    if tool_args:
        args_str = str(tool_args).lower()
        dangerous = ["rm -rf", "format c:", "drop table", "delete from"]
        for d in dangerous:
            if d in args_str:
                logger.warning(
                    f"Dangerous argument detected in {tool_name}: {d}"
                )
                return {
                    "allowed": False,
                    "reason": f"Dangerous argument pattern detected: {d}",
                }

    return {"allowed": True, "reason": f"Tool '{tool_name}' approved."}


# ---------------------------------------------------------------------------
# Action: validate_target
# ---------------------------------------------------------------------------

async def validate_target(target: str) -> dict[str, Any]:
    """Validate that a target is in scope (listed in targets.md)."""
    targets_path = Path(__file__).resolve().parent.parent.parent / "targets.md"

    if not targets_path.exists():
        return {
            "valid": False,
            "reason": "targets.md not found. Cannot verify scope.",
        }

    targets_content = targets_path.read_text(encoding="utf-8").lower()
    target_lower = target.lower().strip()

    # Check if target domain appears in targets.md
    if target_lower in targets_content:
        return {"valid": True, "reason": f"Target '{target}' is in scope."}

    # Check for wildcard patterns like *.target.com
    parts = target_lower.split(".")
    for i in range(len(parts)):
        wildcard = "*." + ".".join(parts[i:])
        if wildcard in targets_content:
            return {
                "valid": True,
                "reason": f"Target '{target}' matches wildcard {wildcard}.",
            }

    return {
        "valid": False,
        "reason": (
            f"Target '{target}' not found in targets.md. "
            f"Add it to targets.md before scanning."
        ),
    }


# ---------------------------------------------------------------------------
# Action: extract_target
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)"
)


async def extract_target(message: str) -> str:
    """Extract a target domain/URL from a user message."""
    match = _URL_PATTERN.search(message)
    if match:
        return match.group(0)
    return ""


# ---------------------------------------------------------------------------
# Register all actions with NeMo Guardrails
# ---------------------------------------------------------------------------

def register_actions(app):
    """Register custom actions with the NeMo Guardrails LLMRails app."""
    app.register_action(retrieve_context, name="retrieve_context")
    app.register_action(validate_cve_id, name="validate_cve_id")
    app.register_action(gate_tool_execution, name="gate_tool_execution")
    app.register_action(validate_target, name="validate_target")
    app.register_action(extract_target, name="extract_target")
    logger.info("Registered 5 custom NeMo Guardrails actions")
