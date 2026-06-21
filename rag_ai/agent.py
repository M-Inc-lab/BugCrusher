"""
BugCrusher RAG AI — Agentic RAG Engine

The core agentic loop:
1. Input  → NeMo Guardrails input rail (sanitize)
2. Retrieve → Vector store query (top-k vulnerability chunks)
3. Reason  → LLM with retrieved context + BugCrusher persona
4. Act    → Tool calls gated by execution rails
5. Output → NeMo Guardrails output rail (validate)
6. Learn  → Store successful patterns back in vector DB
"""

import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _load_config() -> dict:
    import yaml
    config_path = Path(__file__).parent / "config.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


# ---------------------------------------------------------------------------
# Guardrails wrapper (graceful degradation if NeMo not installed)
# ---------------------------------------------------------------------------

class GuardrailsLayer:
    """Wraps NeMo Guardrails. Falls back to regex-based checks if unavailable."""

    def __init__(self, config: dict):
        self._enabled = config.get("guardrails", {}).get("enabled", True)
        self._nemo_app = None
        self._injection_patterns = [
            "ignore previous instructions",
            "ignore all previous",
            "you are now",
            "system:",
            "forget everything",
            "disregard your training",
        ]
        self._allowed_tools = set(
            config.get("guardrails", {}).get("allowed_tools", [])
        )

        if self._enabled:
            self._try_load_nemo()

    def _try_load_nemo(self):
        """Try to load NeMo Guardrails."""
        try:
            from nemoguardrails import LLMRails, RailsConfig
            guardrails_dir = Path(__file__).parent / "guardrails"
            if guardrails_dir.exists():
                rails_config = RailsConfig.from_path(str(guardrails_dir))
                self._nemo_app = LLMRails(rails_config)

                # Register custom actions
                from rag_ai.guardrails.actions import register_actions
                register_actions(self._nemo_app)

                logger.info("NeMo Guardrails loaded successfully")
            else:
                logger.warning("Guardrails directory not found, using fallback")
        except ImportError:
            logger.warning(
                "nemoguardrails not installed. Using regex-based fallback. "
                "Install: pip install nemoguardrails"
            )
        except Exception as e:
            logger.warning(f"NeMo Guardrails init failed: {e}. Using fallback.")

    def check_input(self, user_message: str) -> tuple[bool, str]:
        """Check user input. Returns (is_safe, reason)."""
        if not self._enabled:
            return True, "Guardrails disabled"

        msg_lower = user_message.lower()
        for pattern in self._injection_patterns:
            if pattern in msg_lower:
                return False, f"Prompt injection detected: '{pattern}'"

        return True, "Input passed"

    def check_tool(self, tool_name: str) -> tuple[bool, str]:
        """Check if tool execution is allowed."""
        if not self._enabled:
            return True, "Guardrails disabled"

        if self._allowed_tools and tool_name not in self._allowed_tools:
            return False, f"Tool '{tool_name}' not in allowed set"

        return True, f"Tool '{tool_name}' approved"

    def check_output(self, response: str) -> str:
        """Sanitize output. Returns cleaned response."""
        if not self._enabled:
            return response

        # Scrub potential PII patterns
        response = re.sub(
            r"\b\d{3}-\d{2}-\d{4}\b", "[SSN-REDACTED]", response
        )
        response = re.sub(
            r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            "[CARD-REDACTED]",
            response,
        )
        return response


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

class ToolExecutor:
    """Executes security tools with permission gating."""

    def __init__(self, guardrails: GuardrailsLayer):
        self._guardrails = guardrails
        self._base_dir = Path(__file__).resolve().parent.parent

    def search_vulnerabilities(self, query: str, top_k: int = 5) -> list[dict]:
        """Search the vulnerability knowledge base."""
        from rag_ai.vector_store import VulnVectorStore
        store = VulnVectorStore()
        return store.query(query, top_k=top_k)

    def check_cve(self, cve_id: str) -> dict:
        """Check CVE in local weapons database."""
        import sqlite3
        db_path = self._base_dir / "cve_weapons.db"
        if not db_path.exists():
            return {"found": False, "reason": "CVE weapons DB not found"}

        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM weapons WHERE cve_id = ?", (cve_id,)
            )
            row = cursor.fetchone()
            conn.close()
            if row:
                return {"found": True, "data": row}
            return {"found": False, "reason": f"{cve_id} not in weapons DB"}
        except Exception as e:
            return {"found": False, "reason": str(e)}

    def run_scan(self, target: str, tool: str, args: list[str] | None = None) -> dict:
        """Execute a security scanning tool."""
        allowed, reason = self._guardrails.check_tool(tool)
        if not allowed:
            return {"success": False, "error": reason}

        cmd = [tool] + (args or []) + [target]
        logger.info(f"Executing: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(self._base_dir / "workspace"),
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout[:5000],
                "stderr": result.stderr[:2000],
                "returncode": result.returncode,
            }
        except FileNotFoundError:
            return {"success": False, "error": f"Tool '{tool}' not found on PATH"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Tool '{tool}' timed out (300s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_report(self, findings: list[dict], target: str) -> str:
        """Generate a hunt report from findings."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        report = [
            f"# BugCrusher AI Hunt Report: {target}",
            f"**Date:** {timestamp}",
            f"**Findings:** {len(findings)}",
            "",
            "## Findings",
            "",
            "| # | Type | Severity | Endpoint | CWE |",
            "|---|------|----------|----------|-----|",
        ]

        for i, f in enumerate(findings, 1):
            report.append(
                f"| {i} | {f.get('type', 'N/A')} | "
                f"{f.get('severity', 'N/A')} | "
                f"{f.get('endpoint', 'N/A')} | "
                f"{f.get('cwe', 'N/A')} |"
            )

        report.extend([
            "",
            "---",
            f"*Generated by BugCrusher RAG AI — {timestamp}*",
        ])

        report_text = "\n".join(report)

        # Save report
        report_dir = self._base_dir / "hunt_reports"
        report_dir.mkdir(exist_ok=True)
        safe_target = re.sub(r"[^\w.-]", "_", target)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_path = report_dir / f"{safe_target}_{ts}.md"
        report_path.write_text(report_text, encoding="utf-8")

        logger.info(f"Report saved: {report_path}")
        return report_text

    def execute(self, tool_name: str, **kwargs) -> Any:
        """Dispatch tool execution by name."""
        dispatch = {
            "search_vulnerabilities": self.search_vulnerabilities,
            "check_cve": self.check_cve,
            "run_scan": self.run_scan,
            "generate_report": self.generate_report,
        }
        handler = dispatch.get(tool_name)
        if handler is None:
            return {"error": f"Unknown tool: {tool_name}"}
        return handler(**kwargs)


# ---------------------------------------------------------------------------
# LLM wrapper (supports multiple backends)
# ---------------------------------------------------------------------------

class LLMEngine:
    """Wraps the LLM for inference. Supports HuggingFace and llama.cpp."""

    def __init__(self, config: dict):
        self._config = config.get("model", {})
        self._model = None
        self._tokenizer = None
        self._persona = self._load_persona(config)

    def _load_persona(self, config: dict) -> str:
        """Load BugCrusher persona from SOUL.md."""
        persona_path = config.get("agent", {}).get("persona_path", "SOUL.md")
        base_dir = Path(__file__).resolve().parent.parent
        soul_path = base_dir / persona_path

        if soul_path.exists():
            content = soul_path.read_text(encoding="utf-8")
            # Truncate to fit context
            return content[:2000]
        return (
            "You are BugCrusher, an expert autonomous bug bounty hunter AI. "
            "You find vulnerabilities, craft exploit payloads, and generate reports."
        )

    def _ensure_loaded(self):
        """Lazy-load the model."""
        if self._model is not None:
            return

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            model_name = self._config.get("base", "Qwen/Qwen2.5-7B-Instruct")

            # Check for fine-tuned checkpoint first
            base_dir = Path(__file__).resolve().parent.parent
            checkpoint = base_dir / "rag_ai" / "checkpoints" / "final"
            if checkpoint.exists():
                logger.info(f"Loading fine-tuned model: {checkpoint}")
                model_name = str(checkpoint)

            self._tokenizer = AutoTokenizer.from_pretrained(
                model_name, trust_remote_code=True
            )
            self._model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True,
            )
            logger.info(f"LLM loaded: {model_name}")

        except ImportError:
            logger.warning(
                "transformers not available. LLM inference disabled. "
                "Install: pip install transformers torch"
            )
        except Exception as e:
            logger.error(f"Failed to load LLM: {e}")

    def generate(
        self,
        user_message: str,
        context: str = "",
        max_tokens: int = 2048,
    ) -> str:
        """Generate a response using the LLM with RAG context."""
        self._ensure_loaded()

        if self._model is None:
            # Fallback: return context-only response
            return self._fallback_response(user_message, context)

        import torch

        system_prompt = (
            f"{self._persona}\n\n"
            f"Use the following retrieved vulnerability knowledge to answer:\n\n"
            f"{context}"
        )

        prompt = (
            f"<|im_start|>system\n{system_prompt}<|im_end|>\n"
            f"<|im_start|>user\n{user_message}<|im_end|>\n"
            f"<|im_start|>assistant\n"
        )

        inputs = self._tokenizer(prompt, return_tensors="pt")
        input_ids = inputs["input_ids"].to(self._model.device)

        with torch.no_grad():
            outputs = self._model.generate(
                input_ids,
                max_new_tokens=max_tokens,
                temperature=0.7,
                top_p=0.9,
                do_sample=True,
                pad_token_id=self._tokenizer.eos_token_id,
            )

        response = self._tokenizer.decode(
            outputs[0][input_ids.shape[1]:], skip_special_tokens=True
        )
        return response.strip()

    def _fallback_response(self, user_message: str, context: str) -> str:
        """Context-only fallback when no LLM is loaded."""
        if context:
            return (
                f"**BugCrusher RAG Response** (LLM not loaded — showing retrieved context)\n\n"
                f"Query: {user_message}\n\n"
                f"Retrieved Knowledge:\n{context}"
            )
        return (
            f"LLM not available. Please install transformers and torch, "
            f"or run fine-tuning first."
        )


# ---------------------------------------------------------------------------
# Agentic RAG Agent
# ---------------------------------------------------------------------------

class BugCrusherAgent:
    """The main agentic RAG loop."""

    def __init__(self, config: dict | None = None):
        self.config = config or _load_config()
        self.guardrails = GuardrailsLayer(self.config)
        self.tools = ToolExecutor(self.guardrails)
        self.llm = LLMEngine(self.config)
        self._max_tool_calls = self.config.get("agent", {}).get("max_tool_calls", 10)
        self._learning_enabled = self.config.get("agent", {}).get("learning_enabled", True)

        # Audit log
        self._audit_log: list[dict] = []

    def _log_audit(self, event: str, data: dict):
        """Append to audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **data,
        }
        self._audit_log.append(entry)
        logger.debug(f"AUDIT: {event} — {data}")

    def ask(self, question: str) -> str:
        """Answer a vulnerability question using RAG."""
        self._log_audit("input", {"question": question})

        # 1. Input guardrail
        is_safe, reason = self.guardrails.check_input(question)
        if not is_safe:
            self._log_audit("blocked", {"reason": reason})
            return f"⚠️ {reason}"

        # 2. Retrieve context
        results = self.tools.search_vulnerabilities(question, top_k=5)
        context = "\n\n---\n\n".join(
            hit["document"][:500] for hit in results
        ) if results else ""
        self._log_audit("retrieve", {"hits": len(results)})

        # 3. Reason with LLM
        response = self.llm.generate(question, context=context)
        self._log_audit("generate", {"response_len": len(response)})

        # 4. Output guardrail
        response = self.guardrails.check_output(response)

        return response

    def hunt(self, target: str) -> str:
        """Run an AI-guided vulnerability hunt on a target."""
        self._log_audit("hunt_start", {"target": target})

        # 1. Input guardrail
        is_safe, reason = self.guardrails.check_input(f"Hunt {target}")
        if not is_safe:
            return f"⚠️ {reason}"

        findings = []

        # 2. Retrieve attack patterns for this target type
        context_hits = self.tools.search_vulnerabilities(
            f"vulnerability testing methodology for web application {target}",
            top_k=10,
        )
        self._log_audit("retrieve_patterns", {"hits": len(context_hits)})

        # 3. Ask LLM to plan the attack
        context = "\n".join(h["document"][:300] for h in context_hits)
        plan = self.llm.generate(
            f"Plan a security assessment for {target}. "
            f"List the top 5 tests to run in order of priority.",
            context=context,
        )
        self._log_audit("plan", {"plan_len": len(plan)})

        # 4. Execute available tools
        tool_calls = 0

        # Nmap scan
        allowed, _ = self.guardrails.check_tool("nmap")
        if allowed and tool_calls < self._max_tool_calls:
            result = self.tools.run_scan(target, "nmap", ["-sV", "-sC", "--top-ports", "100"])
            if result.get("success"):
                findings.append({
                    "type": "Port Scan",
                    "severity": "INFO",
                    "endpoint": target,
                    "cwe": "N/A",
                    "details": result.get("stdout", "")[:500],
                })
            tool_calls += 1

        # Nuclei scan
        allowed, _ = self.guardrails.check_tool("nuclei")
        if allowed and tool_calls < self._max_tool_calls:
            result = self.tools.run_scan(target, "nuclei", ["-u"])
            if result.get("success") and result.get("stdout"):
                findings.append({
                    "type": "Nuclei Findings",
                    "severity": "MEDIUM",
                    "endpoint": target,
                    "cwe": "Various",
                    "details": result.get("stdout", "")[:500],
                })
            tool_calls += 1

        self._log_audit("tools_executed", {"count": tool_calls})

        # 5. Generate report
        report = self.tools.generate_report(findings, target)

        # 6. Learn from this hunt (store successful patterns)
        if self._learning_enabled and findings:
            self._learn_from_hunt(target, findings)

        return report

    def _learn_from_hunt(self, target: str, findings: list[dict]):
        """Store successful attack patterns back in vector DB."""
        try:
            from rag_ai.vector_store import VulnVectorStore
            from rag_ai.generate_dataset import _stable_id

            store = VulnVectorStore()
            chunks = []
            for f in findings:
                chunk = {
                    "id": _stable_id(f"{target}:{f['type']}:{f.get('endpoint', '')}"),
                    "category": f.get("type", "Unknown"),
                    "subcategory": "",
                    "title": f"Successful: {f['type']} on {target}",
                    "content": f.get("details", ""),
                    "cwe_ids": [f.get("cwe", "")] if f.get("cwe") else [],
                    "severity": f.get("severity", "INFO"),
                }
                chunks.append(chunk)

            if chunks:
                count = store.update(chunks)
                logger.info(f"Learned {count} patterns from hunt")

        except Exception as e:
            logger.warning(f"Learning failed: {e}")

    def get_audit_log(self) -> list[dict]:
        """Return the audit trail for this session."""
        return self._audit_log


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_agent(config: dict | None = None) -> BugCrusherAgent:
    """Create and return a configured BugCrusher agent."""
    return BugCrusherAgent(config)
