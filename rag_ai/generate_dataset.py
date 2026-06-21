"""
BugCrusher RAG AI — Dataset Generator

Parses bug_bounty_vulnerability_encyclopedia.md into structured RAG chunks
and SFT training pairs for fine-tuning.

Usage:
    python -m rag_ai.generate_dataset
    python -m rag_ai.generate_dataset --encyclopedia path/to/encyclopedia.md
"""

import json
import os
import re
import hashlib
from pathlib import Path
from typing import Generator


# ---------------------------------------------------------------------------
# Chunk dataclass (plain dict for zero-dep serialisation)
# ---------------------------------------------------------------------------

def make_chunk(
    chunk_id: str,
    category: str,
    subcategory: str,
    title: str,
    content: str,
    cwe_ids: list[str],
    severity: str = "",
    metadata: dict | None = None,
) -> dict:
    return {
        "id": chunk_id,
        "category": category,
        "subcategory": subcategory,
        "title": title,
        "content": content,
        "cwe_ids": cwe_ids,
        "severity": severity,
        "metadata": metadata or {},
    }


# ---------------------------------------------------------------------------
# CWE extraction
# ---------------------------------------------------------------------------

_CWE_RE = re.compile(r"CWE-(\d+)")


def extract_cwes(text: str) -> list[str]:
    return [f"CWE-{m}" for m in _CWE_RE.findall(text)]


# ---------------------------------------------------------------------------
# Severity mapping (heuristic from the encyclopedia's own rating table)
# ---------------------------------------------------------------------------

_HIGH_KEYWORDS = {
    "RCE", "Remote Code Execution", "SQL Injection", "SQLi",
    "SSRF", "Auth Bypass", "Authentication Bypass",
    "Deserialization", "XXE", "Command Injection",
    "Buffer Overflow", "Privilege Escalation",
}
_MEDIUM_KEYWORDS = {
    "XSS", "Cross-Site Scripting", "CSRF", "IDOR",
    "Open Redirect", "File Upload", "Path Traversal",
    "Directory Traversal", "LFI", "RFI",
}


def infer_severity(title: str) -> str:
    upper = title.upper()
    for kw in _HIGH_KEYWORDS:
        if kw.upper() in upper:
            return "HIGH"
    for kw in _MEDIUM_KEYWORDS:
        if kw.upper() in upper:
            return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Encyclopedia parser
# ---------------------------------------------------------------------------

def _stable_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def parse_encyclopedia(path: str | Path) -> list[dict]:
    """Parse the markdown encyclopedia into a list of chunk dicts."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Encyclopedia not found: {path}")

    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    chunks: list[dict] = []
    current_category = ""
    current_subcategory = ""
    current_section_title = ""
    current_items: list[str] = []

    def flush():
        nonlocal current_items
        if not current_items or not current_section_title:
            current_items = []
            return

        content_block = "\n".join(current_items)
        cwes = extract_cwes(f"{current_section_title}\n{content_block}")
        severity = infer_severity(current_section_title)
        chunk_id = _stable_id(f"{current_category}:{current_section_title}")

        chunks.append(make_chunk(
            chunk_id=chunk_id,
            category=current_category,
            subcategory=current_subcategory,
            title=current_section_title,
            content=content_block,
            cwe_ids=cwes,
            severity=severity,
        ))
        current_items = []

    for line in lines:
        stripped = line.strip()

        # Top-level section: ## N. TITLE
        if re.match(r"^##\s+\d+[\.\)]\s+", stripped):
            flush()
            current_category = re.sub(r"^##\s+\d+[\.\)]\s*", "", stripped).strip()
            current_subcategory = ""
            current_section_title = current_category
            continue

        # Subsection: ### N.N Title
        if re.match(r"^###\s+\d+\.\d+", stripped):
            flush()
            current_subcategory = re.sub(r"^###\s+\d+\.\d+\s*", "", stripped).strip()
            current_section_title = current_subcategory
            continue

        # Bullet items
        if stripped.startswith("- **") or stripped.startswith("- "):
            current_items.append(stripped)
            continue

        # Indented sub-bullets
        if stripped.startswith("- ") or stripped.startswith("* "):
            current_items.append(stripped)

    flush()
    return chunks


# ---------------------------------------------------------------------------
# SFT pair generator from existing training corpus
# ---------------------------------------------------------------------------

def load_training_corpus(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    pairs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            pairs.append({
                "instruction": entry.get("input", ""),
                "response": entry.get("output", ""),
                "category": entry.get("category", entry.get("type", "general")),
            })
        except json.JSONDecodeError:
            continue
    return pairs


# ---------------------------------------------------------------------------
# Augment chunks → SFT instruction pairs
# ---------------------------------------------------------------------------

def chunks_to_sft_pairs(chunks: list[dict]) -> list[dict]:
    """Generate instruction-response training pairs from vuln chunks."""
    pairs = []
    for chunk in chunks:
        # Q&A about the vulnerability
        pairs.append({
            "instruction": f"What is {chunk['title']}? List all subtypes and their CWE IDs.",
            "response": (
                f"**{chunk['title']}** (Category: {chunk['category']})\n"
                f"Severity: {chunk['severity']}\n"
                f"CWE IDs: {', '.join(chunk['cwe_ids']) if chunk['cwe_ids'] else 'N/A'}\n\n"
                f"Subtypes:\n{chunk['content']}"
            ),
            "category": chunk["category"],
        })

        # Exploitation methodology
        if chunk["severity"] in ("HIGH", "MEDIUM"):
            pairs.append({
                "instruction": f"How do I test for {chunk['title']} in a bug bounty target?",
                "response": (
                    f"Testing methodology for **{chunk['title']}**:\n\n"
                    f"1. Identify attack surface — look for input vectors related to "
                    f"{chunk['category'].lower()}\n"
                    f"2. Known subtypes to test:\n{chunk['content']}\n"
                    f"3. Use appropriate tools and manual testing\n"
                    f"4. Document PoC with request/response pairs\n"
                    f"5. Triage severity — {chunk['severity']} priority"
                ),
                "category": chunk["category"],
            })

    return pairs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate(
    encyclopedia_path: str = "bug_bounty_vulnerability_encyclopedia.md",
    corpus_path: str = "training_corpus.jsonl",
    output_dir: str = "rag_ai/data",
):
    """Generate RAG chunks and SFT training data."""
    base_dir = Path(__file__).resolve().parent.parent
    enc_path = base_dir / encyclopedia_path
    corp_path = base_dir / corpus_path
    out_dir = base_dir / output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Parse encyclopedia → RAG chunks
    print(f"[+] Parsing encyclopedia: {enc_path}")
    chunks = parse_encyclopedia(enc_path)
    print(f"    → {len(chunks)} vulnerability chunks extracted")

    chunks_file = out_dir / "vuln_chunks.jsonl"
    with open(chunks_file, "w", encoding="utf-8") as f:
        for chunk in chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")
    print(f"    → Saved to {chunks_file}")

    # 2. Load existing training corpus
    print(f"[+] Loading training corpus: {corp_path}")
    existing_pairs = load_training_corpus(corp_path)
    print(f"    → {len(existing_pairs)} existing training pairs")

    # 3. Generate SFT pairs from chunks
    generated_pairs = chunks_to_sft_pairs(chunks)
    print(f"    → {len(generated_pairs)} generated SFT pairs from encyclopedia")

    # 4. Merge and deduplicate
    all_pairs = existing_pairs + generated_pairs
    seen = set()
    deduped = []
    for pair in all_pairs:
        key = _stable_id(pair["instruction"])
        if key not in seen:
            seen.add(key)
            deduped.append(pair)

    sft_file = out_dir / "finetune_sft.jsonl"
    with open(sft_file, "w", encoding="utf-8") as f:
        for pair in deduped:
            f.write(json.dumps(pair, ensure_ascii=False) + "\n")
    print(f"    → {len(deduped)} total SFT pairs saved to {sft_file}")

    # 5. Stats
    categories = set(c["category"] for c in chunks)
    high_count = sum(1 for c in chunks if c["severity"] == "HIGH")
    med_count = sum(1 for c in chunks if c["severity"] == "MEDIUM")
    cwe_count = len(set(cwe for c in chunks for cwe in c["cwe_ids"]))

    print(f"\n[*] Dataset Stats:")
    print(f"    Categories:    {len(categories)}")
    print(f"    HIGH severity: {high_count}")
    print(f"    MED severity:  {med_count}")
    print(f"    Unique CWEs:   {cwe_count}")
    print(f"    RAG chunks:    {len(chunks)}")
    print(f"    SFT pairs:     {len(deduped)}")


if __name__ == "__main__":
    import sys
    kwargs = {}
    for arg in sys.argv[1:]:
        if arg.startswith("--encyclopedia="):
            kwargs["encyclopedia_path"] = arg.split("=", 1)[1]
        elif arg.startswith("--corpus="):
            kwargs["corpus_path"] = arg.split("=", 1)[1]
        elif arg.startswith("--output="):
            kwargs["output_dir"] = arg.split("=", 1)[1]
    generate(**kwargs)
