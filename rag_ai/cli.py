"""
BugCrusher RAG AI — CLI Interface

Usage:
    python -m rag_ai.cli ask "What is SSRF?"
    python -m rag_ai.cli hunt api.target.com
    python -m rag_ai.cli ingest rag_ai/data/vuln_chunks.jsonl
    python -m rag_ai.cli train --epochs 3
    python -m rag_ai.cli generate-dataset
    python -m rag_ai.cli stats
"""

import argparse
import logging
import sys
from pathlib import Path


def _setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_ask(args):
    """Ask the RAG agent a vulnerability question."""
    from rag_ai.agent import create_agent

    agent = create_agent()
    question = " ".join(args.question)
    print(f"\n🔍 Query: {question}\n")

    response = agent.ask(question)
    print(response)


def cmd_hunt(args):
    """Run an AI-guided hunt on a target."""
    from rag_ai.agent import create_agent

    agent = create_agent()
    print(f"\n🎯 Hunting: {args.target}\n")

    report = agent.hunt(args.target)
    print(report)


def cmd_ingest(args):
    """Ingest vulnerability chunks into the vector store."""
    from rag_ai.vector_store import VulnVectorStore

    store = VulnVectorStore()
    count = store.ingest(args.file)
    print(f"\n✅ Ingested {count} chunks into vector store")
    print(f"   Total chunks: {store.count()}")


def cmd_generate_dataset(args):
    """Generate RAG dataset from the vulnerability encyclopedia."""
    from rag_ai.generate_dataset import generate

    kwargs = {}
    if args.encyclopedia:
        kwargs["encyclopedia_path"] = args.encyclopedia
    if args.corpus:
        kwargs["corpus_path"] = args.corpus

    generate(**kwargs)


def cmd_train(args):
    """Fine-tune the model using ACAB-X pipeline."""
    from rag_ai.finetune import ACABXFineTuner, _load_config

    config = _load_config()
    if args.epochs:
        config.setdefault("training", {})["epochs"] = args.epochs
    if args.lr:
        config.setdefault("training", {})["learning_rate"] = args.lr

    tuner = ACABXFineTuner(config)
    kwargs = {}
    if args.dataset:
        kwargs["dataset_path"] = args.dataset

    tuner.train(**kwargs)


def cmd_stats(args):
    """Show vector store and dataset statistics."""
    print("\n📊 BugCrusher RAG AI Stats\n")

    # Vector store
    try:
        from rag_ai.vector_store import VulnVectorStore
        store = VulnVectorStore()
        print(f"   Vector Store Chunks: {store.count()}")
    except Exception as e:
        print(f"   Vector Store: Error — {e}")

    # Dataset files
    base_dir = Path(__file__).resolve().parent.parent
    data_dir = base_dir / "rag_ai" / "data"
    for fname in ["vuln_chunks.jsonl", "finetune_sft.jsonl"]:
        fpath = data_dir / fname
        if fpath.exists():
            line_count = sum(1 for _ in open(fpath, encoding="utf-8"))
            print(f"   {fname}: {line_count} entries")
        else:
            print(f"   {fname}: not generated yet")

    # Checkpoints
    ckpt_dir = base_dir / "rag_ai" / "checkpoints"
    if ckpt_dir.exists():
        ckpts = list(ckpt_dir.iterdir())
        print(f"   Checkpoints: {len(ckpts)}")
    else:
        print(f"   Checkpoints: none")

    # Training corpus
    corpus = base_dir / "training_corpus.jsonl"
    if corpus.exists():
        line_count = sum(1 for _ in open(corpus, encoding="utf-8"))
        print(f"   Training Corpus: {line_count} entries")

    print()


def cmd_query(args):
    """Direct vector store query (no LLM)."""
    from rag_ai.vector_store import VulnVectorStore

    store = VulnVectorStore()
    question = " ".join(args.question)
    print(f"\n🔍 Vector Query: {question}\n")

    results = store.query(
        question,
        top_k=args.top_k,
        filter_severity=args.severity,
    )

    if not results:
        print("No results found.")
        return

    for i, hit in enumerate(results, 1):
        meta = hit.get("metadata", {})
        dist = hit.get("distance", 0)
        print(f"--- [{i}] Score: {1 - dist:.3f} | {meta.get('severity', '?')} ---")
        print(f"Category: {meta.get('category', 'N/A')}")
        print(hit["document"][:300])
        print()


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="rag_ai",
        description="BugCrusher RAG AI — Agentic Vulnerability Intelligence",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ask
    p_ask = subparsers.add_parser("ask", help="Ask a vulnerability question")
    p_ask.add_argument("question", nargs="+", help="The question to ask")
    p_ask.set_defaults(func=cmd_ask)

    # hunt
    p_hunt = subparsers.add_parser("hunt", help="AI-guided vulnerability hunt")
    p_hunt.add_argument("target", help="Target domain/URL")
    p_hunt.set_defaults(func=cmd_hunt)

    # ingest
    p_ingest = subparsers.add_parser("ingest", help="Ingest chunks into vector store")
    p_ingest.add_argument("file", help="Path to JSONL file")
    p_ingest.set_defaults(func=cmd_ingest)

    # generate-dataset
    p_gen = subparsers.add_parser("generate-dataset", help="Generate RAG dataset")
    p_gen.add_argument("--encyclopedia", default=None)
    p_gen.add_argument("--corpus", default=None)
    p_gen.set_defaults(func=cmd_generate_dataset)

    # train
    p_train = subparsers.add_parser("train", help="Fine-tune model with ACAB-X")
    p_train.add_argument("--epochs", type=int, default=None)
    p_train.add_argument("--lr", type=float, default=None)
    p_train.add_argument("--dataset", default=None)
    p_train.set_defaults(func=cmd_train)

    # stats
    p_stats = subparsers.add_parser("stats", help="Show system statistics")
    p_stats.set_defaults(func=cmd_stats)

    # query (direct vector store)
    p_query = subparsers.add_parser("query", help="Direct vector store query")
    p_query.add_argument("question", nargs="+")
    p_query.add_argument("--top-k", type=int, default=5)
    p_query.add_argument("--severity", default=None)
    p_query.set_defaults(func=cmd_query)

    args = parser.parse_args()
    _setup_logging(args.log_level)

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
