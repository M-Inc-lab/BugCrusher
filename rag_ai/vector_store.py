"""
BugCrusher RAG AI — Vector Store

ChromaDB-backed vector store for vulnerability knowledge retrieval.
Embeds chunks using sentence-transformers, supports ingest/query/update.

Usage:
    from rag_ai.vector_store import VulnVectorStore
    store = VulnVectorStore()
    store.ingest("rag_ai/data/vuln_chunks.jsonl")
    results = store.query("SSRF via cloud metadata", top_k=5)
"""

import json
import os
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _load_config() -> dict:
    """Load RAG config from config.yaml."""
    import yaml
    config_path = Path(__file__).parent / "config.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


class VulnVectorStore:
    """Lightweight ChromaDB wrapper for vulnerability chunk retrieval."""

    def __init__(
        self,
        db_path: str | None = None,
        embedding_model: str | None = None,
        collection_name: str = "bugcrusher_vulns",
    ):
        config = _load_config().get("rag", {})
        self._db_path = db_path or config.get("db_path", "rag_ai/chroma_db")
        self._embedding_model_name = embedding_model or config.get(
            "embedding_model", "sentence-transformers/all-MiniLM-L6-v2"
        )
        self._collection_name = collection_name

        # Resolve db_path relative to BugCrusher root
        base_dir = Path(__file__).resolve().parent.parent
        self._db_path_abs = str(base_dir / self._db_path)

        self._client = None
        self._collection = None
        self._embed_fn = None

    def _ensure_client(self):
        """Lazy-init ChromaDB client and embedding function."""
        if self._client is not None:
            return

        try:
            import chromadb
            from chromadb.utils import embedding_functions
        except ImportError:
            raise ImportError(
                "chromadb is required. Install: pip install chromadb"
            )

        os.makedirs(self._db_path_abs, exist_ok=True)

        self._client = chromadb.PersistentClient(path=self._db_path_abs)

        # Use sentence-transformers embedding function
        self._embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=self._embedding_model_name
        )

        self._collection = self._client.get_or_create_collection(
            name=self._collection_name,
            embedding_function=self._embed_fn,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            f"ChromaDB initialized: {self._db_path_abs} "
            f"(collection={self._collection_name}, "
            f"count={self._collection.count()})"
        )

    def ingest(self, jsonl_path: str, batch_size: int = 100) -> int:
        """Ingest vulnerability chunks from JSONL into the vector store.

        Returns the number of chunks ingested.
        """
        self._ensure_client()

        path = Path(jsonl_path)
        if not path.is_absolute():
            path = Path(__file__).resolve().parent.parent / path

        if not path.exists():
            raise FileNotFoundError(f"Chunk file not found: {path}")

        chunks = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    chunks.append(json.loads(line))

        if not chunks:
            logger.warning("No chunks found in %s", path)
            return 0

        # Batch upsert
        total = 0
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i : i + batch_size]

            ids = [c["id"] for c in batch]
            documents = [
                f"[{c['category']}] {c['title']}\n"
                f"Severity: {c['severity']}\n"
                f"CWE: {', '.join(c['cwe_ids'])}\n\n"
                f"{c['content']}"
                for c in batch
            ]
            metadatas = [
                {
                    "category": c["category"],
                    "subcategory": c.get("subcategory", ""),
                    "severity": c["severity"],
                    "cwe_ids": ",".join(c["cwe_ids"]),
                }
                for c in batch
            ]

            self._collection.upsert(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
            )
            total += len(batch)

        logger.info(f"Ingested {total} chunks into vector store")
        return total

    def query(
        self,
        question: str,
        top_k: int | None = None,
        filter_severity: str | None = None,
        filter_category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query the vector store for relevant vulnerability chunks.

        Returns a list of dicts with keys: id, document, metadata, distance.
        """
        self._ensure_client()
        config = _load_config().get("rag", {})
        top_k = top_k or config.get("top_k", 5)

        where_filter = None
        conditions = []
        if filter_severity:
            conditions.append({"severity": filter_severity})
        if filter_category:
            conditions.append({"category": filter_category})
        if len(conditions) == 1:
            where_filter = conditions[0]
        elif len(conditions) > 1:
            where_filter = {"$and": conditions}

        results = self._collection.query(
            query_texts=[question],
            n_results=top_k,
            where=where_filter,
            include=["documents", "metadatas", "distances"],
        )

        hits = []
        if results and results["ids"] and results["ids"][0]:
            for idx in range(len(results["ids"][0])):
                hits.append({
                    "id": results["ids"][0][idx],
                    "document": results["documents"][0][idx],
                    "metadata": results["metadatas"][0][idx],
                    "distance": results["distances"][0][idx],
                })

        return hits

    def update(self, chunks: list[dict]) -> int:
        """Update or add new chunks to the vector store."""
        self._ensure_client()

        if not chunks:
            return 0

        ids = [c["id"] for c in chunks]
        documents = [
            f"[{c['category']}] {c['title']}\n"
            f"Severity: {c['severity']}\n"
            f"CWE: {', '.join(c['cwe_ids'])}\n\n"
            f"{c['content']}"
            for c in chunks
        ]
        metadatas = [
            {
                "category": c["category"],
                "subcategory": c.get("subcategory", ""),
                "severity": c["severity"],
                "cwe_ids": ",".join(c["cwe_ids"]),
            }
            for c in chunks
        ]

        self._collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        return len(chunks)

    def count(self) -> int:
        """Return total chunks in the store."""
        self._ensure_client()
        return self._collection.count()

    def delete_collection(self):
        """Drop the entire collection (destructive)."""
        self._ensure_client()
        self._client.delete_collection(self._collection_name)
        self._collection = None
        logger.warning(f"Deleted collection: {self._collection_name}")
