"""
rag/rag_engine.py — SHADOW-ML RAG Engine v10.0

Retrieval-Augmented Generation for threat intelligence:
  • Vector similarity search over structured knowledge base
  • LLM-powered synthesis (Claude / fallback rule-based)
  • Context-aware threat narrative generation
  • Defense recommendation augmentation
  • Continuous knowledge base ingestion from live threat feeds
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from .knowledge_base import search, get_high_severity, THREAT_KNOWLEDGE

logger = logging.getLogger("shadow.rag.engine")


class _LLMSynthesiser:
    """
    Synthesises threat narratives from retrieved knowledge chunks.
    Uses Claude API if available; falls back to template-based synthesis.
    """

    def __init__(self):
        self._client = self._init_claude()

    def _init_claude(self):
        try:
            import anthropic
            client = anthropic.Anthropic()
            logger.info("RAG Engine: Claude API client initialised")
            return client
        except Exception:
            logger.info("RAG Engine: Claude unavailable — using template synthesis")
            return None

    def synthesise(self, query: str, chunks: List[Dict[str, Any]], context: Dict[str, Any]) -> str:
        if self._client:
            return self._claude_synthesis(query, chunks, context)
        return self._template_synthesis(query, chunks, context)

    def _claude_synthesis(self, query: str, chunks: List[Dict[str, Any]], context: Dict[str, Any]) -> str:
        try:
            chunk_text = "\n\n".join(
                f"[{c['id']}] {c['title']}\n{c['body']}" for c in chunks[:5]
            )
            threat_score = context.get("threat_score", 0)
            attack_type = context.get("attack_type", "unknown")

            prompt = (
                f"You are SHADOW-ML's threat intelligence analyst. "
                f"A security event has been detected: attack_type={attack_type}, "
                f"threat_score={threat_score:.2f}.\n\n"
                f"Relevant knowledge:\n{chunk_text}\n\n"
                f"Query: {query}\n\n"
                f"Provide a concise (3-5 sentence) threat assessment and top 3 recommended defenses."
            )
            response = self._client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        except Exception as exc:
            logger.warning("Claude synthesis failed: %s — falling back to template", exc)
            return self._template_synthesis(query, chunks, context)

    @staticmethod
    def _template_synthesis(query: str, chunks: List[Dict[str, Any]], context: Dict[str, Any]) -> str:
        threat_score = context.get("threat_score", 0)
        attack_type = context.get("attack_type", "unknown")
        source_ip = context.get("source_ip", "unknown")

        if not chunks:
            return (
                f"No specific threat intelligence found for query '{query}'. "
                f"Event: {attack_type} from {source_ip} (score={threat_score:.2f}). "
                f"Recommend: monitor, alert analyst, increase sampling."
            )

        top = chunks[0]
        defenses_found = []
        for chunk in chunks[:3]:
            body = chunk.get("body", "")
            for word in ["Defence:", "Mitigation:", "Response:", "Countermeasure:"]:
                if word in body:
                    defence_text = body.split(word)[-1].split(".")[0].strip()
                    if defence_text:
                        defenses_found.append(defence_text[:100])
                    break

        result = (
            f"SHADOW-ML Threat Assessment: Detected {attack_type} from {source_ip} "
            f"(threat score={threat_score:.2f}). "
            f"Most relevant knowledge: '{top['title']}' (severity={top['severity']:.1f}). "
        )
        if defenses_found:
            result += f"Recommended defenses: {'; '.join(defenses_found[:2])}."
        else:
            result += "Activate standard defense matrix for this threat level."
        return result


class RAGEngine:
    """
    SHADOW-ML RAG Engine v10.0

    Combines vector retrieval with LLM synthesis for actionable threat intelligence.
    """

    VERSION = "10.0.0"

    def __init__(self):
        self._synthesiser = _LLMSynthesiser()
        self._query_log: List[Dict[str, Any]] = []
        self._ingested_feeds: List[str] = []
        logger.info("RAGEngine v%s initialised — %d knowledge entries", self.VERSION, len(THREAT_KNOWLEDGE))

    def query(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
        top_k: int = 5,
        category_filter: Optional[str] = None,
    ) -> str:
        """
        Primary RAG query: retrieve → synthesise → return threat narrative.
        """
        t0 = time.perf_counter()
        ctx = context or {}

        chunks = search(text, top_k=top_k, category_filter=category_filter)
        narrative = self._synthesiser.synthesise(text, chunks, ctx)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        self._query_log.append({
            "query": text,
            "chunks_retrieved": len(chunks),
            "elapsed_ms": round(elapsed_ms, 2),
            "timestamp": time.time(),
        })
        logger.debug("RAG query: '%s' → %d chunks in %.1fms", text, len(chunks), elapsed_ms)
        return narrative

    def retrieve(
        self,
        text: str,
        top_k: int = 5,
        category_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return raw retrieved chunks without synthesis."""
        return search(text, top_k=top_k, category_filter=category_filter)

    def query_rich(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """Full structured response with chunks + narrative + metadata."""
        t0 = time.perf_counter()
        ctx = context or {}
        chunks = search(text, top_k=top_k)
        narrative = self._synthesiser.synthesise(text, chunks, ctx)
        return {
            "query": text,
            "narrative": narrative,
            "chunks": chunks,
            "processing_ms": round((time.perf_counter() - t0) * 1000, 2),
            "knowledge_base_size": len(THREAT_KNOWLEDGE),
        }

    def get_high_severity_intel(self, threshold: float = 0.85) -> List[Dict[str, Any]]:
        """Return all high-severity threat entries above threshold."""
        return get_high_severity(threshold)

    def ingest_feed(self, feed_url: str, feed_data: List[Dict[str, Any]]) -> int:
        """
        Ingest new threat intelligence entries from external feed.
        Returns number of new entries added.
        """
        added = 0
        existing_ids = {e["id"] for e in THREAT_KNOWLEDGE}
        for entry in feed_data:
            if entry.get("id") not in existing_ids:
                entry["indexed_at"] = time.time()
                THREAT_KNOWLEDGE.append(entry)
                added += 1
        if added:
            logger.info("RAG: ingested %d new entries from %s", added, feed_url)
            self._ingested_feeds.append(feed_url)
        return added

    def get_stats(self) -> Dict[str, Any]:
        return {
            "knowledge_base_size": len(THREAT_KNOWLEDGE),
            "total_queries": len(self._query_log),
            "ingested_feeds": len(self._ingested_feeds),
            "avg_query_ms": (
                round(sum(q["elapsed_ms"] for q in self._query_log) / len(self._query_log), 2)
                if self._query_log else 0
            ),
            "recent_queries": self._query_log[-5:],
        }
