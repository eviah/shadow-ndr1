"""
analytics/nlp_query.py — Natural-Language Threat Query Engine v10.0

Allows SOC analysts to query the threat intelligence system using plain English:

  Examples:
    "Show me all ADS-B spoofing attempts from 192.168.1.x in the last hour"
    "Which entities have impossible travel anomalies today?"
    "Find DNS beaconing with interval less than 30 seconds"
    "What MITRE techniques were used in the last BGP hijack?"
    "List critical incidents involving SCADA systems"

Processing pipeline:
  1. Intent classifier → determines query type (filter / aggregate / explain / hunt)
  2. Entity extractor  → pulls IPs, protocols, timeframes, thresholds
  3. Query builder     → converts intent + entities to structured filter dict
  4. Executor          → routes to correct backend (UEBA / correlator / RAG / vector store)
  5. Formatter         → renders results as natural-language response + structured data

Backends:
  • Vector store (semantic similarity search on threat intel)
  • UEBA engine (entity/behavior queries)
  • Cross-protocol correlator (attack correlation queries)
  • RAG engine (MITRE ATT&CK / CTI queries)
  • Claude claude-sonnet-4-6 (complex reasoning, explanation queries)
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("shadow.analytics.nlp_query")


# ---------------------------------------------------------------------------
# Intent taxonomy
# ---------------------------------------------------------------------------

class Intent:
    FILTER    = "filter"      # "show me X where Y"
    AGGREGATE = "aggregate"   # "how many X in last Y hours"
    EXPLAIN   = "explain"     # "why was X flagged?"
    HUNT      = "hunt"        # "find indicators of X"
    COMPARE   = "compare"     # "compare X and Y"
    SUMMARIZE = "summarize"   # "summarize the last hour"
    MITRE     = "mitre"       # "what ATT&CK techniques..."
    UNKNOWN   = "unknown"


# ---------------------------------------------------------------------------
# Parsed query
# ---------------------------------------------------------------------------

@dataclass
class ParsedQuery:
    raw: str
    intent: str
    protocols: List[str] = field(default_factory=list)
    src_ips: List[str] = field(default_factory=list)
    threat_levels: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    entity_ids: List[str] = field(default_factory=list)
    time_window_minutes: int = 60
    threshold: Optional[float] = None
    keywords: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw":                 self.raw,
            "intent":              self.intent,
            "protocols":           self.protocols,
            "src_ips":             self.src_ips,
            "threat_levels":       self.threat_levels,
            "ttps":                self.ttps,
            "entity_ids":          self.entity_ids,
            "time_window_minutes": self.time_window_minutes,
            "threshold":           self.threshold,
            "keywords":            self.keywords,
            "confidence":          round(self.confidence, 3),
        }


# ---------------------------------------------------------------------------
# Entity extractor (regex-based)
# ---------------------------------------------------------------------------

class EntityExtractor:
    """Extracts typed entities from free-text threat queries."""

    _IP_RE        = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b")
    _PROTOCOL_RE  = re.compile(
        r"\b(adsb|ads-b|iec104|iec\s*104|modbus|dnp3|acars|cpdlc|bgp|dns|tcp|udp|"
        r"http|https|tls|ssh|ftp|scada|ot|gps|ils)\b", re.I)
    _LEVEL_RE     = re.compile(r"\b(critical|high|medium|low|info)\b", re.I)
    _TTP_RE       = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
    _TIME_RE      = re.compile(
        r"\b(\d+)\s*(second|minute|hour|day|week)s?\b", re.I)
    _THRESHOLD_RE = re.compile(
        r"\b(?:score|threshold|above|greater than|>)\s*([0-9]*\.?[0-9]+)\b", re.I)
    _ENTITY_RE    = re.compile(
        r"\b([A-Za-z][A-Za-z0-9_\-]{2,}(?:@[A-Za-z0-9_\-]+)?)\b")

    # Protocol aliases
    _PROTO_MAP = {
        "ads-b": "adsb", "iec 104": "iec104", "iec-104": "iec104",
        "scada": "modbus", "ot": "modbus",
    }

    def extract(self, text: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "ips": [],
            "protocols": [],
            "levels": [],
            "ttps": [],
            "time_minutes": 60,
            "threshold": None,
        }

        # IPs
        result["ips"] = list(set(self._IP_RE.findall(text)))

        # Protocols
        raw_protos = [m.lower() for m in self._PROTOCOL_RE.findall(text)]
        protocols = list({self._PROTO_MAP.get(p, p) for p in raw_protos})
        result["protocols"] = protocols

        # Severity levels
        result["levels"] = list({m.lower() for m in self._LEVEL_RE.findall(text)})

        # MITRE TTPs
        result["ttps"] = list(set(self._TTP_RE.findall(text)))

        # Time window
        time_match = self._TIME_RE.search(text)
        if time_match:
            n, unit = int(time_match.group(1)), time_match.group(2).lower()
            if unit.startswith("second"):
                result["time_minutes"] = max(1, n // 60)
            elif unit.startswith("minute"):
                result["time_minutes"] = n
            elif unit.startswith("hour"):
                result["time_minutes"] = n * 60
            elif unit.startswith("day"):
                result["time_minutes"] = n * 1440
            elif unit.startswith("week"):
                result["time_minutes"] = n * 10080

        # Threshold
        thr_match = self._THRESHOLD_RE.search(text)
        if thr_match:
            result["threshold"] = float(thr_match.group(1))

        return result


# ---------------------------------------------------------------------------
# Intent classifier
# ---------------------------------------------------------------------------

class IntentClassifier:
    """Rule-based intent classification with confidence scoring."""

    _RULES: List[Tuple[List[str], str, float]] = [
        # (keywords, intent, base_confidence)
        (["why", "explain", "reason", "how", "flagged", "triggered"], Intent.EXPLAIN, 0.85),
        (["how many", "count", "total", "number of", "aggregate", "sum"], Intent.AGGREGATE, 0.85),
        (["find", "hunt", "search", "detect", "indicators", "ioc"], Intent.HUNT, 0.80),
        (["compare", "versus", "vs", "difference between"], Intent.COMPARE, 0.80),
        (["summarize", "summary", "overview", "report", "digest"], Intent.SUMMARIZE, 0.80),
        (["mitre", "att&ck", "technique", "tactic", "ttp"], Intent.MITRE, 0.80),
        (["show", "list", "display", "get", "fetch", "filter", "where", "which"], Intent.FILTER, 0.70),
    ]

    def classify(self, text: str) -> Tuple[str, float]:
        lower = text.lower()
        best_intent = Intent.UNKNOWN
        best_conf = 0.0

        for keywords, intent, base_conf in self._RULES:
            hits = sum(1 for kw in keywords if kw in lower)
            if hits > 0:
                conf = min(1.0, base_conf + hits * 0.05)
                if conf > best_conf:
                    best_conf = conf
                    best_intent = intent

        return best_intent, best_conf


# ---------------------------------------------------------------------------
# Query executor
# ---------------------------------------------------------------------------

class QueryExecutor:
    """Routes parsed queries to the appropriate backend and executes them."""

    def __init__(self):
        self._cache: Dict[str, Tuple[float, Any]] = {}  # query_hash → (ts, result)
        self._cache_ttl = 60.0  # seconds

    def execute(self, query: ParsedQuery) -> Dict[str, Any]:
        # Cache hit
        import hashlib
        cache_key = hashlib.sha256(json.dumps(query.to_dict(), sort_keys=True).encode()).hexdigest()[:16]
        if cache_key in self._cache:
            ts, result = self._cache[cache_key]
            if time.time() - ts < self._cache_ttl:
                return {**result, "cached": True}

        result = self._dispatch(query)
        self._cache[cache_key] = (time.time(), result)
        return result

    def _dispatch(self, query: ParsedQuery) -> Dict[str, Any]:
        intent = query.intent

        if intent == Intent.MITRE:
            return self._mitre_query(query)
        elif intent == Intent.SUMMARIZE:
            return self._summarize(query)
        elif intent in (Intent.FILTER, Intent.AGGREGATE):
            return self._filter_query(query)
        elif intent == Intent.EXPLAIN:
            return self._explain_query(query)
        elif intent == Intent.HUNT:
            return self._hunt_query(query)
        else:
            # Fallback to vector search
            return self._vector_search(query)

    def _vector_search(self, query: ParsedQuery) -> Dict[str, Any]:
        try:
            from rag.vector_store import VectorStore
            vs = VectorStore()
            results = vs.search(query.raw, top_k=10)
            return {
                "backend": "vector_store",
                "results": results,
                "count": len(results),
            }
        except Exception as exc:
            return {"backend": "vector_store", "error": str(exc), "results": []}

    def _mitre_query(self, query: ParsedQuery) -> Dict[str, Any]:
        try:
            from rag.rag_engine import RAGEngine
            rag = RAGEngine()
            result = rag.query_rich(query.raw)
            return {
                "backend": "rag_mitre",
                "answer": result.get("answer", ""),
                "sources": result.get("sources", []),
                "ttps": query.ttps,
            }
        except Exception as exc:
            return {"backend": "rag_mitre", "error": str(exc)}

    def _summarize(self, query: ParsedQuery) -> Dict[str, Any]:
        try:
            from monitoring.dashboard import get_dashboard
            dash = get_dashboard()
            snapshot = dash.get_snapshot(query.time_window_minutes)
            report = dash.generate_report(max(1, query.time_window_minutes // 60))
            return {
                "backend": "dashboard",
                "snapshot": snapshot,
                "narrative": report.narrative,
                "kpis": report.kpis.to_dict(),
            }
        except Exception as exc:
            return {"backend": "dashboard", "error": str(exc)}

    def _filter_query(self, query: ParsedQuery) -> Dict[str, Any]:
        results = {}

        # UEBA results for entity queries
        if query.entity_ids or "entity" in query.raw.lower() or "user" in query.raw.lower():
            try:
                from analytics.ueba import UEBAEngine
                ueba = UEBAEngine()
                risks = ueba.get_high_risk_entities(query.threshold or 0.5)
                results["ueba"] = {
                    "high_risk_entities": risks,
                    "recent_anomalies": ueba.get_recent_anomalies(20),
                }
            except Exception as exc:
                results["ueba_error"] = str(exc)

        # Correlation results for protocol queries
        if query.protocols:
            try:
                from analytics.cross_protocol_correlator import CrossProtocolCorrelator
                correlator = CrossProtocolCorrelator()
                for proto in query.protocols:
                    corrs = correlator.get_correlations(
                        min_score=query.threshold or 0.5,
                        protocol_filter=proto,
                    )
                    if corrs:
                        results[f"correlations_{proto}"] = corrs
            except Exception as exc:
                results["correlator_error"] = str(exc)

        # IOC check for IP queries
        if query.src_ips:
            try:
                from rag.stix_ingestion import STIXIngestionEngine
                stix = STIXIngestionEngine()
                for ip in query.src_ips:
                    hit = stix.ioc_blacklist.check_ip(ip)
                    results[f"ioc_{ip}"] = {"malicious": hit is not None, "ioc": hit}
            except Exception as exc:
                results["ioc_error"] = str(exc)

        return {"backend": "filter", "results": results, "query": query.to_dict()}

    def _explain_query(self, query: ParsedQuery) -> Dict[str, Any]:
        """Use Claude for complex explanation queries."""
        try:
            import anthropic
            client = anthropic.Anthropic()
            context = json.dumps(query.to_dict(), indent=2)
            response = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=400,
                system=(
                    "You are SHADOW-ML, an expert AI security analyst. "
                    "Answer the user's security question concisely and accurately. "
                    "Focus on actionable insights. Keep response under 200 words."
                ),
                messages=[{
                    "role": "user",
                    "content": f"Query: {query.raw}\n\nExtracted context:\n{context}",
                }],
            )
            return {
                "backend": "claude",
                "explanation": response.content[0].text,
                "model": "claude-sonnet-4-6",
            }
        except ImportError:
            return self._vector_search(query)
        except Exception as exc:
            return {"backend": "claude", "error": str(exc)}

    def _hunt_query(self, query: ParsedQuery) -> Dict[str, Any]:
        try:
            from rag.threat_hunter import ThreatHuntingEngine
            hunter = ThreatHuntingEngine()
            findings = hunter.get_recent_findings(20)
            # Filter by protocol if specified
            if query.protocols:
                findings = [f for f in findings
                            if any(p in str(f).lower() for p in query.protocols)]
            return {
                "backend": "threat_hunter",
                "findings": findings,
                "count": len(findings),
                "protocols_searched": query.protocols,
            }
        except Exception as exc:
            return {"backend": "threat_hunter", "error": str(exc)}


# ---------------------------------------------------------------------------
# Response formatter
# ---------------------------------------------------------------------------

class ResponseFormatter:
    """Formats executor results into analyst-friendly responses."""

    def format(self, query: ParsedQuery, result: Dict[str, Any]) -> Dict[str, Any]:
        summary = self._build_summary(query, result)
        return {
            "query": query.raw,
            "intent": query.intent,
            "parsed": query.to_dict(),
            "result": result,
            "summary": summary,
            "timestamp": time.time(),
        }

    def _build_summary(self, query: ParsedQuery, result: Dict[str, Any]) -> str:
        intent = query.intent

        if intent == Intent.EXPLAIN and "explanation" in result:
            return result["explanation"]

        if intent == Intent.SUMMARIZE and "narrative" in result:
            return result["narrative"]

        if intent == Intent.AGGREGATE:
            counts = []
            for key, val in result.get("results", {}).items():
                if isinstance(val, list):
                    counts.append(f"{len(val)} {key}")
                elif isinstance(val, dict):
                    counts.append(f"{key}: {json.dumps(val)[:80]}")
            return f"Query returned: {'; '.join(counts) or 'no results'}."

        if intent == Intent.HUNT:
            n = result.get("count", 0)
            return f"Found {n} threat hunting findings matching your query."

        if intent == Intent.MITRE and "answer" in result:
            return result["answer"][:300]

        # Generic summary
        backend = result.get("backend", "unknown")
        items = result.get("results", result.get("count", 0))
        if isinstance(items, list):
            return f"Query executed via {backend}: {len(items)} results returned."
        elif isinstance(items, dict):
            return f"Query executed via {backend}: {len(items)} result categories."
        return f"Query executed via {backend}."


# ---------------------------------------------------------------------------
# Main NLP Query Engine
# ---------------------------------------------------------------------------

class NLPQueryEngine:
    """
    SHADOW-ML Natural-Language Threat Query Engine v10.0

    Accepts free-text security questions and routes them to the appropriate
    analytics backend, returning structured data and a plain-English summary.
    """

    VERSION = "10.0.0"

    def __init__(self):
        self._extractor   = EntityExtractor()
        self._classifier  = IntentClassifier()
        self._executor    = QueryExecutor()
        self._formatter   = ResponseFormatter()
        self._stats: Dict[str, Any] = {
            "queries_processed": 0,
            "by_intent": {},
            "cache_hits": 0,
            "errors": 0,
        }
        logger.info("NLPQueryEngine v%s initialised", self.VERSION)

    def query(self, text: str) -> Dict[str, Any]:
        """Process a natural-language threat query end-to-end."""
        t0 = time.perf_counter()
        self._stats["queries_processed"] += 1

        try:
            # 1. Classify intent
            intent, conf = self._classifier.classify(text)

            # 2. Extract entities
            entities = self._extractor.extract(text)

            # 3. Build parsed query
            # Extract keywords (non-stopword tokens)
            stopwords = {"the", "a", "an", "in", "of", "for", "and", "or", "is",
                         "are", "was", "were", "to", "me", "show", "from", "all"}
            keywords = [w for w in re.findall(r"\b[a-z]{3,}\b", text.lower())
                        if w not in stopwords][:10]

            parsed = ParsedQuery(
                raw=text,
                intent=intent,
                protocols=entities["protocols"],
                src_ips=entities["ips"],
                threat_levels=entities["levels"],
                ttps=entities["ttps"],
                time_window_minutes=entities["time_minutes"],
                threshold=entities["threshold"],
                keywords=keywords,
                confidence=conf,
            )

            # 4. Execute
            result = self._executor.execute(parsed)
            if result.get("cached"):
                self._stats["cache_hits"] = self._stats.get("cache_hits", 0) + 1

            # 5. Format response
            response = self._formatter.format(parsed, result)
            response["processing_ms"] = round((time.perf_counter() - t0) * 1000, 2)

            # Update intent stats
            self._stats["by_intent"][intent] = self._stats["by_intent"].get(intent, 0) + 1

            return response

        except Exception as exc:
            self._stats["errors"] = self._stats.get("errors", 0) + 1
            logger.exception("NLP query failed: %s", exc)
            return {
                "query": text,
                "error": str(exc),
                "summary": "Query processing failed. Please try rephrasing.",
                "processing_ms": round((time.perf_counter() - t0) * 1000, 2),
            }

    def batch_query(self, queries: List[str]) -> List[Dict[str, Any]]:
        """Process multiple queries sequentially."""
        return [self.query(q) for q in queries]

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "version": self.VERSION}

    def suggest_queries(self, context: str = "") -> List[str]:
        """Return example queries relevant to the current threat context."""
        suggestions = [
            "Show me all critical ADS-B anomalies in the last hour",
            "Which users have impossible travel anomalies today?",
            "Find DNS beaconing patterns in the last 30 minutes",
            "What MITRE ATT&CK techniques match a BGP route hijack?",
            "List SCADA incidents above threat score 0.8",
            "Explain why the last IEC104 alert was flagged",
            "Summarize the threat landscape for the last 24 hours",
            "Hunt for signs of lateral movement in the airport network",
            "Show me all cross-protocol correlations involving ADS-B and IEC104",
            "Which entities were seen on multiple protocols in the last hour?",
        ]
        if context:
            # Filter for relevance to context
            context_lower = context.lower()
            filtered = [s for s in suggestions
                        if any(w in s.lower() for w in context_lower.split())]
            return filtered or suggestions[:5]
        return suggestions


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_engine: Optional[NLPQueryEngine] = None


def get_nlp_engine() -> NLPQueryEngine:
    global _engine
    if _engine is None:
        _engine = NLPQueryEngine()
    return _engine
