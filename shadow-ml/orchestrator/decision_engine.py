"""
orchestrator/decision_engine.py — SHADOW-ML Decision Engine v10.0

The sovereign brain of Shadow-ML:
  • Fuses signals from neural engine, honeypot, canary, anomaly detectors
  • Applies MITRE ATT&CK kill-chain reasoning
  • Selects optimal defense combination via multi-armed bandit
  • Maintains full audit trail for SOC analysts
  • Integrates with death-trap, quantum-noise, and reflection engines
"""

from __future__ import annotations

import logging
import math
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("shadow.orchestrator.decision")


class ThreatLevel(str, Enum):
    LOW         = "low"
    MEDIUM      = "medium"
    HIGH        = "high"
    CRITICAL    = "critical"
    EMERGENCY   = "emergency"
    APOCALYPTIC = "apocalyptic"


THREAT_SCORE_MAP = {
    ThreatLevel.LOW:         (0.00, 0.20),
    ThreatLevel.MEDIUM:      (0.20, 0.40),
    ThreatLevel.HIGH:        (0.40, 0.65),
    ThreatLevel.CRITICAL:    (0.65, 0.80),
    ThreatLevel.EMERGENCY:   (0.80, 0.92),
    ThreatLevel.APOCALYPTIC: (0.92, 1.00),
}

DEFENSE_MATRIX: Dict[ThreatLevel, List[str]] = {
    ThreatLevel.LOW:         ["monitor", "log"],
    ThreatLevel.MEDIUM:      ["alert_analyst", "increase_sampling", "scan_source"],
    ThreatLevel.HIGH:        ["isolate_source", "honeypot_redirect", "canary_deploy", "block_lateral"],
    ThreatLevel.CRITICAL:    ["block_ip", "quarantine_asset", "engage_death_trap", "notify_soc",
                              "quantum_noise_injection", "snapshot_evidence"],
    ThreatLevel.EMERGENCY:   ["all_critical_defenses", "attack_reflection", "chameleon_activate",
                              "soc_escalation", "kill_session", "netflow_capture", "forensic_dump"],
    ThreatLevel.APOCALYPTIC: ["omega_protocol", "phoenix_rebirth", "death_star_defense",
                              "suicide_model", "full_isolation", "government_notify",
                              "air_gap_critical_assets", "wipe_model_weights"],
}


@dataclass
class DecisionRecord:
    decision_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)
    threat_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.LOW
    source_ip: str = ""
    attack_type: str = "unknown"
    confidence: float = 0.0
    defenses_activated: List[str] = field(default_factory=list)
    signals: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    analyst_override: Optional[str] = None
    outcome: str = "pending"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "threat_score": round(self.threat_score, 4),
            "threat_level": self.threat_level,
            "source_ip": self.source_ip,
            "attack_type": self.attack_type,
            "confidence": round(self.confidence, 4),
            "defenses_activated": self.defenses_activated,
            "reasoning": self.reasoning,
            "outcome": self.outcome,
        }


class _MultiArmedBandit:
    """
    Upper Confidence Bound (UCB1) bandit for defense action selection.
    Learns which defense combinations are most effective over time.
    """

    def __init__(self, actions: List[str]):
        self.actions = actions
        self._counts = {a: 0 for a in actions}
        self._rewards = {a: 0.0 for a in actions}
        self._t = 0

    def select(self, threat_level: ThreatLevel) -> List[str]:
        """Select optimal defense subset using UCB1."""
        mandatory = DEFENSE_MATRIX.get(threat_level, ["monitor"])
        self._t += 1
        # UCB bonus for under-explored actions
        ucb_scores = {}
        for action in self.actions:
            n = self._counts[action]
            if n == 0:
                ucb_scores[action] = float("inf")
            else:
                avg = self._rewards[action] / n
                bonus = math.sqrt(2 * math.log(self._t) / n)
                ucb_scores[action] = avg + bonus
        # Augment mandatory defenses with highest-UCB extras
        extras = sorted(
            [a for a in self.actions if a not in mandatory],
            key=lambda a: ucb_scores[a],
            reverse=True,
        )[:2]
        return list(mandatory) + extras

    def update(self, action: str, reward: float) -> None:
        if action in self._counts:
            self._counts[action] += 1
            self._rewards[action] += reward


ALL_DEFENSE_ACTIONS = [
    "monitor", "log", "alert_analyst", "increase_sampling", "scan_source",
    "isolate_source", "honeypot_redirect", "canary_deploy", "block_lateral",
    "block_ip", "quarantine_asset", "engage_death_trap", "notify_soc",
    "quantum_noise_injection", "snapshot_evidence", "attack_reflection",
    "chameleon_activate", "soc_escalation", "kill_session", "netflow_capture",
    "forensic_dump", "omega_protocol", "phoenix_rebirth", "death_star_defense",
    "suicide_model", "full_isolation", "government_notify", "air_gap_critical_assets",
    "wipe_model_weights",
]


class _SignalFuser:
    """
    Combines signals from multiple detectors using Bayesian fusion.
    Sources: neural_engine, honeypot, canary, rl_agent, anomaly, rag.
    """

    SOURCE_WEIGHTS = {
        "neural_engine": 0.35,
        "honeypot":      0.20,
        "canary":        0.15,
        "rl_agent":      0.15,
        "anomaly":       0.10,
        "rag":           0.05,
    }

    def fuse(self, signals: Dict[str, float]) -> Tuple[float, float]:
        """Returns (fused_score, confidence)."""
        total_weight = 0.0
        weighted_sum = 0.0
        variance_sum = 0.0

        for source, score in signals.items():
            w = self.SOURCE_WEIGHTS.get(source, 0.05)
            weighted_sum += w * score
            total_weight += w
            variance_sum += w * (score - weighted_sum / max(total_weight, 1e-8)) ** 2

        fused = weighted_sum / max(total_weight, 1e-8)
        std = math.sqrt(variance_sum / max(total_weight, 1e-8))
        confidence = max(0.0, 1.0 - std)
        return min(1.0, fused), min(1.0, confidence)


class DecisionEngine:
    """
    SHADOW-ML Decision Engine v10.0

    Processes multi-source threat signals and produces actionable defense decisions.
    """

    VERSION = "10.0.0"

    def __init__(self):
        self._bandit = _MultiArmedBandit(ALL_DEFENSE_ACTIONS)
        self._fuser = _SignalFuser()
        self._history: List[DecisionRecord] = []
        self._feedback_buffer: List[Tuple[str, float]] = []  # (action, reward)
        logger.info("DecisionEngine v%s initialised", self.VERSION)

    # ── Primary API ──────────────────────────────────────────────────────────

    def evaluate(self, signals: Dict[str, Any]) -> str:
        """
        Lightweight compatibility shim — returns threat level string.
        For full decision use `decide()`.
        """
        record = self.decide(signals)
        return record.threat_level

    def decide(self, signals: Dict[str, Any]) -> DecisionRecord:
        """
        Full decision pipeline.

        signals: dict with optional keys:
          neural_engine, honeypot, canary, rl_agent, anomaly, rag (all floats 0-1)
          source_ip, attack_type, metadata
        """
        # Extract scores
        score_signals = {
            k: float(v) for k, v in signals.items()
            if k in self._fuser.SOURCE_WEIGHTS and isinstance(v, (int, float))
        }
        if not score_signals:
            score_signals = {"neural_engine": 0.1}

        fused_score, confidence = self._fuser.fuse(score_signals)
        level = self._score_to_level(fused_score)
        defenses = self._bandit.select(level)

        source_ip = str(signals.get("source_ip", ""))
        attack_type = str(signals.get("attack_type", "unknown"))

        reasoning = self._build_reasoning(fused_score, level, score_signals, attack_type)

        record = DecisionRecord(
            threat_score=fused_score,
            threat_level=level,
            source_ip=source_ip,
            attack_type=attack_type,
            confidence=confidence,
            defenses_activated=defenses,
            signals=score_signals,
            reasoning=reasoning,
        )
        self._history.append(record)
        logger.info(
            "Decision: level=%s score=%.3f confidence=%.3f ip=%s defenses=%s",
            level, fused_score, confidence, source_ip, defenses[:3],
        )
        return record

    def feedback(self, decision_id: str, effective: bool, reward_override: Optional[float] = None) -> None:
        """SOC analyst feedback to update bandit rewards."""
        record = next((r for r in self._history if r.decision_id == decision_id), None)
        if not record:
            logger.warning("Decision %s not found for feedback", decision_id)
            return
        reward = reward_override if reward_override is not None else (1.0 if effective else -0.5)
        record.outcome = "effective" if effective else "ineffective"
        for action in record.defenses_activated:
            self._bandit.update(action, reward)
        logger.info("Feedback recorded: decision=%s effective=%s reward=%.2f", decision_id, effective, reward)

    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._history[-limit:]]

    def get_stats(self) -> Dict[str, Any]:
        if not self._history:
            return {"total_decisions": 0}
        scores = [r.threat_score for r in self._history]
        level_counts: Dict[str, int] = {}
        for r in self._history:
            level_counts[r.threat_level] = level_counts.get(r.threat_level, 0) + 1
        return {
            "total_decisions": len(self._history),
            "avg_threat_score": round(sum(scores) / len(scores), 4),
            "max_threat_score": round(max(scores), 4),
            "level_distribution": level_counts,
            "effective_rate": self._effective_rate(),
        }

    # ── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _score_to_level(score: float) -> ThreatLevel:
        for level, (lo, hi) in THREAT_SCORE_MAP.items():
            if lo <= score < hi:
                return level
        return ThreatLevel.APOCALYPTIC if score >= 1.0 else ThreatLevel.LOW

    @staticmethod
    def _build_reasoning(score: float, level: ThreatLevel, signals: Dict[str, float], attack_type: str) -> str:
        top_source = max(signals, key=signals.get) if signals else "unknown"
        return (
            f"Fused threat score {score:.3f} → level={level}. "
            f"Primary signal: {top_source}={signals.get(top_source, 0):.3f}. "
            f"Attack type: {attack_type}."
        )

    def _effective_rate(self) -> float:
        outcomes = [r.outcome for r in self._history if r.outcome != "pending"]
        if not outcomes:
            return 0.0
        return round(sum(1 for o in outcomes if o == "effective") / len(outcomes), 4)
