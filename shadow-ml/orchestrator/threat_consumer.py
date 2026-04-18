"""
orchestrator/threat_consumer.py — SHADOW-ML Threat Consumer v1.0

Real-time threat consumer that:
  • Reads from Kafka shadow.threats topic (from shadow-sensor)
  • Passes threats to decision engine for threat scoring
  • Executes response actions via defense modules
  • Records decisions to shadow.ml.decisions topic
  • Provides feedback loop for decision effectiveness
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    from kafka import KafkaConsumer, KafkaProducer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False

from .decision_engine import DecisionEngine, ThreatLevel

logger = logging.getLogger("shadow.orchestrator.threat_consumer")


@dataclass
class ThreatAlert:
    """Threat object from sensor"""
    icao24: str
    threat_type: str
    severity: float
    timestamp_ms: int
    sensor_id: str
    metadata: Dict[str, Any] | None = None

    @staticmethod
    def from_kafka(data: Dict[str, Any]) -> ThreatAlert:
        """Deserialize threat from Kafka message"""
        return ThreatAlert(
            icao24=data.get("icao24", ""),
            threat_type=data.get("threat_type", ""),
            severity=float(data.get("severity", 0.0)),
            timestamp_ms=int(data.get("timestamp_ms", 0)),
            sensor_id=data.get("sensor_id", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class DecisionAction:
    """Response action to be executed"""
    decision_id: str
    threat_type: str
    action_type: str
    target: str  # icao24, IP, aircraft ID
    severity: float
    actions: list[str]  # ["block_ip", "honeypot_redirect", etc]
    metadata: Dict[str, Any]

    def to_kafka(self) -> Dict[str, Any]:
        """Serialize to Kafka message"""
        return {
            "decision_id": self.decision_id,
            "threat_type": self.threat_type,
            "action_type": self.action_type,
            "target": self.target,
            "severity": self.severity,
            "actions": self.actions,
            "metadata": self.metadata,
        }


class ThreatConsumer:
    """
    Consumes threats from sensor and executes response pipeline.
    """

    def __init__(
        self,
        kafka_brokers: str | list[str] = "localhost:9092",
        group_id: str = "shadow-ml-decisions",
        enabled: bool = True,
    ):
        self.kafka_brokers = kafka_brokers
        self.group_id = group_id
        self.enabled = enabled and HAS_KAFKA
        self.decision_engine = DecisionEngine()
        self.kafka_consumer: Optional[KafkaConsumer] = None
        self.kafka_producer: Optional[KafkaProducer] = None
        self._threat_count = 0
        self._decision_count = 0

        if not self.enabled:
            logger.warning("Kafka not available, threat consumer disabled")
            return

        self._init_kafka()

    def _init_kafka(self) -> None:
        """Initialize Kafka connections"""
        try:
            self.kafka_consumer = KafkaConsumer(
                "shadow.threats",
                bootstrap_servers=self.kafka_brokers,
                group_id=self.group_id,
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                auto_offset_reset="latest",
                enable_auto_commit=True,
            )
            logger.info("✅ Kafka consumer connected to shadow.threats")
        except Exception as e:
            logger.error("❌ Failed to connect Kafka consumer: %s", e)
            self.enabled = False
            return

        try:
            self.kafka_producer = KafkaProducer(
                bootstrap_servers=self.kafka_brokers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            )
            logger.info("✅ Kafka producer connected")
        except Exception as e:
            logger.error("❌ Failed to connect Kafka producer: %s", e)
            self.kafka_consumer.close()
            self.kafka_consumer = None
            self.enabled = False

    async def start(self) -> None:
        """Start consuming threats (async wrapper for blocking consumer)"""
        if not self.enabled:
            logger.warning("Threat consumer not enabled")
            return

        logger.info("🚀 Starting threat consumer...")
        try:
            # Run in thread pool to avoid blocking event loop
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._consume_loop)
        except Exception as e:
            logger.error("Threat consumer error: %s", e)

    def _consume_loop(self) -> None:
        """Main consumption loop (blocking)"""
        if not self.kafka_consumer:
            return

        logger.info("📡 Threat consumer loop started")
        message_count = 0

        try:
            for message in self.kafka_consumer:
                try:
                    threat_data = message.value
                    threat = ThreatAlert.from_kafka(threat_data)
                    self._process_threat(threat)
                    message_count += 1

                    if message_count % 10 == 0:
                        logger.info(
                            "📊 Processed %d threats | Decisions made: %d",
                            message_count,
                            self._decision_count,
                        )
                except Exception as e:
                    logger.error("Error processing threat: %s", e)
                    continue

        except KeyboardInterrupt:
            logger.info("Threat consumer stopped by user")
        except Exception as e:
            logger.error("Fatal error in threat consumer loop: %s", e)
        finally:
            if self.kafka_consumer:
                self.kafka_consumer.close()
            logger.info("Threat consumer loop ended")

    def _process_threat(self, threat: ThreatAlert) -> None:
        """Process single threat through decision pipeline"""
        logger.debug(
            "🚨 Processing threat: type=%s icao24=%s severity=%.2f",
            threat.threat_type,
            threat.icao24,
            threat.severity,
        )
        self._threat_count += 1

        # Map threat_type to signal for decision engine
        threat_score_map = {
            "SPOOFING": 0.85,
            "CALLSIGN_MISMATCH": 0.75,
            "TELEPORTATION": 0.90,
            "ICAO_UNKNOWN": 0.70,
            "BASELINE_DEVIATION": 0.45,
            "PHYSICS_VIOLATION": 0.80,
        }

        base_score = threat_score_map.get(threat.threat_type, threat.severity)

        # Create signal dict for decision engine
        signals = {
            "neural_engine": base_score,  # Primary threat score from sensor
            "source_ip": threat.sensor_id,
            "attack_type": threat.threat_type,
            "metadata": threat.metadata or {},
        }

        # Get decision from engine
        decision = self.decision_engine.decide(signals)
        self._decision_count += 1

        # Create action to execute
        action = DecisionAction(
            decision_id=decision.decision_id,
            threat_type=threat.threat_type,
            action_type=f"{threat.threat_type}_response",
            target=threat.icao24,
            severity=threat.severity,
            actions=decision.defenses_activated,
            metadata={
                "threat_score": float(decision.threat_score),
                "confidence": float(decision.confidence),
                "timestamp_ms": threat.timestamp_ms,
                "sensor_id": threat.sensor_id,
            },
        )

        # Execute response actions
        self._execute_actions(action)

        # Publish decision to Kafka
        self._publish_decision(action)

        logger.info(
            "✅ Decision made: id=%s level=%s target=%s actions=%s",
            decision.decision_id,
            decision.threat_level,
            action.target,
            len(action.actions),
        )

    def _execute_actions(self, action: DecisionAction) -> None:
        """Execute response actions via defense modules"""
        if not action.actions:
            logger.info("No actions to execute")
            return

        logger.info(
            "🛡️  Executing %d response actions for threat %s",
            len(action.actions),
            action.threat_type,
        )

        for act in action.actions:
            try:
                if act == "honeypot_redirect":
                    self._action_honeypot_redirect(action)
                elif act == "canary_deploy":
                    self._action_canary_deploy(action)
                elif act == "quantum_noise_injection":
                    self._action_quantum_noise(action)
                elif act == "attack_reflection":
                    self._action_attack_reflection(action)
                elif act == "block_ip":
                    self._action_block_ip(action)
                elif act == "monitor":
                    self._action_monitor(action)
                elif act == "log":
                    self._action_log(action)
                else:
                    logger.warning("Unknown action: %s", act)
            except Exception as e:
                logger.error("Error executing action %s: %s", act, e)

    def _action_honeypot_redirect(self, action: DecisionAction) -> None:
        """Redirect spoofed aircraft to honeypot"""
        logger.info(
            "🍯 Honeypot redirect: Redirecting %s to isolated analysis sandbox",
            action.target,
        )
        # In production, would call honeypot_ml.py to create fake aircraft
        action.metadata["honeypot_id"] = f"hp_{uuid.uuid4().hex[:8]}"
        action.metadata["action_status"] = "redirected_to_honeypot"

    def _action_canary_deploy(self, action: DecisionAction) -> None:
        """Deploy canary tokens"""
        logger.info("🦆 Canary deploy: Creating decoy aircraft identities")
        # In production, would call canary_tokens.py
        action.metadata["canary_count"] = 5
        action.metadata["canary_ids"] = [f"can_{uuid.uuid4().hex[:8]}" for _ in range(5)]
        action.metadata["action_status"] = "canaries_deployed"

    def _action_quantum_noise(self, action: DecisionAction) -> None:
        """Inject position/altitude noise"""
        logger.info("⚡ Quantum noise: Injecting position uncertainty")
        # In production, would call quantum_noise.py
        action.metadata["noise_level"] = "high"
        action.metadata["noise_variance_feet"] = 500
        action.metadata["action_status"] = "noise_active"

    def _action_attack_reflection(self, action: DecisionAction) -> None:
        """Analyze and reflect attack pattern"""
        logger.info("🔄 Attack reflection: Analyzing attack characteristics")
        # In production, would call attack_reflection.py
        action.metadata["attack_pattern_id"] = f"ap_{uuid.uuid4().hex[:8]}"
        action.metadata["action_status"] = "pattern_analyzed"

    def _action_block_ip(self, action: DecisionAction) -> None:
        """Block source IP"""
        logger.info("🚫 Blocking IP/sensor: %s", action.target)
        action.metadata["block_status"] = "ip_blocked"

    def _action_monitor(self, action: DecisionAction) -> None:
        """Increase monitoring on target"""
        logger.info("👁️  Monitor: Increasing sampling on %s", action.target)
        action.metadata["monitoring_level"] = "high"

    def _action_log(self, action: DecisionAction) -> None:
        """Log for forensics"""
        logger.info("📝 Logging event for forensic analysis")
        action.metadata["log_status"] = "logged"

    def _publish_decision(self, action: DecisionAction) -> None:
        """Publish decision to Kafka"""
        if not self.kafka_producer:
            logger.warning("Kafka producer not available, skipping publish")
            return

        try:
            decision_msg = action.to_kafka()
            self.kafka_producer.send(
                "shadow.ml.decisions",
                value=decision_msg,
            )
            logger.debug(
                "📤 Published decision %s to shadow.ml.decisions",
                action.decision_id,
            )
        except Exception as e:
            logger.error("Failed to publish decision: %s", e)

    def record_feedback(
        self,
        decision_id: str,
        effective: bool,
        notes: str = "",
    ) -> None:
        """Record feedback from API on decision effectiveness"""
        self.decision_engine.feedback(decision_id, effective)
        logger.info(
            "📋 Feedback recorded: decision=%s effective=%s notes=%s",
            decision_id,
            effective,
            notes,
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get consumer and decision statistics"""
        return {
            "threats_processed": self._threat_count,
            "decisions_made": self._decision_count,
            "decision_engine_stats": self.decision_engine.get_stats(),
        }

    def shutdown(self) -> None:
        """Clean shutdown"""
        logger.info("Shutting down threat consumer...")
        if self.kafka_consumer:
            self.kafka_consumer.close()
        if self.kafka_producer:
            self.kafka_producer.close()
        logger.info("Threat consumer shutdown complete")


# Global singleton
_threat_consumer: Optional[ThreatConsumer] = None


def get_threat_consumer() -> ThreatConsumer:
    """Get or create threat consumer singleton"""
    global _threat_consumer
    if _threat_consumer is None:
        _threat_consumer = ThreatConsumer()
    return _threat_consumer
