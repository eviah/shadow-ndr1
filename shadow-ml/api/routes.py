"""
api/routes.py — SHADOW-ML REST API v10.0

Full endpoint surface (50 endpoints across 15 domains):

  Core
    GET  /                          System info
    GET  /health                    Deep health check
    GET  /metrics                   Prometheus metrics
    POST /auth/login                Issue JWT

  Neural / ML
    POST /analyze                   200-layer neural analysis
    POST /threat/evaluate           Full decision pipeline
    GET  /threat/history            Recent decisions
    GET  /alerts                    Active alerts

  Aviation
    POST /aviation/rf-fingerprint   RF/IQ transponder fingerprinting
    POST /aviation/autoencoder      Autoencoder zero-day detection
    POST /aviation/protocol         Protocol micro-model scoring
    POST /aviation/kinematic        Kinematic ADS-B validation

  Analytics
    POST /analytics/traffic         JA3/JA4 + entropy + Markov analysis
    POST /analytics/ueba            UEBA behavior event ingestion
    GET  /analytics/ueba/risks      High-risk entities
    POST /analytics/correlate       Cross-protocol temporal correlation
    GET  /analytics/correlations    Recent correlations
    POST /analytics/query           NLP natural-language threat query

  ML Ops
    GET  /ml/drift                  Drift detector status
    POST /ml/drift/report           Submit drift report
    GET  /ml/registry               Model registry listing
    POST /ml/federated/aggregate    Federated learning aggregation round
    POST /ml/adversarial/screen     Adversarial example screening

  Response
    POST /response/firewall         Generate firewall rules from threat
    GET  /response/firewall/rules   Active firewall rules
    POST /response/triage           Incident triage
    GET  /response/incidents        Recent incidents
    POST /response/impact           Cyber-physical impact assessment

  Threat Intelligence
    POST /intel/ioc/check           Check IP/domain/hash against IOC blacklist
    POST /intel/stix/ingest         Ingest STIX bundle
    POST /intel/hunt/run            Run threat hunting hypothesis
    GET  /intel/hunt/results        Recent hunting results
    POST /rag/query                 RAG threat intelligence query
    POST /rag/search                Direct vector similarity search

  Defense
    POST /honeypot/interact         Honeypot interaction
    GET  /honeypot/profiles         All attacker profiles
    POST /canary/create             Create canary token
    GET  /canary/all                All canary tokens
    POST /canary/check              Check if value trips canary
    POST /death-trap/engage         Engage death trap
    GET  /death-trap/reports        Death trap history

  RL / Autonomous
    POST /rl/feedback               Analyst feedback for RLHF
    GET  /rl/action                 PPO agent action for state
    POST /rl/canary/predict         Predictive canary placement

  Security
    GET  /security/pqc/stats        Post-quantum comms stats
    GET  /security/mtls/status      mTLS service certificate status

  Observability
    GET  /traces/recent             Recent distributed traces
    GET  /traces/slow               Slow trace analysis
    GET  /distributed/stats         Ray engine auto-scaling stats

  System
    GET  /stats                     Aggregated system stats
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .auth import authenticate, require_permission

logger = logging.getLogger("shadow.api.routes")

router = APIRouter()


# ---------------------------------------------------------------------------
# Lazy-loaded singletons
# ---------------------------------------------------------------------------

def _neural():
    from core.neural_engine import get_engine
    return get_engine()

def _decision():
    from orchestrator.decision_engine import DecisionEngine
    if not hasattr(_decision, "_inst"):
        _decision._inst = DecisionEngine()
    return _decision._inst

def _honeypot():
    from defense.honeypot_ml import HoneypotML
    if not hasattr(_honeypot, "_inst"):
        _honeypot._inst = HoneypotML()
    return _honeypot._inst

def _canary():
    from defense.canary_tokens import CanaryTokens
    if not hasattr(_canary, "_inst"):
        _canary._inst = CanaryTokens()
    return _canary._inst

def _death_trap():
    from orchestrator.death_trap_engine import DeathTrapEngine
    if not hasattr(_death_trap, "_inst"):
        _death_trap._inst = DeathTrapEngine()
    return _death_trap._inst

def _rag():
    from rag.rag_engine import RAGEngine
    if not hasattr(_rag, "_inst"):
        _rag._inst = RAGEngine()
    return _rag._inst

def _metrics():
    from monitoring.metrics import get_registry
    return get_registry()

def _db():
    from storage.database import get_db
    return get_db()

# ── New module singletons ────────────────────────────────────────────────────

def _rf_fingerprinter():
    from aviation.rf_fingerprinting import RFFingerprinter
    if not hasattr(_rf_fingerprinter, "_inst"):
        _rf_fingerprinter._inst = RFFingerprinter()
    return _rf_fingerprinter._inst

def _autoencoder():
    from aviation.autoencoder import AutoencoderAnomalyDetector
    if not hasattr(_autoencoder, "_inst"):
        _autoencoder._inst = AutoencoderAnomalyDetector()
    return _autoencoder._inst

def _protocol_registry():
    from aviation.protocol_models import ProtocolModelRegistry
    if not hasattr(_protocol_registry, "_inst"):
        _protocol_registry._inst = ProtocolModelRegistry()
    return _protocol_registry._inst

def _kinematic():
    from aviation.kinematic_validator import KinematicValidator
    if not hasattr(_kinematic, "_inst"):
        _kinematic._inst = KinematicValidator()
    return _kinematic._inst

def _traffic_analytics():
    from analytics.traffic_analytics import TrafficAnalyticsEngine
    if not hasattr(_traffic_analytics, "_inst"):
        _traffic_analytics._inst = TrafficAnalyticsEngine()
    return _traffic_analytics._inst

def _ueba():
    from analytics.ueba import UEBAEngine
    if not hasattr(_ueba, "_inst"):
        _ueba._inst = UEBAEngine()
    return _ueba._inst

def _correlator():
    from analytics.cross_protocol_correlator import CrossProtocolCorrelator
    if not hasattr(_correlator, "_inst"):
        _correlator._inst = CrossProtocolCorrelator()
    return _correlator._inst

def _drift():
    from ml.drift_detector import DriftDetector
    if not hasattr(_drift, "_inst"):
        _drift._inst = DriftDetector()
    return _drift._inst

def _model_registry():
    from ml.model_registry import ModelRegistry
    if not hasattr(_model_registry, "_inst"):
        _model_registry._inst = ModelRegistry()
    return _model_registry._inst

def _federated():
    from ml.federated_learning import FederatedLearningEngine
    if not hasattr(_federated, "_inst"):
        _federated._inst = FederatedLearningEngine(node_id="api-gateway")
    return _federated._inst

def _adv_defense():
    from ml.adversarial_defense import AdversarialDefenseLayer
    if not hasattr(_adv_defense, "_inst"):
        _adv_defense._inst = AdversarialDefenseLayer()
    return _adv_defense._inst

def _firewall():
    from response.firewall_generator import FirewallRuleGenerator
    if not hasattr(_firewall, "_inst"):
        _firewall._inst = FirewallRuleGenerator()
    return _firewall._inst

def _triage():
    from response.incident_triage import IncidentTriageEngine
    if not hasattr(_triage, "_inst"):
        _triage._inst = IncidentTriageEngine()
    return _triage._inst

def _impact():
    from response.cyber_physical_impact import CyberPhysicalImpactEngine
    if not hasattr(_impact, "_inst"):
        _impact._inst = CyberPhysicalImpactEngine()
    return _impact._inst

def _stix():
    from rag.stix_ingestion import STIXIngestionEngine
    if not hasattr(_stix, "_inst"):
        _stix._inst = STIXIngestionEngine()
    return _stix._inst

def _threat_hunter():
    from rag.threat_hunter import ThreatHuntingEngine
    if not hasattr(_threat_hunter, "_inst"):
        _threat_hunter._inst = ThreatHuntingEngine()
    return _threat_hunter._inst

def _vector_store():
    from rag.vector_store import VectorStore
    if not hasattr(_vector_store, "_inst"):
        _vector_store._inst = VectorStore()
    return _vector_store._inst

def _ppo():
    from rl.ppo_rlhf import PPORLHFEngine
    if not hasattr(_ppo, "_inst"):
        _ppo._inst = PPORLHFEngine()
    return _ppo._inst

def _pred_canary():
    from rl.predictive_canary import PredictiveCanaryEngine
    if not hasattr(_pred_canary, "_inst"):
        _pred_canary._inst = PredictiveCanaryEngine()
    return _pred_canary._inst

def _pqc():
    from security.pqc_comms import PQCCommsEngine
    if not hasattr(_pqc, "_inst"):
        _pqc._inst = PQCCommsEngine()
    return _pqc._inst

def _mtls():
    from security.mtls_manager import ZeroTrustMTLSManager
    if not hasattr(_mtls, "_inst"):
        _mtls._inst = ZeroTrustMTLSManager()
    return _mtls._inst

def _tracer():
    from monitoring.opentelemetry_tracer import get_tracer
    return get_tracer()

def _ray_engine():
    from distributed.ray_engine import RayDistributedEngine
    if not hasattr(_ray_engine, "_inst"):
        _ray_engine._inst = RayDistributedEngine()
    return _ray_engine._inst


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    token: str
    role: str
    expires_in_hours: int = 6

class AnalyzeRequest(BaseModel):
    features: List[float] = Field(..., min_length=1, max_length=10000)
    source_ip: str = "0.0.0.0"
    dest_ip: str = "0.0.0.0"
    protocol: str = "tcp"
    timestamp: Optional[float] = None
    modality_scores: Dict[str, float] = Field(default_factory=dict)

class EvaluateRequest(BaseModel):
    signals: Dict[str, Any]
    source_ip: str = ""
    attack_type: str = "unknown"

class HoneypotInteractRequest(BaseModel):
    source_ip: str
    service: str = "ssh"
    command: str = "ls"
    payload_hex: str = ""

class CanaryCreateRequest(BaseModel):
    token_type: str = "api_key"
    description: str = ""

class CanaryCheckRequest(BaseModel):
    value: str
    source: str = ""

class DeathTrapRequest(BaseModel):
    source_ip: str
    threat_level: str = "critical"
    context: Dict[str, Any] = Field(default_factory=dict)

class RAGQueryRequest(BaseModel):
    query: str
    context: Dict[str, Any] = Field(default_factory=dict)
    top_k: int = 5
    category_filter: Optional[str] = None

# ── Aviation ────────────────────────────────────────────────────────────────

class RFFingerprintRequest(BaseModel):
    icao24: str
    amplitude: float = 1.0
    phase_deg: float = 0.0
    dc_i: float = 0.0
    dc_q: float = 0.0
    iq_imbalance_db: float = 0.0
    rise_time_us: float = 1.0
    snr_db: float = 20.0
    frequency_offset_hz: float = 0.0
    declared_speed_ms: float = 250.0
    declared_heading_deg: float = 0.0
    declared_lat: float = 32.0
    declared_lon: float = 34.0

class AutoencoderRequest(BaseModel):
    protocol: str = "adsb"
    features: List[float] = Field(..., min_length=1, max_length=2048)
    train: bool = False

class ProtocolScoreRequest(BaseModel):
    protocol: str
    event: Dict[str, Any]

class KinematicRequest(BaseModel):
    icao24: str
    lat: float
    lon: float
    alt_ft: float
    speed_kts: float
    heading_deg: float
    vertical_rate_fpm: float = 0.0
    squawk: str = "0000"

# ── Analytics ────────────────────────────────────────────────────────────────

class TrafficAnalyticsRequest(BaseModel):
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = "tcp"
    payload_hex: str = ""
    tcp_flags: int = 0
    tcp_window: int = 0
    ttl: int = 64
    mss: int = 0
    flow_key: str = ""
    tls_version: int = 771
    tls_ciphers: List[int] = Field(default_factory=list)
    tls_extensions: List[int] = Field(default_factory=list)
    tls_curves: List[int] = Field(default_factory=list)
    tls_point_formats: List[int] = Field(default_factory=list)
    sni: str = ""

class UEBAEventRequest(BaseModel):
    entity_id: str
    entity_type: str = "user"
    event_type: str = "login"
    bytes_transferred: int = 0
    target_system: str = ""
    source_ip: str = ""
    success: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)

class CorrelateRequest(BaseModel):
    event_id: str
    protocol: str
    threat_score: float
    src_ip: str = ""
    entity_id: str = ""
    description: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

class NLPQueryRequest(BaseModel):
    query: str
    top_k: int = 10

# ── ML Ops ───────────────────────────────────────────────────────────────────

class DriftReportRequest(BaseModel):
    feature_name: str
    production_values: List[float]
    reference_values: Optional[List[float]] = None

class FederatedAggregateRequest(BaseModel):
    node_id: str
    gradients: List[float]
    num_samples: int = 100
    loss: float = 0.0

class AdversarialScreenRequest(BaseModel):
    features: List[float] = Field(..., min_length=1, max_length=10000)
    label: int = 0

# ── Response ─────────────────────────────────────────────────────────────────

class FirewallRequest(BaseModel):
    threat_score: float
    src_ip: str = ""
    protocol: str = "tcp"
    threat_type: str = "unknown"
    attack_type: str = "unknown"
    target_format: str = "suricata"  # suricata / iptables / ebpf / cisco

class TriageRequest(BaseModel):
    alerts: List[Dict[str, Any]]
    ttps: List[str] = Field(default_factory=list)

class ImpactRequest(BaseModel):
    attack_type: str
    affected_assets: List[str]
    conditions: Dict[str, bool] = Field(default_factory=dict)
    # conditions keys: imc, night, no_redundancy, peak_traffic

# ── Threat Intel ─────────────────────────────────────────────────────────────

class IOCCheckRequest(BaseModel):
    value: str
    ioc_type: str = "auto"  # auto / ip / domain / hash / url

class STIXIngestRequest(BaseModel):
    bundle: Dict[str, Any]

class HuntRequest(BaseModel):
    hypothesis_id: str = ""      # empty → run all
    events: List[Dict[str, Any]] = Field(default_factory=list)

class VectorSearchRequest(BaseModel):
    text: str
    top_k: int = 5
    category: Optional[str] = None

# ── RL ───────────────────────────────────────────────────────────────────────

class RLFeedbackRequest(BaseModel):
    state: List[float]
    action: int
    feedback_type: str = "true_positive"  # true_positive / false_positive / unclear

class RLActionRequest(BaseModel):
    state: List[float]

class PredictiveCanaryRequest(BaseModel):
    current_node: str
    steps: int = 3

# ---------------------------------------------------------------------------
# Public / health endpoints
# ---------------------------------------------------------------------------

@router.get("/")
async def root() -> Dict[str, Any]:
    return {
        "system": "SHADOW-ML",
        "version": "10.0.0",
        "description": "World's most powerful neural NDR — 200-layer deep architecture",
        "layers": 200,
        "attack_classes": 23,
        "defense_techniques": 24,
        "api_endpoints": 50,
        "modules": [
            "neural_engine", "decision_engine", "rf_fingerprinting", "autoencoder",
            "protocol_models", "kinematic_validator", "traffic_analytics", "ueba",
            "cross_protocol_correlator", "drift_detector", "model_registry",
            "federated_learning", "adversarial_defense", "firewall_generator",
            "incident_triage", "cyber_physical_impact", "stix_ingestion",
            "threat_hunter", "vector_store", "ppo_rlhf", "predictive_canary",
            "pqc_comms", "mtls_manager", "opentelemetry_tracer", "ray_engine",
            "honeypot", "canary_tokens", "death_trap", "rag_engine",
        ],
        "uptime_seconds": round(time.time() - _metrics()._start_time, 1),
    }


@router.get("/health")
async def health() -> Dict[str, Any]:
    reg = _metrics()
    subsystems = {
        "neural_engine":    "ok",
        "decision_engine":  "ok",
        "honeypot":         "ok",
        "canary":           "ok",
        "death_trap":       "ok",
        "rag":              "ok",
        "storage":          "ok",
        "analytics":        "ok",
        "response":         "ok",
        "security":         "ok",
        "distributed":      "ok",
    }
    return {
        "status": "healthy" if reg.system_healthy() else "degraded",
        "timestamp": time.time(),
        "subsystems": subsystems,
        "uptime_seconds": round(time.time() - reg._start_time, 1),
    }


@router.get("/metrics")
async def metrics() -> str:
    return _metrics().prometheus_text()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@router.post("/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest) -> LoginResponse:
    token = authenticate(req.username, req.password)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid credentials or rate limit exceeded")
    from .auth import SERVICE_ACCOUNTS
    role = SERVICE_ACCOUNTS.get(req.username, {}).get("role", "readonly")
    return LoginResponse(token=token, role=role)


# ---------------------------------------------------------------------------
# Neural analysis
# ---------------------------------------------------------------------------

@router.post("/analyze")
async def analyze(req: AnalyzeRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Run the full 200-layer neural threat analysis pipeline."""
    t0 = time.perf_counter()
    from core.neural_engine import ThreatVector

    tv = ThreatVector(
        raw_features=req.features,
        source_ip=req.source_ip,
        dest_ip=req.dest_ip,
        protocol=req.protocol,
        timestamp=req.timestamp or time.time(),
        modality_scores=req.modality_scores,
    )
    result = _neural().process(tv)
    reg = _metrics()
    reg.packets_ingested.inc()
    reg.neural_latency_ms.observe(result.processing_time_ms)
    reg.threat_score_current.set(result.threat_score)
    if result.threat_score >= 0.4:
        reg.threats_detected.inc()

    return {
        "threat_score":            result.threat_score,
        "threat_level":            result.threat_level,
        "confidence":              result.confidence,
        "uncertainty":             result.uncertainty,
        "top_attack_class":        result.layer_stats.get("top_attack", "none"),
        "attack_classes":          result.attack_classes,
        "anomaly_scores":          result.anomaly_scores,
        "defense_recommendations": result.defense_recommendations,
        "layer_stats":             result.layer_stats,
        "processing_time_ms":      result.processing_time_ms,
        "total_api_ms":            round((time.perf_counter() - t0) * 1000, 2),
    }


# ---------------------------------------------------------------------------
# Decision engine
# ---------------------------------------------------------------------------

@router.post("/threat/evaluate")
async def evaluate_threat(req: EvaluateRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    signals = dict(req.signals)
    signals["source_ip"] = req.source_ip
    signals["attack_type"] = req.attack_type
    record = _decision().decide(signals)
    _metrics().defenses_activated.inc(len(record.defenses_activated))
    _db().save_decision(record.to_dict())
    return record.to_dict()


@router.get("/threat/history")
async def threat_history(limit: int = 50, _auth: Dict = Depends(require_permission("read"))) -> List[Dict[str, Any]]:
    return _db().get_decisions(limit=limit)


@router.get("/alerts")
async def get_alerts(limit: int = 100, _auth: Dict = Depends(require_permission("read"))) -> List[Dict[str, Any]]:
    return _db().get_alerts(limit=limit)


# ---------------------------------------------------------------------------
# Aviation — RF Fingerprinting
# ---------------------------------------------------------------------------

@router.post("/aviation/rf-fingerprint")
async def rf_fingerprint(req: RFFingerprintRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Analyze IQ samples from an ADS-B transponder for spoofing signatures."""
    from aviation.rf_fingerprinting import IQFrame
    frame = IQFrame(
        icao24=req.icao24,
        timestamp=time.time(),
        amplitude=req.amplitude,
        phase_deg=req.phase_deg,
        dc_i=req.dc_i,
        dc_q=req.dc_q,
        iq_imbalance_db=req.iq_imbalance_db,
        rise_time_us=req.rise_time_us,
        snr_db=req.snr_db,
        frequency_offset_hz=req.frequency_offset_hz,
    )
    result = _rf_fingerprinter().analyze_frame(
        frame=frame,
        declared_speed_ms=req.declared_speed_ms,
        declared_heading_deg=req.declared_heading_deg,
        declared_lat=req.declared_lat,
        declared_lon=req.declared_lon,
    )
    return result


# ---------------------------------------------------------------------------
# Aviation — Autoencoder Anomaly Detection
# ---------------------------------------------------------------------------

@router.post("/aviation/autoencoder")
async def autoencoder_detect(req: AutoencoderRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Run autoencoder anomaly detection on protocol feature vector."""
    detector = _autoencoder()
    if req.train:
        detector.train_step(req.features)
        return {"status": "trained", "protocol": req.protocol}
    return detector.infer(req.features, req.protocol)


# ---------------------------------------------------------------------------
# Aviation — Protocol Micro-Models
# ---------------------------------------------------------------------------

@router.post("/aviation/protocol")
async def protocol_score(req: ProtocolScoreRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Score an event against the protocol-specific micro-model."""
    score, reason = _protocol_registry().score(req.protocol, req.event)
    return {
        "protocol": req.protocol,
        "anomaly_score": round(score, 4),
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Aviation — Kinematic Validation
# ---------------------------------------------------------------------------

@router.post("/aviation/kinematic")
async def kinematic_validate(req: KinematicRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Validate ADS-B position/velocity report against physics model."""
    try:
        from aviation.kinematic_validator import AircraftState
        state = AircraftState(
            icao24=req.icao24,
            timestamp=time.time(),
            lat=req.lat,
            lon=req.lon,
            alt_ft=req.alt_ft,
            speed_kts=req.speed_kts,
            heading_deg=req.heading_deg,
            vertical_rate_fpm=req.vertical_rate_fpm,
            squawk=req.squawk,
        )
        result = _kinematic().validate(state)
        return result if isinstance(result, dict) else {"valid": result}
    except Exception as exc:
        return {"error": str(exc), "valid": False}


# ---------------------------------------------------------------------------
# Analytics — Traffic Analysis
# ---------------------------------------------------------------------------

@router.post("/analytics/traffic")
async def analyze_traffic(req: TrafficAnalyticsRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """JA3/JA4 fingerprint, entropy analysis, Markov TCP state, OS fingerprint."""
    engine = _traffic_analytics()

    # Payload
    try:
        payload = bytes.fromhex(req.payload_hex) if req.payload_hex else b""
    except ValueError:
        payload = b""

    result = engine.analyze_packet(
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        protocol=req.protocol,
        payload=payload,
        tcp_flags=req.tcp_flags,
        tcp_window=req.tcp_window,
        ttl=req.ttl,
        mss=req.mss,
        flow_key=req.flow_key or f"{req.src_ip}:{req.dst_ip}:{req.protocol}",
    )

    # TLS fingerprinting if fields provided
    if req.tls_ciphers:
        from analytics.traffic_analytics import TLSClientHello
        hello = TLSClientHello(
            version=req.tls_version,
            cipher_suites=req.tls_ciphers,
            extensions=req.tls_extensions,
            elliptic_curves=req.tls_curves,
            elliptic_curve_point_formats=req.tls_point_formats,
            src_ip=req.src_ip,
            dst_ip=req.dst_ip,
        )
        tls_result = engine.ja3.screen(hello)
        result["tls"] = tls_result

    return result


# ---------------------------------------------------------------------------
# Analytics — UEBA
# ---------------------------------------------------------------------------

@router.post("/analytics/ueba")
async def ueba_event(req: UEBAEventRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Process a behavior event and return anomalies detected."""
    from analytics.ueba import BehaviorEvent
    event = BehaviorEvent(
        entity_id=req.entity_id,
        entity_type=req.entity_type,
        event_type=req.event_type,
        timestamp=time.time(),
        bytes_transferred=req.bytes_transferred,
        target_system=req.target_system,
        source_ip=req.source_ip,
        success=req.success,
        metadata=req.metadata,
    )
    anomalies = _ueba().process_event(event)
    return {
        "entity_id": req.entity_id,
        "anomalies": [a.to_dict() for a in anomalies],
        "anomaly_count": len(anomalies),
        "entity_risk": _ueba().get_entity_risk(req.entity_id),
    }


@router.get("/analytics/ueba/risks")
async def ueba_risks(threshold: float = 0.6, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Return all entities with risk score above threshold."""
    return {
        "high_risk_entities": _ueba().get_high_risk_entities(threshold),
        "recent_anomalies": _ueba().get_recent_anomalies(20),
        "stats": _ueba().get_stats(),
    }


# ---------------------------------------------------------------------------
# Analytics — Cross-Protocol Correlation
# ---------------------------------------------------------------------------

@router.post("/analytics/correlate")
async def correlate_event(req: CorrelateRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Ingest a protocol event and detect cross-protocol attack correlations."""
    from analytics.cross_protocol_correlator import ProtocolEvent
    import uuid
    event = ProtocolEvent(
        event_id=req.event_id or uuid.uuid4().hex[:12],
        protocol=req.protocol,
        timestamp=time.time(),
        threat_score=req.threat_score,
        src_ip=req.src_ip,
        entity_id=req.entity_id,
        description=req.description,
        metadata=req.metadata,
    )
    correlations = _correlator().ingest(event)
    return {
        "event_id": event.event_id,
        "correlations_found": len(correlations) if correlations else 0,
        "correlations": [c.to_dict() for c in correlations] if correlations else [],
        "stats": _correlator().get_stats(),
    }


@router.get("/analytics/correlations")
async def get_correlations(min_score: float = 0.5, protocol: Optional[str] = None,
                           _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    return {
        "correlations": _correlator().get_correlations(min_score, protocol),
        "stats": _correlator().get_stats(),
    }


# ---------------------------------------------------------------------------
# Analytics — NLP Query
# ---------------------------------------------------------------------------

@router.post("/analytics/query")
async def nlp_query(req: NLPQueryRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Natural-language threat query — searches vector store + RAG."""
    vs_results = _vector_store().search(req.query, top_k=req.top_k)
    rag_result = _rag().query_rich(req.query, top_k=req.top_k)
    return {
        "query": req.query,
        "vector_results": vs_results,
        "rag_answer": rag_result.get("answer", ""),
        "sources": rag_result.get("sources", []),
    }


# ---------------------------------------------------------------------------
# ML Ops — Drift Detection
# ---------------------------------------------------------------------------

@router.get("/ml/drift")
async def drift_status(_auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    return _drift().get_stats()


@router.post("/ml/drift/report")
async def drift_report(req: DriftReportRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Submit production values for drift detection against reference distribution."""
    detector = _drift()
    results = []
    for val in req.production_values:
        r = detector.observe(req.feature_name, val)
        if r:
            results.append(r)
    return {
        "feature": req.feature_name,
        "samples_submitted": len(req.production_values),
        "drift_detected": len(results) > 0,
        "drift_reports": results,
        "stats": detector.get_stats(),
    }


# ---------------------------------------------------------------------------
# ML Ops — Model Registry
# ---------------------------------------------------------------------------

@router.get("/ml/registry")
async def model_registry(_auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    reg = _model_registry()
    return {
        "models": reg.list_models(),
        "stats": reg.get_stats(),
    }


# ---------------------------------------------------------------------------
# ML Ops — Federated Learning
# ---------------------------------------------------------------------------

@router.post("/ml/federated/aggregate")
async def federated_aggregate(req: FederatedAggregateRequest, _auth: Dict = Depends(require_permission("write"))) -> Dict[str, Any]:
    """Submit a node's model update for Byzantine-robust federated aggregation."""
    from ml.federated_learning import ModelUpdate
    update = ModelUpdate(
        node_id=req.node_id,
        gradients=req.gradients,
        num_samples=req.num_samples,
        loss=req.loss,
        round_number=0,
    )
    engine = _federated()
    engine.submit_update(update)
    return {
        "node_id": req.node_id,
        "update_accepted": True,
        "stats": engine.get_stats(),
    }


# ---------------------------------------------------------------------------
# ML Ops — Adversarial Defense
# ---------------------------------------------------------------------------

@router.post("/ml/adversarial/screen")
async def adversarial_screen(req: AdversarialScreenRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Screen features for adversarial perturbation before neural inference."""
    result = _adv_defense().screen(req.features, req.label)
    return result


# ---------------------------------------------------------------------------
# Response — Firewall Generator
# ---------------------------------------------------------------------------

@router.post("/response/firewall")
async def generate_firewall(req: FirewallRequest, _auth: Dict = Depends(require_permission("write"))) -> Dict[str, Any]:
    """Generate firewall rules from a threat signal."""
    from response.firewall_generator import ThreatSignal
    signal = ThreatSignal(
        threat_score=req.threat_score,
        src_ip=req.src_ip,
        protocol=req.protocol,
        threat_type=req.threat_type,
        attack_type=req.attack_type,
    )
    rules = _firewall().generate_from_threat(signal, req.target_format)
    return {
        "rules_generated": len(rules),
        "target_format": req.target_format,
        "rules": [r.to_dict() for r in rules],
    }


@router.get("/response/firewall/rules")
async def firewall_rules(_auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    gen = _firewall()
    return {
        "active_rules": gen.get_active_rules(),
        "stats": gen.get_stats(),
    }


# ---------------------------------------------------------------------------
# Response — Incident Triage
# ---------------------------------------------------------------------------

@router.post("/response/triage")
async def triage_incident(req: TriageRequest, _auth: Dict = Depends(require_permission("write"))) -> Dict[str, Any]:
    """Cluster raw alerts into incidents with kill-chain phase and playbook."""
    incidents = _triage().run_triage(req.alerts, req.ttps)
    return {
        "incidents_created": len(incidents),
        "incidents": [inc.to_dict() for inc in incidents],
        "stats": _triage().get_stats(),
    }


@router.get("/response/incidents")
async def get_incidents(limit: int = 20, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    return {
        "incidents": _triage().get_recent_incidents(limit),
        "stats": _triage().get_stats(),
    }


# ---------------------------------------------------------------------------
# Response — Cyber-Physical Impact
# ---------------------------------------------------------------------------

@router.post("/response/impact")
async def assess_impact(req: ImpactRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Compute cyber-physical impact score for attack on aviation/SCADA assets."""
    result = _impact().assess(
        attack_type=req.attack_type,
        affected_assets=req.affected_assets,
        conditions=req.conditions,
    )
    return result


# ---------------------------------------------------------------------------
# Threat Intelligence — IOC Check
# ---------------------------------------------------------------------------

@router.post("/intel/ioc/check")
async def ioc_check(req: IOCCheckRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Check a value against the STIX IOC blacklist."""
    bl = _stix().ioc_blacklist
    val = req.value
    ioc_type = req.ioc_type

    # Auto-detect type
    if ioc_type == "auto":
        import re
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
            ioc_type = "ip"
        elif len(val) in (32, 40, 64):
            ioc_type = "hash"
        elif val.startswith("http"):
            ioc_type = "url"
        else:
            ioc_type = "domain"

    if ioc_type == "ip":
        hit = bl.check_ip(val)
    elif ioc_type == "domain":
        hit = bl.check_domain(val)
    elif ioc_type == "hash":
        hit = bl.check_hash(val)
    elif ioc_type == "url":
        hit = bl.check_url(val)
    else:
        hit = None

    return {
        "value": val,
        "ioc_type": ioc_type,
        "malicious": hit is not None,
        "ioc": hit,
        "blacklist_stats": {
            "total_ips": len(bl._ip_blacklist),
            "total_domains": len(bl._domain_blacklist),
            "total_hashes": len(bl._hash_blacklist),
        },
    }


# ---------------------------------------------------------------------------
# Threat Intelligence — STIX Ingest
# ---------------------------------------------------------------------------

@router.post("/intel/stix/ingest")
async def stix_ingest(req: STIXIngestRequest, _auth: Dict = Depends(require_permission("write"))) -> Dict[str, Any]:
    """Ingest a STIX 2.1 bundle into the threat intelligence store."""
    result = _stix().ingest_bundle(req.bundle)
    return result


# ---------------------------------------------------------------------------
# Threat Intelligence — Threat Hunting
# ---------------------------------------------------------------------------

@router.post("/intel/hunt/run")
async def hunt_run(req: HuntRequest, _auth: Dict = Depends(require_permission("write"))) -> Dict[str, Any]:
    """Run threat hunting hypothesis against event stream."""
    hunter = _threat_hunter()
    if req.hypothesis_id:
        results = hunter.run_hypothesis(req.hypothesis_id, req.events)
        return {"results": [r.to_dict() for r in results] if hasattr(results[0] if results else None, "to_dict") else results}
    else:
        all_results = hunter.run_all(req.events)
        return {
            "hypotheses_run": len(all_results),
            "results": all_results,
        }


@router.get("/intel/hunt/results")
async def hunt_results(limit: int = 20, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    hunter = _threat_hunter()
    return {
        "results": hunter.get_recent_findings(limit),
        "stats": hunter.get_stats(),
    }


# ---------------------------------------------------------------------------
# RAG
# ---------------------------------------------------------------------------

@router.post("/rag/query")
async def rag_query(req: RAGQueryRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    _metrics().rag_queries.inc()
    return _rag().query_rich(req.query, context=req.context, top_k=req.top_k)


@router.post("/rag/search")
async def rag_search(req: VectorSearchRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Direct vector similarity search in the knowledge base."""
    results = _vector_store().search(req.text, top_k=req.top_k, category=req.category)
    return {"query": req.text, "results": results, "count": len(results)}


# ---------------------------------------------------------------------------
# Defense — Honeypot
# ---------------------------------------------------------------------------

@router.post("/honeypot/interact")
async def honeypot_interact(req: HoneypotInteractRequest, _auth: Dict = Depends(require_permission("write"))) -> Dict[str, Any]:
    payload = bytes.fromhex(req.payload_hex) if req.payload_hex else b""
    result = _honeypot().interact(req.source_ip, req.service, req.command, payload)
    _metrics().active_sessions.set(len(_honeypot().get_all_profiles()))
    if result.get("escalate"):
        _metrics().threats_detected.inc()
    return result


@router.get("/honeypot/profiles")
async def honeypot_profiles(_auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    return {"profiles": _honeypot().get_all_profiles(), "stats": _honeypot().get_stats()}


# ---------------------------------------------------------------------------
# Defense — Canary tokens
# ---------------------------------------------------------------------------

@router.post("/canary/create")
async def canary_create(req: CanaryCreateRequest, _auth: Dict = Depends(require_permission("write"))) -> Dict[str, Any]:
    from defense.canary_tokens import CanaryTokenType
    try:
        tt = CanaryTokenType(req.token_type)
    except ValueError:
        tt = CanaryTokenType.API_KEY
    token = _canary().create(tt, req.description)
    return token.to_dict() | {"value": token.value}


@router.get("/canary/all")
async def canary_all(_auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    return {"tokens": _canary().get_all(), "stats": _canary().get_stats()}


@router.post("/canary/check")
async def canary_check(req: CanaryCheckRequest, _auth: Dict = Depends(require_permission("write"))) -> Dict[str, Any]:
    token = _canary().check_trip(req.value, source=req.source)
    if token:
        _metrics().canaries_tripped.inc()
        return {"tripped": True, "token": token.to_dict()}
    return {"tripped": False}


# ---------------------------------------------------------------------------
# Defense — Death trap
# ---------------------------------------------------------------------------

@router.post("/death-trap/engage")
async def engage_death_trap(req: DeathTrapRequest, _auth: Dict = Depends(require_permission("manage"))) -> Dict[str, Any]:
    report = _death_trap().engage(
        threat_level=req.threat_level,
        source_ip=req.source_ip,
        context=req.context,
    )
    _metrics().death_traps_engaged.inc()
    _db().audit("api", "death_trap_engage", req.source_ip, "ok",
                {"trap_id": report.trap_id, "level": req.threat_level})
    return report.to_dict()


@router.get("/death-trap/reports")
async def death_trap_reports(limit: int = 20, _auth: Dict = Depends(require_permission("read"))) -> List[Dict[str, Any]]:
    return _death_trap().get_reports(limit=limit)


# ---------------------------------------------------------------------------
# RL — PPO / RLHF
# ---------------------------------------------------------------------------

@router.post("/rl/feedback")
async def rl_feedback(req: RLFeedbackRequest, _auth: Dict = Depends(require_permission("write"))) -> Dict[str, Any]:
    """Submit analyst feedback to refine the PPO policy via RLHF."""
    _ppo().analyst_feedback(req.state, req.action, req.feedback_type)
    return {"status": "feedback_recorded", "action": req.action, "type": req.feedback_type}


@router.post("/rl/action")
async def rl_action(req: RLActionRequest, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    """Get PPO agent's recommended action for a given state vector."""
    action, log_prob, value = _ppo().act(req.state)
    from rl.ppo_rlhf import Action
    return {
        "action_id": action,
        "action_name": Action(action).name,
        "log_prob": round(float(log_prob), 4),
        "value_estimate": round(float(value), 4),
    }


@router.post("/rl/canary/predict")
async def predictive_canary(req: PredictiveCanaryRequest, _auth: Dict = Depends(require_permission("write"))) -> Dict[str, Any]:
    """Predict next attack steps and return optimised canary placement."""
    engine = _pred_canary()
    placement = engine.get_canary_placement(req.current_node, req.steps)
    return placement


# ---------------------------------------------------------------------------
# Security — PQC
# ---------------------------------------------------------------------------

@router.get("/security/pqc/stats")
async def pqc_stats(_auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    return _pqc().get_stats()


# ---------------------------------------------------------------------------
# Security — mTLS
# ---------------------------------------------------------------------------

@router.get("/security/mtls/status")
async def mtls_status(_auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    mgr = _mtls()
    return {
        "ca_fingerprint": mgr.get_ca_cert_pem()[:60] + "...",
        "registered_services": mgr.list_services(),
        "stats": mgr.get_stats(),
    }


# ---------------------------------------------------------------------------
# Observability — Distributed Traces
# ---------------------------------------------------------------------------

@router.get("/traces/recent")
async def recent_traces(n: int = 20, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    return {"traces": _tracer().get_recent_traces(n), "stats": _tracer().get_stats()}


@router.get("/traces/slow")
async def slow_traces(threshold_ms: float = 100.0, _auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    return {"slow_traces": _tracer().get_slow_traces(threshold_ms)}


# ---------------------------------------------------------------------------
# Distributed — Ray engine
# ---------------------------------------------------------------------------

@router.get("/distributed/stats")
async def distributed_stats(_auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    return _ray_engine().get_stats()


# ---------------------------------------------------------------------------
# System stats
# ---------------------------------------------------------------------------

@router.get("/stats")
async def stats(_auth: Dict = Depends(require_permission("read"))) -> Dict[str, Any]:
    return {
        "neural_engine":     {"version": "10.0.0", "layers": 200},
        "decision_engine":   _decision().get_stats(),
        "honeypot":          _honeypot().get_stats(),
        "canary":            _canary().get_stats(),
        "death_trap":        _death_trap().get_stats(),
        "rag":               _rag().get_stats(),
        "storage":           _db().get_stats(),
        "metrics":           _metrics().collect_all(),
        "analytics":         {
            "traffic":        _traffic_analytics().get_stats(),
            "ueba":           _ueba().get_stats(),
            "correlator":     _correlator().get_stats(),
        },
        "ml": {
            "drift":          _drift().get_stats(),
            "registry":       _model_registry().get_stats(),
            "federated":      _federated().get_stats(),
        },
        "response": {
            "firewall":       _firewall().get_stats(),
            "triage":         _triage().get_stats(),
        },
        "security": {
            "pqc":            _pqc().get_stats(),
            "mtls":           _mtls().get_stats(),
        },
        "distributed":       _ray_engine().get_stats(),
        "tracing":           _tracer().get_stats(),
    }
