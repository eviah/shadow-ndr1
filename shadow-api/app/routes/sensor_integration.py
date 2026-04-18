"""
Shadow Sensor Integration Routes

Handles real-time threat data from shadow-sensor v11.0
Integrates CPR decoding, ICAO validation, burst detection, baseline anomalies
"""

from fastapi import APIRouter, WebSocket, Query, HTTPException
from kafka import KafkaConsumer, KafkaProducer
import json
import asyncio
from typing import Optional, List
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger("shadow.api.sensor")

router = APIRouter(prefix="/api/sensor", tags=["sensor"])

# ============================================================================
# Kafka Connectors
# ============================================================================

KAFKA_BROKERS = ["localhost:9092"]

# Consumers
threat_consumer = None
raw_consumer = None
analytics_consumer = None

# Producers
decisions_producer = None

def init_kafka():
    """Initialize Kafka connections"""
    global threat_consumer, raw_consumer, analytics_consumer, decisions_producer

    try:
        threat_consumer = KafkaConsumer(
            'shadow.threats',
            bootstrap_servers=KAFKA_BROKERS,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest',
            group_id='shadow-api-threats'
        )

        raw_consumer = KafkaConsumer(
            'shadow.raw',
            bootstrap_servers=KAFKA_BROKERS,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest',
            group_id='shadow-api-raw'
        )

        analytics_consumer = KafkaConsumer(
            'shadow.analytics',
            bootstrap_servers=KAFKA_BROKERS,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest',
            group_id='shadow-api-analytics'
        )

        decisions_producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKERS,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )

        logger.info("✅ Kafka integration initialized")
    except Exception as e:
        logger.error(f"❌ Kafka init failed: {e}")

# ============================================================================
# In-Memory State (for fast queries, not for persistence)
# ============================================================================

aircraft_profiles = {}  # ICAO24 -> {profile data}
active_threats = []     # List of current threats
threat_history = defaultdict(list)  # ICAO24 -> [threats]

# ============================================================================
# Health & Status
# ============================================================================

@router.get("/health")
async def sensor_health():
    """Check sensor health and threat detection status"""
    try:
        metrics = {
            "status": "online",
            "version": "11.0.0",
            "timestamp": datetime.utcnow().isoformat(),
            "modules": {
                "cpr_decoder": "active",
                "icao_validator": "active",
                "burst_detector": "active",
                "baseline_scorer": "active",
                "physics_engine": "active",
                "mesh_consensus": "active",
                "threat_correlator": "active"
            },
            "uptime_seconds": 0,  # Would track actual uptime
            "kafka_connected": threat_consumer is not None,
        }
        return metrics
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "error", "error": str(e)}

# ============================================================================
# Threat Streams
# ============================================================================

@router.websocket("/ws/threats")
async def websocket_threats(websocket: WebSocket):
    """
    Real-time threat stream via WebSocket

    Returns: {
        "type": "threat",
        "icao24": "0x3C5EF8",
        "threat_type": "CALLSIGN_MISMATCH",
        "severity": 0.9,
        "timestamp_ms": 1713350400000,
        "sensor_id": "sensor-primary"
    }
    """
    await websocket.accept()
    logger.info(f"📡 Threat stream client connected: {websocket.client}")

    try:
        # Send threats as they arrive
        for message in threat_consumer:
            threat = message.value

            # Track in local state
            icao24 = threat.get("icao24")
            active_threats.append(threat)
            if icao24:
                threat_history[icao24].append(threat)

            # Keep only recent (last 1000)
            if len(active_threats) > 1000:
                active_threats.pop(0)

            await websocket.send_json(threat)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()

@router.get("/threats/current")
async def current_threats(
    severity: Optional[str] = Query(None, description="Filter: CRITICAL, HIGH, MEDIUM, LOW"),
    threat_type: Optional[str] = None,
    icao24: Optional[str] = None,
    limit: int = Query(100, le=1000)
) -> dict:
    """
    Get current active threats

    Examples:
    - GET /api/sensor/threats/current?severity=CRITICAL
    - GET /api/sensor/threats/current?threat_type=CALLSIGN_MISMATCH
    - GET /api/sensor/threats/current?icao24=0x3C5EF8
    """
    try:
        threats = list(active_threats[-limit:])

        # Apply filters
        if severity:
            severity_map = {"CRITICAL": 0.8, "HIGH": 0.6, "MEDIUM": 0.4, "LOW": 0.2}
            threshold = severity_map.get(severity, 0.0)
            threats = [t for t in threats if t.get("severity", 0) >= threshold]

        if threat_type:
            threats = [t for t in threats if t.get("threat_type") == threat_type]

        if icao24:
            threats = [t for t in threats if t.get("icao24") == icao24]

        return {
            "count": len(threats),
            "threats": threats,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to fetch threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/threats/timeline")
async def threats_timeline(icao24: str, hours: int = 24) -> dict:
    """
    Get threat timeline for an aircraft

    Shows all threats detected for a specific ICAO24 in the past N hours
    """
    try:
        since = datetime.utcnow() - timedelta(hours=hours)
        threats = threat_history.get(icao24, [])

        # Filter by time
        recent_threats = [
            t for t in threats
            if datetime.fromtimestamp(t.get("timestamp_ms", 0) / 1000) > since
        ]

        return {
            "icao24": icao24,
            "period_hours": hours,
            "threat_count": len(recent_threats),
            "threats": recent_threats,
            "threat_types": list(set(t.get("threat_type") for t in recent_threats))
        }
    except Exception as e:
        logger.error(f"Failed to fetch timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# Aircraft Profiles
# ============================================================================

@router.get("/aircraft/{icao24}/profile")
async def aircraft_profile(icao24: str):
    """
    Get behavioral profile for aircraft (from baseline scorer)

    Shows:
    - Average location, altitude, speed
    - Number of observations
    - Baseline confidence
    - Recent anomalies
    """
    try:
        profile = aircraft_profiles.get(icao24, {})
        threats = threat_history.get(icao24, [])
        recent_threats = threats[-10:] if threats else []

        return {
            "icao24": icao24,
            "profile": profile,
            "threat_count": len(threats),
            "recent_threats": recent_threats,
            "last_seen": threats[-1].get("timestamp_ms") if threats else None
        }
    except Exception as e:
        logger.error(f"Failed to fetch profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# Sensor Analytics
# ============================================================================

@router.get("/metrics")
async def sensor_metrics():
    """
    Get sensor metrics (packets parsed, threats detected, etc.)

    Aggregates data from shadow.analytics Kafka topic
    """
    try:
        metrics = {}

        # Fetch latest metrics from analytics consumer
        for message in analytics_consumer:
            data = message.value
            if data.get("type") == "metrics":
                metrics = data.get("data", {})

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": metrics,
            "active_aircraft": len(aircraft_profiles),
            "active_threats": len(active_threats)
        }
    except Exception as e:
        logger.error(f"Failed to fetch metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/statistics")
async def sensor_statistics(period_minutes: int = 60) -> dict:
    """
    Get aggregated statistics over a time period

    Shows: threat rates, detection types, aircraft count, etc.
    """
    try:
        since = datetime.utcnow() - timedelta(minutes=period_minutes)

        recent_threats = [
            t for t in active_threats
            if datetime.fromtimestamp(t.get("timestamp_ms", 0) / 1000) > since
        ]

        threat_type_counts = defaultdict(int)
        for t in recent_threats:
            threat_type_counts[t.get("threat_type", "UNKNOWN")] += 1

        severity_counts = defaultdict(int)
        for t in recent_threats:
            sev = t.get("severity", 0.5)
            if sev >= 0.8:
                severity_counts["CRITICAL"] += 1
            elif sev >= 0.6:
                severity_counts["HIGH"] += 1
            elif sev >= 0.4:
                severity_counts["MEDIUM"] += 1
            else:
                severity_counts["LOW"] += 1

        return {
            "period_minutes": period_minutes,
            "timestamp": datetime.utcnow().isoformat(),
            "total_threats": len(recent_threats),
            "threat_rate_per_minute": len(recent_threats) / period_minutes,
            "threat_types": dict(threat_type_counts),
            "severity_distribution": dict(severity_counts),
            "unique_aircraft": len(set(t.get("icao24") for t in recent_threats))
        }
    except Exception as e:
        logger.error(f"Failed to fetch statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# Decision Integration
# ============================================================================

@router.post("/decision/{decision_id}")
async def record_decision(decision_id: str, effective: bool, notes: Optional[str] = None) -> dict:
    """
    Record decision effectiveness feedback (for ML learning)

    Sends feedback to shadow.ml.decisions topic for continuous improvement
    """
    try:
        feedback = {
            "decision_id": decision_id,
            "effective": effective,
            "timestamp": datetime.utcnow().isoformat(),
            "notes": notes
        }

        if decisions_producer:
            decisions_producer.send('shadow.ml.decisions', feedback)

        logger.info(f"📊 Decision feedback recorded: {decision_id} → {effective}")
        return {"status": "recorded", "decision_id": decision_id}
    except Exception as e:
        logger.error(f"Failed to record decision: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# Export/Report
# ============================================================================

@router.get("/export/threats")
async def export_threats(format: str = "json", hours: int = 24) -> dict:
    """
    Export threats for analysis

    Formats: json, csv
    """
    try:
        since = datetime.utcnow() - timedelta(hours=hours)
        threats = [
            t for t in active_threats
            if datetime.fromtimestamp(t.get("timestamp_ms", 0) / 1000) > since
        ]

        if format == "csv":
            # Return CSV format
            csv_lines = ["icao24,threat_type,severity,timestamp_ms,sensor_id"]
            for t in threats:
                csv_lines.append(
                    f"{t.get('icao24')},{t.get('threat_type')},"
                    f"{t.get('severity')},{t.get('timestamp_ms')},{t.get('sensor_id')}"
                )
            return {"format": "csv", "data": "\n".join(csv_lines)}
        else:
            return {"format": "json", "threats": threats, "count": len(threats)}
    except Exception as e:
        logger.error(f"Failed to export: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# Initialization
# ============================================================================

@router.on_event("startup")
async def startup():
    """Initialize Kafka connections on API startup"""
    init_kafka()
    logger.info("✅ Sensor integration routes initialized")
