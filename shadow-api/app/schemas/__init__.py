# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Shadow NDR – Ultimate AI‑Powered Data Schemas                           ║
║  Production‑grade, fully typed, with validation and documentation        ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict
import ipaddress

# =============================================================================
# Enums (Domain‑specific)
# =============================================================================

class Severity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AssetType(str, Enum):
    """Type of aviation network asset."""
    AIRCRAFT = "aircraft"
    AIRPORT  = "airport"
    ATC      = "atc"            # air-traffic-control ground station
    RADAR    = "radar"
    UAV      = "uav"
    GROUND   = "ground"         # airline ground IT / maintenance
    SWITCH   = "switch"
    UNKNOWN  = "unknown"

class Protocol(str, Enum):
    """Network protocol identifiers (aviation + IT)."""
    TCP        = "tcp"
    UDP        = "udp"
    ICMP       = "icmp"
    ADS_B      = "ads_b"
    MODE_S     = "mode_s"
    ACARS      = "acars"
    SATCOM     = "satcom"
    GDL90      = "gdl90"
    AFDX       = "afdx"
    ARINC429   = "arinc429"
    ARINC664   = "arinc664"
    DATALINK   = "datalink"
    MQTT       = "mqtt"
    UNKNOWN    = "unknown"

class AttackType(str, Enum):
    """Known attack types relevant to aviation NDR."""
    SYN_FLOOD           = "SYN_FLOOD"
    UDP_FLOOD           = "UDP_FLOOD"
    ICMP_FLOOD          = "ICMP_FLOOD"
    HTTP_FLOOD          = "HTTP_FLOOD"
    PORT_SCAN           = "PORT_SCAN"
    BRUTE_FORCE         = "BRUTE_FORCE"
    SSH_BRUTE           = "SSH_BRUTE"
    DATA_EXFIL          = "DATA_EXFIL"
    BEACONING           = "BEACONING"
    DNS_TUNNEL          = "DNS_TUNNEL"
    C2_COMMUNICATION    = "C2_COMMUNICATION"
    RANSOMWARE_SPREAD   = "RANSOMWARE_SPREAD"
    ADS_B_SPOOFING      = "ADS_B_SPOOFING"
    ADS_B_JAMMING       = "ADS_B_JAMMING"
    MODE_S_REPLAY       = "MODE_S_REPLAY"
    ACARS_INJECTION     = "ACARS_INJECTION"
    GPS_SPOOFING        = "GPS_SPOOFING"
    GPS_JAMMING         = "GPS_JAMMING"
    SATCOM_HIJACK       = "SATCOM_HIJACK"
    TCAS_MANIPULATION   = "TCAS_MANIPULATION"
    AIRCRAFT_COMPROMISE = "AIRCRAFT_COMPROMISE"
    MQTT_FLOOD          = "MQTT_FLOOD"

# =============================================================================
# Shared mixins
# =============================================================================

class TimestampMixin(BaseModel):
    """Base class for objects with creation and update timestamps."""
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")

class OrgAwareMixin(BaseModel):
    """Base class for objects belonging to an organisation."""
    org_id: str = Field(..., description="Organisation identifier (tenant)")

# =============================================================================
# Packet schemas
# =============================================================================

class ParsedProtocolData(BaseModel):
    """Structured data extracted from protocol parsers."""
    protocol: Protocol = Field(..., description="Identified protocol")
    fields: Dict[str, Any] = Field(default_factory=dict, description="Protocol-specific fields")
    raw: Optional[str] = Field(None, description="Raw payload hex (for debugging)")

class ThreatIntel(BaseModel):
    """External threat intelligence data."""
    abuse_score: int = Field(0, ge=0, le=100, description="AbuseIPDB confidence score")
    is_tor: bool = False
    is_vpn: bool = False
    asn: Optional[str] = None
    asn_rep: float = Field(0.0, ge=0.0, le=1.0, description="ASN reputation (0-1)")
    country: Optional[str] = None
    city: Optional[str] = None

class PacketSchema(BaseModel):
    """Complete packet representation after parsing and enrichment."""
    timestamp: datetime = Field(..., description="Packet capture time (UTC)")
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: Optional[int] = Field(None, ge=0, le=65535, description="Source port (if TCP/UDP)")
    dst_port: Optional[int] = Field(None, ge=0, le=65535, description="Destination port (if TCP/UDP)")
    proto: int = Field(..., ge=0, le=255, description="IP protocol number (6=TCP, 17=UDP, 1=ICMP)")
    size: int = Field(..., gt=0, description="Packet size in bytes")

    # Parsed protocol information
    protocol: Protocol = Protocol.UNKNOWN
    parsed_data: Optional[ParsedProtocolData] = None

    # Security fields
    attack_types: List[AttackType] = Field(default_factory=list, description="Detected attack types")
    score: float = Field(0.0, ge=0.0, le=1.0, description="Anomaly score (0=normal, 1=anomalous)")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Confidence of the ML model")
    is_critical: bool = False
    threat_intel: Optional[ThreatIntel] = None
    explanation: Optional[Dict[str, Any]] = Field(None, description="SHAP explanation (if available)")

    # Enrichment
    aircraft_id: Optional[str] = None          # ICAO24 hex / tail number
    asset_id: Optional[str] = None
    org_id: str = "default"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "timestamp": "2025-03-21T12:00:00Z",
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "src_port": 54321,
                "dst_port": 80,
                "proto": 6,
                "size": 1500,
                "protocol": "tcp",
                "attack_types": ["SYN_FLOOD"],
                "score": 0.95,
                "confidence": 0.92,
                "is_critical": True,
                "org_id": "default"
            }
        }
    )

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    @field_validator("score", "confidence")
    @classmethod
    def validate_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("Value must be between 0 and 1")
        return v

# =============================================================================
# Threat response schemas
# =============================================================================

class MitreContext(BaseModel):
    """MITRE ATT&CK framework information."""
    tactic: str = Field(..., description="MITRE tactic (e.g., TA0043)")
    technique: str = Field(..., description="MITRE technique (e.g., T1046)")
    sub_technique: Optional[str] = None
    description: str = ""

class RuleMatch(BaseModel):
    """Rule that triggered the alert."""
    rule_id: str
    rule_name: str
    severity: str
    cve: Optional[str] = None
    mitre: Optional[MitreContext] = None
    matched_at: datetime = Field(default_factory=datetime.utcnow)

class ThreatResponse(BaseModel):
    """Response model for a single threat/alert."""
    id: str = Field(..., description="Unique identifier")
    timestamp: datetime
    src_ip: str
    dst_ip: str
    score: float
    attack_types: List[AttackType]
    severity: Severity
    is_critical: bool
    confidence: float = Field(0.0, description="Confidence of detection")
    rule_matches: List[RuleMatch] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    explanation: Optional[Dict[str, Any]] = None
    recommended_actions: List[str] = Field(default_factory=list, description="Suggested next steps")
    org_id: str = "default"

class PaginatedResponse(BaseModel):
    """Generic paginated response container."""
    total: int = Field(..., description="Total number of items")
    limit: int = Field(..., description="Items per page")
    offset: int = Field(..., description="Offset from start")
    next: Optional[str] = Field(None, description="URL for next page")
    prev: Optional[str] = Field(None, description="URL for previous page")

class ThreatListResponse(PaginatedResponse):
    """Response for list of threats."""
    threats: List[ThreatResponse]

# =============================================================================
# Asset schemas
# =============================================================================

class Vulnerability(BaseModel):
    """Known vulnerability associated with an asset."""
    cve_id: str
    cvss_score: Optional[float] = None
    description: str

class AssetResponse(BaseModel):
    """Detailed asset information."""
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    os_guess: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    services: Dict[int, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)

    # Classification
    asset_type: AssetType = AssetType.UNKNOWN
    is_aircraft: bool = False
    icao24: Optional[str] = None               # 24-bit ICAO address (hex)
    tail_number: Optional[str] = None

    # Timestamps
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Risk
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    risk_trend: str = Field("stable", description="Trend of risk (increasing, decreasing, stable)")

    # Enrichment
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    threat_intel: Optional[ThreatIntel] = None
    geolocation: Optional[Dict[str, Any]] = Field(None, description="Geo coordinates and location info")

    org_id: str = "default"

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "ip": "192.168.1.10",
            "hostname": "b737-acars-01",
            "os_guess": "VxWorks 6.9",
            "open_ports": [5555, 8443],
            "asset_type": "aircraft",
            "is_aircraft": True,
            "icao24": "738065",
            "tail_number": "4X-EDB",
            "risk_score": 0.85,
            "vulnerabilities": [{"cve_id": "CVE-2021-34527", "cvss_score": 8.5}]
        }
    })

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

class AssetListResponse(PaginatedResponse):
    assets: List[AssetResponse]

# =============================================================================
# User schemas
# =============================================================================

class UserRole(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    RESPONDER = "responder"
    ADMIN = "admin"

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str
    role: UserRole = UserRole.VIEWER
    org_id: str = "default"

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class UserResponse(UserBase, TimestampMixin):
    id: str
    is_active: bool = True

# =============================================================================
# ML service schemas
# =============================================================================

class MLModelInfo(BaseModel):
    name: str
    version: str
    status: str  # active, training, failed
    trained_at: Optional[datetime] = None
    metrics: Dict[str, float] = Field(default_factory=dict)

class MLHealthResponse(BaseModel):
    status: str
    ml_service: str  # online, degraded, offline
    circuit_breaker_state: str
    models: List[MLModelInfo] = Field(default_factory=list)
    fallback_available: bool

# =============================================================================
# Analytics and statistics schemas
# =============================================================================

class TimeSeriesPoint(BaseModel):
    timestamp: datetime
    value: float

class ThreatStatsResponse(BaseModel):
    period_hours: int
    total_threats: int
    critical: int
    high: int
    medium: int
    top_sources: List[Dict[str, Any]]
    time_series: Optional[List[TimeSeriesPoint]] = None

class AssetRiskHistory(BaseModel):
    ip: str
    hours: int
    history: List[Dict[str, Any]]  # timestamp, avg_score, max_score, packet_count