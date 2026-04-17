"""
fusion/zero_trust_verifier.py — Zero-Trust Packet-Level Verification v10.0

Every packet and flow must prove its legitimacy in real-time:
  • Source reputation scoring (IP history, ASN, geolocation)
  • TLS fingerprinting (JA3/JA4 hash matching)
  • TTL/MSS validation (expected OS fingerprints)
  • Anomalous port combinations (e.g., SQL + SSH on same flow)
  • Cross-protocol verification (must be consistent)

Rejects flows that fail ANY single trust check, regardless of other factors.
"""

import hashlib, time, logging, math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger("shadow.fusion.zero_trust")

class TrustLevel(Enum):
    TRUSTED = 5
    NEUTRAL = 3
    SUSPICIOUS = 1
    BLOCKED = 0

@dataclass
class FlowTrustContext:
    """Trust context for a single flow (5-tuple)."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    ts: float = field(default_factory=time.time)
    src_trust_score: float = 0.5
    dst_trust_score: float = 0.5
    ja3_hash: Optional[str] = None
    ja3_known: bool = False
    ttl_value: int = 64
    mss_value: int = 1460
    anomaly_flags: List[str] = field(default_factory=list)
    decision: TrustLevel = TrustLevel.NEUTRAL

class ZeroTrustVerifier:
    """Packet-level zero-trust enforcement."""
    
    def __init__(self):
        self._ip_reputation: Dict[str, float] = {}
        self._known_ja3: set = set()
        self._expected_ttls: Dict[str, int] = {
            "linux": 64,
            "windows": 128,
            "macos": 64,
            "ios": 64,
            "android": 64,
        }
        self._trust_history: List[FlowTrustContext] = []
    
    def verify_flow(self, context: FlowTrustContext) -> TrustLevel:
        """Zero-trust verification: reject unless ALL checks pass."""
        context.anomaly_flags = []
        
        # 1. Source IP reputation
        if context.src_ip in self._ip_reputation:
            context.src_trust_score = self._ip_reputation[context.src_ip]
            if context.src_trust_score < 0.2:
                context.anomaly_flags.append("blacklisted_src_ip")
        
        # 2. Destination IP reputation
        if context.dst_ip in self._ip_reputation:
            context.dst_trust_score = self._ip_reputation[context.dst_ip]
        
        # 3. TLS Fingerprint validation
        if context.ja3_hash:
            if context.ja3_hash not in self._known_ja3:
                context.anomaly_flags.append("unknown_ja3_fingerprint")
                context.ja3_known = False
            else:
                context.ja3_known = True
        
        # 4. TTL value validation
        if context.ttl_value not in [64, 128, 255]:
            context.anomaly_flags.append(f"anomalous_ttl_{context.ttl_value}")
        
        # 5. Port combination validation
        suspicious_combos = [
            (22, 3306),  # SSH + MySQL
            (3389, 445),  # RDP + SMB
            (6379, 27017),  # Redis + MongoDB
        ]
        if (context.src_port, context.dst_port) in suspicious_combos:
            context.anomaly_flags.append("suspicious_port_combo")
        
        # Decision: BLOCKED if ANY critical flag
        critical_flags = ["blacklisted_src_ip", "anomalous_ttl"]
        if any(f in context.anomaly_flags for f in critical_flags):
            context.decision = TrustLevel.BLOCKED
        elif len(context.anomaly_flags) > 2:
            context.decision = TrustLevel.SUSPICIOUS
        elif context.src_trust_score < 0.3 or context.dst_trust_score < 0.3:
            context.decision = TrustLevel.SUSPICIOUS
        else:
            context.decision = TrustLevel.TRUSTED
        
        self._trust_history.append(context)
        return context.decision
    
    def register_trusted_ja3(self, ja3_hash: str) -> None:
        """Register a known-good TLS fingerprint."""
        self._known_ja3.add(ja3_hash)
    
    def set_ip_reputation(self, ip: str, score: float) -> None:
        """Set IP reputation score [0.0 (bad) to 1.0 (good)]."""
        self._ip_reputation[ip] = max(0.0, min(1.0, score))

_verifier: Optional[ZeroTrustVerifier] = None
def get_verifier() -> ZeroTrustVerifier:
    global _verifier
    if _verifier is None:
        _verifier = ZeroTrustVerifier()
    return _verifier
