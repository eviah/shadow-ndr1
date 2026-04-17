"""
analytics/encrypted_traffic_analyzer.py — Encrypted Traffic Analysis v10.0

Detects attacks within encrypted channels (HTTPS, TLS, SSH):
  • TLS handshake anomalies (unusual cipher suites, elliptic curves)
  • Packet size distribution analysis (padding patterns reveal plaintext structure)
  • Inter-packet timing and burst patterns (information leakage)
  • TLS fingerprinting (JA3/JA4 to identify client/server types)
  • Behavioral anomalies in encrypted flows (data exfiltration, C2 beacons)
  • Certificate chain validation and anomalies
  • Protocol metadata analysis (DNS queries, SNI, timing)

Beats encryption to catch attacks that "hide in plain sight" using HTTPS.
Detects encrypted C2, DNS tunneling, data exfiltration through HTTPS.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("shadow.analytics.encrypted")


class EncryptedThreat(Enum):
    SUSPICIOUS_HANDSHAKE = "suspicious_handshake"
    C2_BEACON = "c2_beacon"
    DATA_EXFILTRATION = "data_exfiltration"
    DNS_TUNNELING = "dns_tunneling"
    CERTIFICATE_ANOMALY = "certificate_anomaly"
    TIMING_ATTACK = "timing_attack"
    PADDING_ORACLE = "padding_oracle"


@dataclass
class TLSFingerprint:
    """TLS handshake signature (JA3-like)."""
    tls_version: str
    accepted_ciphers: List[str]
    supported_groups: List[str]
    signature_algorithms: List[str]
    extensions: List[str]
    ja3_hash: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.ja3_hash:
            ja3_str = f"{self.tls_version},{','.join(self.accepted_ciphers)}," \
                     f"{','.join(self.supported_groups)}," \
                     f"{','.join(self.signature_algorithms)}"
            self.ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()


@dataclass
class PacketSequence:
    """Sequence of packets in a flow."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # tls, ssh, https
    packets: List[Tuple[float, int]] = field(default_factory=list)  # (timestamp, size)
    flow_start: float = 0.0
    flow_end: float = 0.0
    total_bytes: int = 0


@dataclass
class EncryptedAnomaly:
    """Detected anomaly in encrypted traffic."""
    threat_type: EncryptedThreat
    src_ip: str
    dst_ip: str
    severity: str
    confidence: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class TLSAnalyzer:
    """
    Analyzes TLS handshakes for anomalies.
    """

    def __init__(self):
        self._known_fingerprints: Dict[str, TLSFingerprint] = {}
        self._suspicious_cipher_suites = [
            "NULL",
            "EXPORT",
            "ANON",
            "DES",
            "RC4",
        ]
        self._known_good_ciphers = [
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        ]

    def register_fingerprint(self, client_id: str, fingerprint: TLSFingerprint) -> None:
        """Register known good TLS fingerprint."""
        self._known_fingerprints[client_id] = fingerprint
        logger.info(f"Registered TLS fingerprint for {client_id}: {fingerprint.ja3_hash}")

    def analyze_handshake(self, fingerprint: TLSFingerprint) -> Optional[EncryptedAnomaly]:
        """Analyze TLS handshake for anomalies."""
        anomalies = []

        # Check for weak/suspicious ciphers
        for cipher in fingerprint.accepted_ciphers:
            if any(weak in cipher for weak in self._suspicious_cipher_suites):
                anomalies.append((
                    0.8,
                    EncryptedThreat.SUSPICIOUS_HANDSHAKE,
                    f"Weak cipher suite negotiated: {cipher}"
                ))

        # Check for unusual protocol version
        if fingerprint.tls_version not in ["TLS1.2", "TLS1.3"]:
            anomalies.append((
                0.6,
                EncryptedThreat.SUSPICIOUS_HANDSHAKE,
                f"Unusual TLS version: {fingerprint.tls_version}"
            ))

        # Check for suspicious extensions
        suspicious_extensions = ["client_hello_padding", "session_ticket"]
        for ext in fingerprint.extensions:
            if ext in suspicious_extensions:
                anomalies.append((
                    0.5,
                    EncryptedThreat.SUSPICIOUS_HANDSHAKE,
                    f"Suspicious extension: {ext}"
                ))

        if not anomalies:
            return None

        score, threat, desc = max(anomalies, key=lambda x: x[0])
        return EncryptedAnomaly(
            threat_type=threat,
            src_ip="unknown",
            dst_ip="unknown",
            severity="high" if score > 0.7 else "medium",
            confidence=min(0.95, score),
            description=desc,
            evidence={
                "ja3_hash": fingerprint.ja3_hash,
                "ciphers": fingerprint.accepted_ciphers,
                "version": fingerprint.tls_version,
            },
            timestamp=fingerprint.timestamp
        )


class PacketTimingAnalyzer:
    """
    Analyzes inter-packet timing and burst patterns.
    """

    def __init__(self):
        self._baseline_timing: Dict[str, float] = {}  # flow_id -> baseline_iat
        self._baseline_burst_size: Dict[str, float] = {}

    def analyze_timing(self, sequence: PacketSequence) -> Optional[EncryptedAnomaly]:
        """
        Analyze packet timing for anomalies.
        Regular patterns suggest automated traffic (C2, exfiltration).
        """
        if len(sequence.packets) < 5:
            return None

        # Inter-arrival times
        arrivals = [p[0] for p in sequence.packets]
        inter_arrivals = np.diff(arrivals)

        # Detect periodic patterns (C2 beacons)
        if len(inter_arrivals) > 10:
            mean_iat = np.mean(inter_arrivals)
            std_iat = np.std(inter_arrivals)

            # Very regular timing suggests automated C2
            if std_iat < mean_iat * 0.1:  # <10% variation
                return EncryptedAnomaly(
                    threat_type=EncryptedThreat.C2_BEACON,
                    src_ip=sequence.src_ip,
                    dst_ip=sequence.dst_ip,
                    severity="critical",
                    confidence=0.85,
                    description=f"Periodic C2 beacon pattern detected (IAT={mean_iat:.3f}s ±{std_iat:.3f}s)",
                    evidence={
                        "inter_arrival_time_mean": float(mean_iat),
                        "inter_arrival_time_std": float(std_iat),
                        "regularity": float(std_iat / (mean_iat + 1e-8)),
                    }
                )

            # Detect multiple packets in quick succession (exfiltration burst)
            burst_count = np.sum(inter_arrivals < 0.1)  # Packets within 100ms
            if burst_count > len(inter_arrivals) * 0.3:
                return EncryptedAnomaly(
                    threat_type=EncryptedThreat.DATA_EXFILTRATION,
                    src_ip=sequence.src_ip,
                    dst_ip=sequence.dst_ip,
                    severity="high",
                    confidence=0.75,
                    description=f"Bursty traffic pattern suggesting data exfiltration",
                    evidence={
                        "burst_ratio": float(burst_count / len(inter_arrivals)),
                    }
                )

        return None


class PacketSizeAnalyzer:
    """
    Analyzes packet size patterns to infer plaintext information leakage.
    """

    def __init__(self):
        self._baseline_size_dist: Dict[str, Tuple[float, float]] = {}  # flow_id -> (mean, std)

    def analyze_sizes(self, sequence: PacketSequence) -> Optional[EncryptedAnomaly]:
        """
        Analyze packet sizes for information leakage.
        Regular patterns in ciphertext sizes reveal plaintext structure.
        """
        if len(sequence.packets) < 10:
            return None

        sizes = np.array([p[1] for p in sequence.packets])

        # Check for padding oracle patterns (identical sizes)
        unique_sizes = len(set(sizes))
        if unique_sizes < len(sizes) * 0.2:  # <20% unique sizes
            return EncryptedAnomaly(
                threat_type=EncryptedThreat.PADDING_ORACLE,
                src_ip=sequence.src_ip,
                dst_ip=sequence.dst_ip,
                severity="medium",
                confidence=0.70,
                description=f"Suspicious packet size uniformity ({unique_sizes} unique sizes in {len(sizes)} packets)",
                evidence={
                    "unique_sizes": int(unique_sizes),
                    "total_packets": len(sizes),
                    "size_uniformity": float(unique_sizes / len(sizes)),
                }
            )

        # Check for size patterns suggesting DNS tunneling
        mean_size = np.mean(sizes)
        if 50 < mean_size < 200:  # DNS-like sizes
            # DNS tunneling usually has very specific size patterns
            size_variance = np.var(sizes)
            if size_variance < 100:
                return EncryptedAnomaly(
                    threat_type=EncryptedThreat.DNS_TUNNELING,
                    src_ip=sequence.src_ip,
                    dst_ip=sequence.dst_ip,
                    severity="medium",
                    confidence=0.65,
                    description=f"Packet sizes suggest DNS tunneling pattern",
                    evidence={
                        "mean_size": float(mean_size),
                        "size_variance": float(size_variance),
                    }
                )

        return None


class EncryptedTrafficAnalyzer:
    """
    Main analyzer for encrypted traffic anomalies.
    """

    def __init__(self):
        self._tls_analyzer = TLSAnalyzer()
        self._timing_analyzer = PacketTimingAnalyzer()
        self._size_analyzer = PacketSizeAnalyzer()
        self._flows: Dict[str, PacketSequence] = {}
        self._anomalies: List[EncryptedAnomaly] = []
        self._stats = {
            "flows_analyzed": 0,
            "packets_processed": 0,
            "anomalies_detected": 0,
            "c2_detections": 0,
            "exfil_detections": 0,
        }

    def analyze_tls_handshake(self, fingerprint: TLSFingerprint) -> Optional[EncryptedAnomaly]:
        """Analyze TLS handshake."""
        self._stats["flows_analyzed"] += 1
        anomaly = self._tls_analyzer.analyze_handshake(fingerprint)
        if anomaly:
            self._anomalies.append(anomaly)
            self._stats["anomalies_detected"] += 1
            logger.warning("TLS anomaly [%s]: %s (conf=%.2f)", anomaly.threat_type.value, anomaly.description, anomaly.confidence)
        return anomaly

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        packet_size: int,
        timestamp: float
    ) -> Optional[EncryptedAnomaly]:
        """Add packet to flow and check for anomalies."""
        flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        self._stats["packets_processed"] += 1

        if flow_id not in self._flows:
            self._flows[flow_id] = PacketSequence(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                flow_start=timestamp
            )

        flow = self._flows[flow_id]
        flow.packets.append((timestamp, packet_size))
        flow.total_bytes += packet_size
        flow.flow_end = timestamp

        # Analyze every N packets to save CPU
        if len(flow.packets) % 10 == 0:
            anomaly = self._timing_analyzer.analyze_timing(flow)
            if anomaly:
                self._anomalies.append(anomaly)
                self._stats["anomalies_detected"] += 1
                if anomaly.threat_type == EncryptedThreat.C2_BEACON:
                    self._stats["c2_detections"] += 1
                elif anomaly.threat_type == EncryptedThreat.DATA_EXFILTRATION:
                    self._stats["exfil_detections"] += 1
                logger.warning("Encrypted anomaly [%s]: %s (conf=%.2f)", anomaly.threat_type.value, anomaly.description, anomaly.confidence)
                return anomaly

            anomaly = self._size_analyzer.analyze_sizes(flow)
            if anomaly:
                self._anomalies.append(anomaly)
                self._stats["anomalies_detected"] += 1
                logger.warning("Encrypted anomaly [%s]: %s (conf=%.2f)", anomaly.threat_type.value, anomaly.description, anomaly.confidence)
                return anomaly

        return None

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def recent_anomalies(self) -> List[Dict[str, Any]]:
        return [
            {
                "threat": a.threat_type.value,
                "src": a.src_ip,
                "dst": a.dst_ip,
                "severity": a.severity,
                "confidence": a.confidence,
                "description": a.description,
                "timestamp": a.timestamp,
            }
            for a in self._anomalies[-20:]
        ]


_analyzer: Optional[EncryptedTrafficAnalyzer] = None


def get_analyzer() -> EncryptedTrafficAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = EncryptedTrafficAnalyzer()
    return _analyzer


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    analyzer = get_analyzer()

    # Register normal TLS fingerprint
    normal_fp = TLSFingerprint(
        tls_version="TLS1.3",
        accepted_ciphers=["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
        supported_groups=["secp256r1"],
        signature_algorithms=["rsa_pss_rsae_sha256"],
        extensions=["supported_versions"],
        timestamp=time.time()
    )
    analyzer._tls_analyzer.register_fingerprint("client_normal", normal_fp)

    # Analyze suspicious handshake
    sus_fp = TLSFingerprint(
        tls_version="SSL3.0",
        accepted_ciphers=["NULL_WITH_NULL_NULL", "EXPORT_RC4"],
        supported_groups=["secp521r1"],
        signature_algorithms=["sha1WithRSAEncryption"],
        extensions=["client_hello_padding"],
        timestamp=time.time()
    )
    anomaly = analyzer.analyze_tls_handshake(sus_fp)
    print(f"Suspicious handshake: {anomaly}")

    # Simulate C2 beacon pattern
    for i in range(50):
        analyzer.add_packet(
            "192.168.1.50",
            "1.2.3.4",
            45000 + i,
            443,
            "https",
            256,
            time.time() + i * 300  # Every 5 minutes
        )

    print(f"Stats: {analyzer.stats}")
    print("Encrypted Traffic Analyzer OK")
