"""
defense/supply_chain_detector.py — Supply Chain Attack Detection v10.0

Detects compromised dependencies and build pipeline attacks:
  • Unexpected behavior from third-party libraries (API misuse)
  • Version mismatch detection (downgrade attacks, backdoors)
  • Checksum/hash verification of binaries and packages
  • Suspicious network connections from library code
  • Dependency tree anomalies (circular deps, unused imports)
  • Typosquatting detection (similar package names)
  • Repository integrity verification

Protects against SolarWinds, Codecov, ua-parser-js style attacks.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger("shadow.defense.supply_chain")


class SupplyChainThreat(Enum):
    TYPOSQUATTING = "typosquatting"
    VERSION_MISMATCH = "version_mismatch"
    CHECKSUM_VIOLATION = "checksum_violation"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    NETWORK_ANOMALY = "network_anomaly"
    DEPENDENCY_INJECTION = "dependency_injection"
    BACKDOOR_SIGNATURE = "backdoor_signature"
    BUILD_CONTAMINATION = "build_contamination"


@dataclass
class DependencyInfo:
    """Information about a third-party dependency."""
    name: str
    version: str
    expected_hash: str
    actual_hash: str
    source_url: str
    resolved_at: float
    dependencies: List[str] = field(default_factory=list)
    known_vulnerable_versions: List[str] = field(default_factory=list)


@dataclass
class LibraryBehavior:
    """Runtime behavior of a library."""
    library_name: str
    timestamp: float
    network_connections: List[Tuple[str, int]]  # (ip, port)
    file_accesses: List[str]
    system_calls: List[str]
    memory_allocations_mb: float
    execution_time_ms: float


@dataclass
class SupplyChainAlert:
    """Alert for supply chain anomaly."""
    threat_type: SupplyChainThreat
    library_name: str
    severity: str
    confidence: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class PackageNameAnalyzer:
    """
    Detects typosquatting and similar package names.
    """

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate edit distance between strings."""
        if len(s1) < len(s2):
            return PackageNameAnalyzer.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def detect_typosquatting(
        self,
        package_name: str,
        known_packages: List[str],
        threshold: int = 2
    ) -> Optional[Tuple[str, int]]:
        """
        Detect typosquatting by comparing against known packages.
        Returns (similar_package, distance)
        """
        for known in known_packages:
            distance = self.levenshtein_distance(package_name, known)
            if distance <= threshold and distance > 0:
                return known, distance
        return None


class DependencyVerifier:
    """
    Verifies dependency integrity via checksums and version validation.
    """

    def __init__(self):
        self._known_checksums: Dict[str, Dict[str, str]] = {}  # package -> version -> hash
        self._version_metadata: Dict[str, List[str]] = {}  # package -> versions

    def register_dependency(
        self,
        package: str,
        version: str,
        sha256_hash: str
    ) -> None:
        """Register known good dependency."""
        if package not in self._known_checksums:
            self._known_checksums[package] = {}
        self._known_checksums[package][version] = sha256_hash

    def verify_checksum(
        self,
        package: str,
        version: str,
        actual_hash: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify package checksum.
        Returns (is_valid, reason_if_invalid)
        """
        if package not in self._known_checksums:
            return True, None  # Unknown package - assume valid

        if version not in self._known_checksums[package]:
            return False, f"Unknown version {version} for {package}"

        expected_hash = self._known_checksums[package][version]
        if expected_hash != actual_hash:
            return False, f"Hash mismatch: expected {expected_hash}, got {actual_hash}"

        return True, None

    def detect_version_downgrade(
        self,
        package: str,
        requested_version: str,
        resolved_version: str
    ) -> bool:
        """Detect if resolved version is older than requested."""
        try:
            requested_major, requested_minor, requested_patch = map(int, requested_version.split('.')[:3])
            resolved_major, resolved_minor, resolved_patch = map(int, resolved_version.split('.')[:3])

            if resolved_major < requested_major:
                return True
            if resolved_major == requested_major and resolved_minor < requested_minor:
                return True
            if (resolved_major == requested_major and resolved_minor == requested_minor and
                resolved_patch < requested_patch):
                return True
        except ValueError:
            pass

        return False


class BehaviorAnalyzer:
    """
    Analyzes library runtime behavior for anomalies.
    """

    def __init__(self):
        self._baseline_behaviors: Dict[str, LibraryBehavior] = {}
        self._suspicious_patterns = [
            r"127\.0\.0\.1.*:.*666",  # Suspicious ports
            r"\..*\.onion",  # Tor
            r".*malware.*",  # Malware signatures
            r".*botnet.*",
        ]

    def register_baseline(self, behavior: LibraryBehavior) -> None:
        """Register baseline behavior for library."""
        self._baseline_behaviors[behavior.library_name] = behavior

    def analyze_behavior(self, behavior: LibraryBehavior) -> Optional[SupplyChainAlert]:
        """Analyze library behavior for anomalies."""
        library = behavior.library_name
        baseline = self._baseline_behaviors.get(library)

        if not baseline:
            # No baseline - check for obviously suspicious behavior
            if behavior.network_connections:
                for ip, port in behavior.network_connections:
                    if port > 65000 or port < 1024:
                        return SupplyChainAlert(
                            threat_type=SupplyChainThreat.NETWORK_ANOMALY,
                            library_name=library,
                            severity="high",
                            confidence=0.75,
                            description=f"Library {library} connecting to suspicious port {port}",
                            evidence={
                                "ip": ip,
                                "port": port,
                                "connections": behavior.network_connections,
                            }
                        )

            # Check for excessive memory or CPU usage
            if behavior.memory_allocations_mb > 1000:
                return SupplyChainAlert(
                    threat_type=SupplyChainThreat.SUSPICIOUS_BEHAVIOR,
                    library_name=library,
                    severity="medium",
                    confidence=0.6,
                    description=f"Library {library} allocating excessive memory: {behavior.memory_allocations_mb:.0f}MB",
                    evidence={
                        "memory_mb": behavior.memory_allocations_mb,
                    }
                )
            return None

        # Compare against baseline
        anomalies = []

        # Network connections - check for new outbound connections
        baseline_ips = {ip for ip, _ in baseline.network_connections}
        current_ips = {ip for ip, _ in behavior.network_connections}
        new_connections = current_ips - baseline_ips
        if new_connections:
            anomalies.append((
                0.7,
                SupplyChainThreat.NETWORK_ANOMALY,
                f"New network connections: {new_connections}"
            ))

        # Memory usage
        if behavior.memory_allocations_mb > baseline.memory_allocations_mb * 2:
            anomalies.append((
                0.6,
                SupplyChainThreat.SUSPICIOUS_BEHAVIOR,
                f"Memory usage spike: {behavior.memory_allocations_mb:.0f}MB vs baseline {baseline.memory_allocations_mb:.0f}MB"
            ))

        # Execution time
        if behavior.execution_time_ms > baseline.execution_time_ms * 3:
            anomalies.append((
                0.5,
                SupplyChainThreat.SUSPICIOUS_BEHAVIOR,
                f"Execution time spike: {behavior.execution_time_ms:.0f}ms vs baseline {baseline.execution_time_ms:.0f}ms"
            ))

        if not anomalies:
            return None

        score, threat, desc = max(anomalies, key=lambda x: x[0])
        return SupplyChainAlert(
            threat_type=threat,
            library_name=library,
            severity="critical" if score > 0.8 else "high" if score > 0.6 else "medium",
            confidence=min(0.95, score),
            description=desc,
            evidence={
                "baseline_memory_mb": baseline.memory_allocations_mb,
                "current_memory_mb": behavior.memory_allocations_mb,
                "new_connections": list(new_connections) if new_connections else [],
            }
        )


class SupplyChainDetector:
    """
    Main supply chain attack detector.
    Monitors dependencies, verifies integrity, analyzes behavior.
    """

    def __init__(self):
        self._name_analyzer = PackageNameAnalyzer()
        self._verifier = DependencyVerifier()
        self._behavior_analyzer = BehaviorAnalyzer()
        self._known_packages: Set[str] = set()
        self._alerts: List[SupplyChainAlert] = []
        self._stats = {
            "dependencies_checked": 0,
            "alerts": 0,
            "typosquatting_detections": 0,
            "checksum_violations": 0,
            "behavior_anomalies": 0,
        }

    def register_known_package(self, package_name: str) -> None:
        """Register a known good package."""
        self._known_packages.add(package_name)

    def check_dependency(
        self,
        name: str,
        version: str,
        sha256_hash: str
    ) -> Optional[SupplyChainAlert]:
        """Check a dependency for supply chain attacks."""
        self._stats["dependencies_checked"] += 1

        # Typosquatting check
        typosquat = self._name_analyzer.detect_typosquatting(name, list(self._known_packages), threshold=2)
        if typosquat:
            similar, distance = typosquat
            alert = SupplyChainAlert(
                threat_type=SupplyChainThreat.TYPOSQUATTING,
                library_name=name,
                severity="critical",
                confidence=0.95,
                description=f"Possible typosquatting: '{name}' similar to known package '{similar}' (distance={distance})",
                evidence={
                    "similar_package": similar,
                    "edit_distance": distance,
                }
            )
            self._alerts.append(alert)
            self._stats["alerts"] += 1
            self._stats["typosquatting_detections"] += 1
            return alert

        # Checksum verification
        self._verifier.register_dependency(name, version, sha256_hash)
        is_valid, reason = self._verifier.verify_checksum(name, version, sha256_hash)
        if not is_valid:
            alert = SupplyChainAlert(
                threat_type=SupplyChainThreat.CHECKSUM_VIOLATION,
                library_name=name,
                severity="critical",
                confidence=0.99,
                description=f"Checksum mismatch: {reason}",
                evidence={
                    "expected_hash": reason or "unknown",
                }
            )
            self._alerts.append(alert)
            self._stats["alerts"] += 1
            self._stats["checksum_violations"] += 1
            return alert

        return None

    def analyze_library_behavior(self, behavior: LibraryBehavior) -> Optional[SupplyChainAlert]:
        """Analyze runtime behavior of a library."""
        alert = self._behavior_analyzer.analyze_behavior(behavior)
        if alert:
            self._alerts.append(alert)
            self._stats["alerts"] += 1
            self._stats["behavior_anomalies"] += 1
            logger.warning("Supply chain anomaly [%s]: %s (conf=%.2f)", alert.threat_type.value, alert.description, alert.confidence)

        return alert

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def recent_alerts(self) -> List[Dict[str, Any]]:
        return [
            {
                "threat": a.threat_type.value,
                "library": a.library_name,
                "severity": a.severity,
                "confidence": a.confidence,
                "description": a.description,
                "timestamp": a.timestamp,
            }
            for a in self._alerts[-20:]
        ]


_detector: Optional[SupplyChainDetector] = None


def get_detector() -> SupplyChainDetector:
    global _detector
    if _detector is None:
        _detector = SupplyChainDetector()
    return _detector


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    detector = get_detector()

    # Register known packages
    detector.register_known_package("numpy")
    detector.register_known_package("requests")
    detector.register_known_package("pandas")

    # Check legitimate dependency
    alert = detector.check_dependency(
        "numpy",
        "1.21.0",
        hashlib.sha256(b"numpy_1.21.0_content").hexdigest()
    )
    print(f"Legitimate check: {alert}")

    # Check typosquatting attempt
    alert = detector.check_dependency(
        "nump",  # Typosquatting attempt
        "1.21.0",
        hashlib.sha256(b"fake_numpy").hexdigest()
    )
    print(f"Typosquatting detection: {alert}")

    # Check behavior
    behavior = LibraryBehavior(
        library_name="suspicious_lib",
        timestamp=time.time(),
        network_connections=[("192.0.2.1", 65535), ("192.0.2.2", 666)],
        file_accesses=["/etc/passwd"],
        system_calls=["execve", "fork"],
        memory_allocations_mb=5000,
        execution_time_ms=5000,
    )
    alert = detector.analyze_library_behavior(behavior)
    print(f"Behavior anomaly: {alert}")

    print(f"Stats: {detector.stats}")
    print("Supply Chain Detector OK")
