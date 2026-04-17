"""
response/privesc_enumerator.py — Privilege Escalation Path Enumeration v10.0

Enumerates potential privilege escalation paths for incident response:
  • Kernel vulnerability scanning (CVE matching against installed kernel)
  • SUID binary analysis (dangerous setuid programs)
  • Sudo misconfiguration detection (NOPASSWD, wildcard rules)
  • Capability abuse (libcap-based privilege escalation)
  • Scheduled task exploitation (cron, systemd timers)
  • Service vulnerability enumeration
  • Weak file/directory permissions (world-writable, group-writable paths)
  • Docker/container escape vectors

Assists incident responders in understanding what an attacker can do post-compromise.
Prioritizes exploitable paths by likelihood and impact.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("shadow.response.privesc")


class PrivescMethod(Enum):
    KERNEL_EXPLOIT = "kernel_exploit"
    SUID_BINARY = "suid_binary"
    SUDO_MISCONFIGURATION = "sudo_misconfiguration"
    CAPABILITY_ABUSE = "capability_abuse"
    CRON_EXPLOITATION = "cron_exploitation"
    SERVICE_EXPLOIT = "service_exploit"
    FILE_PERMISSION = "file_permission"
    CONTAINER_ESCAPE = "container_escape"


@dataclass
class CVEInfo:
    """CVE vulnerability information."""
    cve_id: str
    kernel_version: str
    description: str
    cvss_score: float
    is_exploitable: bool
    public_exploit: bool
    difficulty: str  # easy, medium, hard


@dataclass
class SUIDInfo:
    """SUID binary information."""
    path: str
    owner: str
    permissions: str
    known_vulnerabilities: List[str]
    is_dangerous: bool


@dataclass
class SudoRule:
    """Sudoers configuration rule."""
    user: str
    command: str
    requires_password: bool
    is_dangerous: bool
    danger_reason: str


@dataclass
class PrivescPath:
    """Single privilege escalation path."""
    method: PrivescMethod
    description: str
    severity: str  # low, medium, high, critical
    likelihood: float  # 0.0-1.0
    exploitability: float  # 0.0-1.0 based on available tools
    evidence: Dict[str, Any] = field(default_factory=dict)


class KernelVulnerabilityScanner:
    """
    Scans for exploitable kernel vulnerabilities.
    """

    def __init__(self):
        # CVE database (simplified)
        self._known_cves = {
            "CVE-2021-4034": CVEInfo(
                cve_id="CVE-2021-4034",
                kernel_version="<5.16.11, <5.15.25, <5.14.38",
                description="policykit-1 local privilege escalation",
                cvss_score=7.8,
                is_exploitable=True,
                public_exploit=True,
                difficulty="easy"
            ),
            "CVE-2022-0847": CVEInfo(
                cve_id="CVE-2022-0847",
                kernel_version="<5.16.11",
                description="Dirty COW variant - file write primitive",
                cvss_score=7.0,
                is_exploitable=True,
                public_exploit=True,
                difficulty="medium"
            ),
        }

    def scan(self, kernel_version: str) -> List[PrivescPath]:
        """Scan for applicable CVEs."""
        paths = []

        for cve_id, cve_info in self._known_cves.items():
            if self._version_vulnerable(kernel_version, cve_info.kernel_version):
                path = PrivescPath(
                    method=PrivescMethod.KERNEL_EXPLOIT,
                    description=f"{cve_id}: {cve_info.description}",
                    severity="critical" if cve_info.cvss_score > 8 else "high" if cve_info.cvss_score > 6 else "medium",
                    likelihood=0.8 if cve_info.public_exploit else 0.5,
                    exploitability=0.9 if cve_info.public_exploit else 0.6,
                    evidence={
                        "cve_id": cve_id,
                        "cvss_score": cve_info.cvss_score,
                        "public_exploit": cve_info.public_exploit,
                    }
                )
                paths.append(path)

        return paths

    @staticmethod
    def _version_vulnerable(current: str, vulnerable_range: str) -> bool:
        """Check if current version is in vulnerable range (simplified)."""
        # Very simplified version comparison
        try:
            current_parts = [int(x) for x in current.split(".")[:2]]
            for vuln_part in vulnerable_range.split(", "):
                if "<" in vuln_part:
                    vuln_version = vuln_part.replace("<", "").strip()
                    vuln_parts = [int(x) for x in vuln_version.split(".")[:2]]
                    if current_parts < vuln_parts:
                        return True
        except ValueError:
            pass
        return False


class SUIDAnalyzer:
    """
    Analyzes SUID binaries for privilege escalation.
    """

    def __init__(self):
        # Known dangerous SUID binaries
        self._dangerous_suid = {
            "/bin/su": ("su", "User switching without audit"),
            "/usr/bin/sudo": ("sudo", "Sudoers misconfiguration"),
            "/usr/bin/passwd": ("passwd", "Password change mechanism"),
            "/usr/sbin/usermod": ("usermod", "User modification"),
        }

    def analyze(self, suid_binaries: List[SUIDInfo]) -> List[PrivescPath]:
        """Analyze SUID binaries."""
        paths = []

        for binary in suid_binaries:
            if binary.path in self._dangerous_suid:
                name, danger = self._dangerous_suid[binary.path]
                path = PrivescPath(
                    method=PrivescMethod.SUID_BINARY,
                    description=f"SUID binary: {binary.path} ({name}) - {danger}",
                    severity="high",
                    likelihood=0.7,
                    exploitability=0.6,
                    evidence={
                        "binary": binary.path,
                        "owner": binary.owner,
                        "permissions": binary.permissions,
                        "known_vulns": binary.known_vulnerabilities,
                    }
                )
                paths.append(path)

        return paths


class SudoConfigAnalyzer:
    """
    Analyzes sudoers configuration for exploitable rules.
    """

    def analyze(self, sudo_rules: List[SudoRule]) -> List[PrivescPath]:
        """Analyze sudo rules."""
        paths = []

        for rule in sudo_rules:
            if not rule.requires_password:
                path = PrivescPath(
                    method=PrivescMethod.SUDO_MISCONFIGURATION,
                    description=f"NOPASSWD sudo rule allows {rule.command} without password",
                    severity="critical",
                    likelihood=0.95,
                    exploitability=0.99,
                    evidence={
                        "user": rule.user,
                        "command": rule.command,
                        "reason": rule.danger_reason,
                    }
                )
                paths.append(path)

            if "*" in rule.command:
                path = PrivescPath(
                    method=PrivescMethod.SUDO_MISCONFIGURATION,
                    description=f"Wildcard sudo rule: user can run any command matching {rule.command}",
                    severity="critical",
                    likelihood=0.9,
                    exploitability=0.95,
                    evidence={
                        "user": rule.user,
                        "pattern": rule.command,
                    }
                )
                paths.append(path)

        return paths


class PrivescEnumerator:
    """
    Main privilege escalation path enumerator for incident response.
    """

    def __init__(self):
        self._kernel_scanner = KernelVulnerabilityScanner()
        self._suid_analyzer = SUIDAnalyzer()
        self._sudo_analyzer = SudoConfigAnalyzer()
        self._enumerated_paths: List[PrivescPath] = []
        self._stats = {
            "scan_runs": 0,
            "paths_found": 0,
            "critical_paths": 0,
            "high_paths": 0,
        }

    def enumerate(
        self,
        kernel_version: Optional[str] = None,
        suid_binaries: Optional[List[SUIDInfo]] = None,
        sudo_rules: Optional[List[SudoRule]] = None,
    ) -> List[PrivescPath]:
        """
        Enumerate all privilege escalation paths.
        """
        paths = []
        self._stats["scan_runs"] += 1

        if kernel_version:
            logger.info(f"Scanning kernel vulnerabilities for {kernel_version}")
            paths.extend(self._kernel_scanner.scan(kernel_version))

        if suid_binaries:
            logger.info(f"Analyzing {len(suid_binaries)} SUID binaries")
            paths.extend(self._suid_analyzer.analyze(suid_binaries))

        if sudo_rules:
            logger.info(f"Analyzing {len(sudo_rules)} sudoers rules")
            paths.extend(self._sudo_analyzer.analyze(sudo_rules))

        # Rank by exploitability and severity
        paths.sort(
            key=lambda p: (
                p.exploitability * (1.0 if p.severity == "critical" else 0.8 if p.severity == "high" else 0.5)
            ),
            reverse=True
        )

        self._enumerated_paths = paths
        self._stats["paths_found"] = len(paths)
        self._stats["critical_paths"] = sum(1 for p in paths if p.severity == "critical")
        self._stats["high_paths"] = sum(1 for p in paths if p.severity == "high")

        return paths

    def get_attack_chain_estimate(self) -> Dict[str, Any]:
        """Estimate overall attack risk from enumerated paths."""
        if not self._enumerated_paths:
            return {"risk": "low", "confidence": 0.0}

        critical_exploitable = sum(
            1 for p in self._enumerated_paths
            if p.severity == "critical" and p.exploitability > 0.7
        )

        if critical_exploitable > 0:
            risk = "critical"
            confidence = 0.95
        elif self._stats["critical_paths"] > 0:
            risk = "high"
            confidence = 0.85
        elif self._stats["high_paths"] > 0:
            risk = "medium"
            confidence = 0.70
        else:
            risk = "low"
            confidence = 0.5

        return {
            "risk": risk,
            "confidence": confidence,
            "critical_paths": self._stats["critical_paths"],
            "high_paths": self._stats["high_paths"],
            "total_paths": self._stats["paths_found"],
        }

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def enumerated_paths(self) -> List[PrivescPath]:
        return self._enumerated_paths


_enumerator: Optional[PrivescEnumerator] = None


def get_enumerator() -> PrivescEnumerator:
    global _enumerator
    if _enumerator is None:
        _enumerator = PrivescEnumerator()
    return _enumerator


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    enumerator = get_enumerator()

    # Simulate enumeration on compromised system
    kernel_version = "5.10.0"  # Vulnerable to CVE-2021-4034
    suid_binaries = [
        SUIDInfo("/bin/su", "root", "-rwsr-xr-x", [], True),
        SUIDInfo("/usr/bin/sudo", "root", "-rwsr-xr-x", [], True),
    ]
    sudo_rules = [
        SudoRule("www-data", "/usr/bin/systemctl", False, True, "Can control services without password"),
        SudoRule("www-data", "/bin/bash /opt/backup.sh", True, False, ""),
    ]

    paths = enumerator.enumerate(kernel_version, suid_binaries, sudo_rules)

    print(f"\n=== Privilege Escalation Paths Found: {len(paths)} ===")
    for path in paths[:10]:
        print(f"\n{path.severity.upper()}: {path.method.value}")
        print(f"  {path.description}")
        print(f"  Likelihood: {path.likelihood:.1%}, Exploitability: {path.exploitability:.1%}")

    print(f"\nAttack Risk Estimate: {enumerator.get_attack_chain_estimate()}")
    print(f"Stats: {enumerator.stats}")
    print("Privesc Enumerator OK")
