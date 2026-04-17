"""
simulators/auto_threat_simulator.py — Proactive Threat Emulation v10.0

Auto-generates realistic adversarial threat scenarios for testing:
  • Initial reconnaissance patterns (port scans, service enumeration)
  • Lateral movement chains (hop-by-hop network traversal)
  • Privilege escalation attempts (kernel exploits, credential theft)
  • Data exfiltration patterns (large transfers, protocol tunneling)
  • Command-and-control beacons (periodic check-ins with dead-drop exfil)
  • Post-exploitation persistence (cron jobs, registry modifications, rootkits)

Generates synthetic threat vectors to validate detection pipeline.
"""

from __future__ import annotations

import logging
import random
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("shadow.simulator.threat")

# Adjust path for imports
SHADOW_ML_ROOT = Path(__file__).parent.parent
if str(SHADOW_ML_ROOT) not in sys.path:
    sys.path.insert(0, str(SHADOW_ML_ROOT))

try:
    from core.neural_engine import ThreatVector
except ImportError:
    logger.warning("Neural engine not available for simulation validation")


class ThreatPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"


class AttackPattern(Enum):
    PORT_SCAN = "port_scan"
    SERVICE_ENUM = "service_enumeration"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_HOP = "lateral_hop"
    DATA_THEFT = "data_theft"
    C2_BEACON = "c2_beacon"
    PERSISTENCE_MECHANISM = "persistence"


@dataclass
class ThreatScenario:
    """Single threat scenario with multiple stages."""
    scenario_id: str
    phases: List[ThreatPhase]
    duration_seconds: int
    attack_patterns: List[AttackPattern]
    target_assets: List[str]
    severity: str  # low, medium, high, critical
    description: str


@dataclass
class SimulatedEvent:
    """Simulated network/system event."""
    timestamp: float
    event_type: str
    source_ip: str
    dest_ip: str
    protocol: str
    payload_size: int
    flags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ThreatSimulator:
    """
    Generates realistic threat scenarios for testing Shadow NDR detection capabilities.
    """

    def __init__(self):
        self._scenarios: List[ThreatScenario] = []
        self._current_scenario: Optional[ThreatScenario] = None
        self._events_generated: int = 0
        self._detections: int = 0
        self._stats = {
            "scenarios": 0,
            "events": 0,
            "phases_simulated": 0,
            "critical_events": 0,
        }

    def generate_reconnaissance_pattern(self) -> List[SimulatedEvent]:
        """Generate port scan and service enumeration events."""
        events = []
        attacker_ip = f"10.0.0.{random.randint(1, 254)}"
        timestamp = time.time()

        # Port scan: sequential port probing
        for port in random.sample(range(1, 65535), 50):
            events.append(SimulatedEvent(
                timestamp=timestamp + random.uniform(0, 10),
                event_type="syn_packet",
                source_ip=attacker_ip,
                dest_ip=f"192.168.1.{random.randint(1, 254)}",
                protocol="tcp",
                payload_size=0,
                flags=["SYN"],
                metadata={
                    "port": port,
                    "pattern": "port_scan",
                    "scan_speed": "fast",
                }
            ))

        # Service version grabbing
        events.append(SimulatedEvent(
            timestamp=timestamp + 15,
            event_type="http_request",
            source_ip=attacker_ip,
            dest_ip="192.168.1.100",
            protocol="http",
            payload_size=256,
            flags=["USER_AGENT_PROBE"],
            metadata={
                "user_agent": "nmap-http-user-agent",
                "path": "/",
            }
        ))

        self._stats["events"] += len(events)
        return events

    def generate_exploitation_pattern(self, target_ip: str = "192.168.1.100") -> List[SimulatedEvent]:
        """Generate exploit attempt events."""
        events = []
        attacker_ip = f"10.0.0.{random.randint(1, 254)}"
        timestamp = time.time()

        # CVE-style payload delivery
        exploit_payloads = [
            "shellcode_buf_overflow",
            "javascript_heap_spray",
            "kernel_uaf_gadget",
            "sql_injection_union_select",
        ]

        payload = random.choice(exploit_payloads)
        payload_size = random.randint(500, 5000)

        events.append(SimulatedEvent(
            timestamp=timestamp,
            event_type="malicious_payload",
            source_ip=attacker_ip,
            dest_ip=target_ip,
            protocol="http" if random.random() > 0.3 else "tcp",
            payload_size=payload_size,
            flags=["EXPLOIT", "POLYMORPHIC"],
            metadata={
                "payload_type": payload,
                "cve": f"CVE-{random.randint(2015, 2024)}-{random.randint(10000, 99999)}",
                "encoder": "xor_rotation",
                "entropy": random.uniform(0.6, 0.95),
            }
        ))

        self._stats["events"] += len(events)
        return events

    def generate_lateral_movement_pattern(self, starting_node: str = "192.168.1.100") -> List[SimulatedEvent]:
        """Generate lateral movement and hop-by-hop traversal."""
        events = []
        timestamp = time.time()

        # Simulate attacker moving from node to node
        path = [starting_node]
        for _ in range(random.randint(2, 5)):
            path.append(f"192.168.1.{random.randint(1, 254)}")

        # SMB lateral movement (Windows)
        for i, source in enumerate(path[:-1]):
            target = path[i + 1]
            events.append(SimulatedEvent(
                timestamp=timestamp + (i * 10),
                event_type="smb_connection",
                source_ip=source,
                dest_ip=target,
                protocol="smb",
                payload_size=random.randint(100, 1000),
                flags=["LATERAL_MOVE", "CREDENTIAL_REUSE"],
                metadata={
                    "share": "ADMIN$" if random.random() > 0.5 else "C$",
                    "user": "SYSTEM" if random.random() > 0.6 else "Administrator",
                    "auth_method": "ntlm_relay" if random.random() > 0.7 else "credential_dump",
                }
            ))

        self._stats["events"] += len(events)
        return events

    def generate_privilege_escalation_pattern(self, target_ip: str = "192.168.1.100") -> List[SimulatedEvent]:
        """Generate privilege escalation attempts."""
        events = []
        timestamp = time.time()

        escalation_methods = [
            ("kernel_exploit", "cve_exploit", "vulnerable_kernel_module"),
            ("dll_hijacking", "persistence", "windows_update"),
            ("sudo_misconfiguration", "priv_esc", "sudoers_parsing"),
            ("setuid_binary", "buffer_overflow", "vulnerable_binary"),
        ]

        method, technique, target = random.choice(escalation_methods)

        events.append(SimulatedEvent(
            timestamp=timestamp,
            event_type="system_call",
            source_ip=target_ip,
            dest_ip=target_ip,
            protocol="local",
            payload_size=random.randint(200, 2000),
            flags=["PRIV_ESC", "RING0"],
            metadata={
                "method": method,
                "technique": technique,
                "target_process": target,
                "pid": random.randint(1000, 9999),
                "syscall": "ioctl" if method == "kernel_exploit" else "execve",
            }
        ))

        events.append(SimulatedEvent(
            timestamp=timestamp + 5,
            event_type="process_spawned",
            source_ip=target_ip,
            dest_ip=target_ip,
            protocol="local",
            payload_size=100,
            flags=["ELEVATED", "SYSTEM"],
            metadata={
                "process": "cmd.exe" if random.random() > 0.5 else "/bin/bash",
                "parent_pid": random.randint(1000, 9999),
                "privilege_level": "SYSTEM",
            }
        ))

        self._stats["events"] += len(events)
        return events

    def generate_exfiltration_pattern(self, source_ip: str = "192.168.1.100") -> List[SimulatedEvent]:
        """Generate data exfiltration patterns."""
        events = []
        timestamp = time.time()

        exfil_methods = [
            ("dns_tunneling", "dns", 53),
            ("https_covert_channel", "https", 443),
            ("ftp_data_transfer", "ftp", 21),
            ("smtp_attachment", "smtp", 25),
        ]

        method, protocol, port = random.choice(exfil_methods)

        # Large data transfer
        for chunk in range(10):
            events.append(SimulatedEvent(
                timestamp=timestamp + (chunk * 2),
                event_type="data_transfer",
                source_ip=source_ip,
                dest_ip=f"attacker.{['com', 'net', 'org'][random.randint(0, 2)]}",
                protocol=protocol,
                payload_size=random.randint(100000, 5000000),
                flags=["EXFILTRATION", "HIGH_VOLUME"],
                metadata={
                    "method": method,
                    "dest_port": port,
                    "bytes_transferred": random.randint(100000, 5000000),
                    "duration_seconds": 60,
                    "data_type": random.choice(["source_code", "db_dump", "credentials", "documents"]),
                }
            ))

        self._stats["events"] += len(events)
        return events

    def generate_c2_beacon_pattern(self, infected_host: str = "192.168.1.50") -> List[SimulatedEvent]:
        """Generate command-and-control beacon pattern."""
        events = []
        timestamp = time.time()

        # Periodic check-in
        c2_server = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

        for beacon_num in range(5):
            events.append(SimulatedEvent(
                timestamp=timestamp + (beacon_num * 300),  # 5-min interval
                event_type="http_request",
                source_ip=infected_host,
                dest_ip=c2_server,
                protocol="https",
                payload_size=256,
                flags=["C2_BEACON", "SUSPICIOUS_INTERVAL"],
                metadata={
                    "beacon_interval": 300,
                    "host_header": "innocent-domain.com",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0)",
                    "path": "/check",
                    "dead_drop": True,
                }
            ))

        self._stats["events"] += len(events)
        return events

    def generate_persistence_pattern(self, target_ip: str = "192.168.1.100") -> List[SimulatedEvent]:
        """Generate post-exploitation persistence mechanisms."""
        events = []
        timestamp = time.time()

        persistence_methods = [
            ("cron_job", "scheduled_task"),
            ("registry_run_key", "windows_startup"),
            ("ld_preload", "library_injection"),
            ("rootkit_installation", "kernel_module"),
        ]

        method, mechanism = random.choice(persistence_methods)

        events.append(SimulatedEvent(
            timestamp=timestamp,
            event_type="file_system_event",
            source_ip=target_ip,
            dest_ip=target_ip,
            protocol="local",
            payload_size=random.randint(1000, 10000),
            flags=["PERSISTENCE", "FILE_WRITE"],
            metadata={
                "method": method,
                "mechanism": mechanism,
                "file_path": f"/etc/cron.d/scheduler" if method == "cron_job" else f"HKLM\\Software\\Microsoft\\Windows\\Run",
                "file_size": random.randint(1000, 10000),
            }
        ))

        self._stats["events"] += len(events)
        self._stats["critical_events"] += 1
        return events

    def generate_full_attack_chain(self) -> List[SimulatedEvent]:
        """Generate complete multi-stage attack chain."""
        all_events = []

        logger.info("Generating reconnaissance phase...")
        all_events.extend(self.generate_reconnaissance_pattern())
        self._stats["phases_simulated"] += 1

        logger.info("Generating exploitation phase...")
        all_events.extend(self.generate_exploitation_pattern())
        self._stats["phases_simulated"] += 1

        logger.info("Generating lateral movement phase...")
        all_events.extend(self.generate_lateral_movement_pattern())
        self._stats["phases_simulated"] += 1

        logger.info("Generating privilege escalation phase...")
        all_events.extend(self.generate_privilege_escalation_pattern())
        self._stats["phases_simulated"] += 1

        logger.info("Generating persistence phase...")
        all_events.extend(self.generate_persistence_pattern())
        self._stats["phases_simulated"] += 1

        logger.info("Generating exfiltration phase...")
        all_events.extend(self.generate_exfiltration_pattern())
        self._stats["phases_simulated"] += 1

        logger.info("Generating C2 beacon phase...")
        all_events.extend(self.generate_c2_beacon_pattern())
        self._stats["phases_simulated"] += 1

        self._stats["events"] += len(all_events)
        self._stats["scenarios"] += 1

        return all_events

    def simulate_to_threat_vectors(self, events: List[SimulatedEvent]) -> List[ThreatVector]:
        """Convert simulated events to threat vectors."""
        vectors = []
        for event in events:
            # Construct feature vector from event
            features = [
                event.payload_size / 10000.0,  # normalize
                len(event.flags) / 10.0,
                ord(event.event_type[0]) / 255.0,
                random.uniform(0.0, 1.0),  # anomaly features
            ]

            # Ensure we have enough dimensions
            while len(features) < 512:
                features.append(random.uniform(0.0, 1.0))

            vector = ThreatVector(
                raw_features=features[:512],
                protocol=event.protocol,
            )
            vectors.append(vector)

        return vectors

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)


_simulator: Optional[ThreatSimulator] = None


def get_simulator() -> ThreatSimulator:
    global _simulator
    if _simulator is None:
        _simulator = ThreatSimulator()
    return _simulator


def run_simulator(continuous: bool = False, iterations: int = 1):
    """Run threat simulator standalone."""
    logging.basicConfig(level=logging.INFO)
    simulator = get_simulator()

    iteration = 0
    while continuous or iteration < iterations:
        logger.info(f"=== Simulation Round {iteration + 1} ===")

        # Generate attack chain
        events = simulator.generate_full_attack_chain()

        logger.info(f"Generated {len(events)} threat events")
        logger.info(f"Stats: {simulator.stats}")

        if not continuous:
            iteration += 1
            time.sleep(5)
        else:
            time.sleep(300)  # 5 minutes between continuous runs


if __name__ == "__main__":
    run_simulator(continuous=False, iterations=1)
