"""
rl/predictive_canary.py — Predictive Canary Token Deployment v10.0

AI predicts where an attacker will laterally move next and plants
fake honey-token files/services there BEFORE the attacker arrives.

Attack path prediction:
  • Graph-based lateral movement modelling (host-to-host access patterns)
  • Markov chain transition model trained on attack simulations
  • Priority scoring: balance likelihood vs. operational sensitivity
  • Integration with canary_tokens module to deploy appropriate bait

Deployment strategy:
  • Credentials (SSH keys, tokens) → in directories attackers target
  • Services (RDP, SMB shares) → honeypot listeners on predicted targets
  • Files (config files, DB dumps) → canary documents with tracking
  • ADS-B transponder IDs → if attacker probing aviation systems
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("shadow.rl.predictive_canary")


# ---------------------------------------------------------------------------
# Network graph model
# ---------------------------------------------------------------------------

@dataclass
class NetworkNode:
    """Represents a host/service in the network."""
    node_id: str
    ip: str
    role: str           # workstation / server / switch / router / scada / atc
    os: str = ""
    services: List[str] = field(default_factory=list)
    sensitivity: float = 0.5   # 0=low, 1=critical
    compromised: bool = False
    canaries_deployed: int = 0
    last_seen_lateral: float = 0.0


class LateralMovementGraph:
    """
    Directed weighted graph of network connections.
    Edge weight = probability of lateral movement A→B given A is compromised.
    """

    def __init__(self):
        self._nodes: Dict[str, NetworkNode] = {}
        self._edges: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._transition_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._total_from: Dict[str, int] = defaultdict(int)

    def add_node(self, node: NetworkNode) -> None:
        self._nodes[node.node_id] = node

    def add_edge(self, from_id: str, to_id: str, weight: float = 0.1) -> None:
        self._edges[from_id][to_id] = weight

    def observe_lateral(self, from_id: str, to_id: str) -> None:
        """Record observed lateral movement to update transition probabilities."""
        self._transition_counts[from_id][to_id] += 1
        self._total_from[from_id] += 1
        # Update MLE probability
        total = self._total_from[from_id]
        for dest, count in self._transition_counts[from_id].items():
            self._edges[from_id][dest] = count / total

    def get_neighbors(self, node_id: str) -> List[Tuple[str, float]]:
        """Return (neighbor_id, transition_prob) sorted by probability."""
        return sorted(self._edges.get(node_id, {}).items(), key=lambda x: -x[1])

    def top_next_targets(
        self,
        compromised_nodes: Set[str],
        top_k: int = 5,
    ) -> List[Tuple[str, float]]:
        """
        Given currently compromised nodes, predict the most likely next targets.
        Returns list of (node_id, combined_score).
        """
        candidate_scores: Dict[str, float] = defaultdict(float)

        for comp_id in compromised_nodes:
            for neighbor_id, prob in self.get_neighbors(comp_id):
                if neighbor_id not in compromised_nodes:
                    node = self._nodes.get(neighbor_id)
                    if node:
                        # Combine: transition probability × sensitivity × recency
                        recency_bonus = 1.0
                        candidate_scores[neighbor_id] += prob * (1 + node.sensitivity) * recency_bonus

        return sorted(candidate_scores.items(), key=lambda x: -x[1])[:top_k]


# ---------------------------------------------------------------------------
# Attack path predictor (Markov + heuristics)
# ---------------------------------------------------------------------------

class AttackPathPredictor:
    """
    Multi-step attack path prediction using k-step Markov rollout.
    Combines graph transition probabilities with MITRE ATT&CK kill-chain heuristics.
    """

    # MITRE ATT&CK lateral movement techniques by node role
    ROLE_TECHNIQUES = {
        "workstation": ["pass_the_hash", "rdp", "smb_share"],
        "server":      ["service_exploitation", "scheduled_task", "wmi"],
        "switch":      ["snmp_exploit", "telnet_bruteforce"],
        "router":      ["ospf_injection", "bgp_hijack", "snmp"],
        "scada":       ["modbus_write", "dnp3_inject", "s7_exploit"],
        "atc":         ["acars_inject", "adsb_spoof", "cpdlc_hijack"],
    }

    def __init__(self, graph: LateralMovementGraph, horizon: int = 3):
        self.graph = graph
        self.horizon = horizon

    def predict_path(self, compromised: Set[str]) -> List[Dict[str, Any]]:
        """
        Rollout attack paths for `horizon` steps.
        Returns list of prediction steps with node, probability, and likely technique.
        """
        current_compromised = set(compromised)
        path = []

        for step in range(self.horizon):
            next_targets = self.graph.top_next_targets(current_compromised, top_k=3)
            if not next_targets:
                break

            step_predictions = []
            for node_id, score in next_targets:
                node = self.graph._nodes.get(node_id)
                techniques = self.ROLE_TECHNIQUES.get(node.role if node else "workstation", [])
                step_predictions.append({
                    "step": step + 1,
                    "node_id": node_id,
                    "ip": node.ip if node else "unknown",
                    "role": node.role if node else "unknown",
                    "predicted_score": round(score, 4),
                    "likely_techniques": techniques[:2],
                    "sensitivity": node.sensitivity if node else 0.5,
                })
            path.extend(step_predictions)

            # Simulate compromise of highest-scored target for next step
            if next_targets:
                current_compromised.add(next_targets[0][0])

        return path


# ---------------------------------------------------------------------------
# Canary token selector
# ---------------------------------------------------------------------------

class CanarySelector:
    """
    Selects the most effective canary token type for a given node role.
    Maps node characteristics to token type and placement strategy.
    """

    ROLE_TO_CANARY = {
        "workstation": [
            {"type": "aws_api_key", "placement": "~/.aws/credentials", "priority": 0.9},
            {"type": "ssh_private_key", "placement": "~/.ssh/id_rsa", "priority": 0.85},
            {"type": "password_file", "placement": "~/passwords.txt", "priority": 0.7},
        ],
        "server": [
            {"type": "database_connection_string", "placement": "/etc/app/config.json", "priority": 0.95},
            {"type": "api_token", "placement": "/opt/service/.env", "priority": 0.9},
            {"type": "ssl_certificate", "placement": "/etc/ssl/private/", "priority": 0.8},
        ],
        "scada": [
            {"type": "modbus_register_map", "placement": "/opt/scada/registers.conf", "priority": 0.95},
            {"type": "plc_engineering_password", "placement": "/opt/scada/plc.cfg", "priority": 0.9},
        ],
        "atc": [
            {"type": "adsb_transponder_code", "placement": "/opt/adsb/transponders.db", "priority": 0.95},
            {"type": "acars_message", "placement": "/opt/acars/templates/", "priority": 0.85},
        ],
        "router": [
            {"type": "snmp_community_string", "placement": "/etc/snmp/snmpd.conf", "priority": 0.9},
            {"type": "bgp_route_map", "placement": "/etc/quagga/bgpd.conf", "priority": 0.85},
        ],
    }

    def select(self, node: NetworkNode, n: int = 1) -> List[Dict[str, Any]]:
        """Return best canary deployments for this node."""
        options = self.ROLE_TO_CANARY.get(node.role, self.ROLE_TO_CANARY["workstation"])
        sorted_options = sorted(options, key=lambda x: -x["priority"])
        return sorted_options[:n]


# ---------------------------------------------------------------------------
# Deployment record
# ---------------------------------------------------------------------------

@dataclass
class CanaryDeployment:
    deployment_id: str
    node_id: str
    ip: str
    canary_type: str
    placement_path: str
    predicted_score: float
    step: int
    deployed_at: float = field(default_factory=time.time)
    triggered: bool = False
    triggered_at: Optional[float] = None
    attacker_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deployment_id": self.deployment_id,
            "node_id": self.node_id,
            "ip": self.ip,
            "canary_type": self.canary_type,
            "placement_path": self.placement_path,
            "predicted_score": self.predicted_score,
            "step": self.step,
            "deployed_at": self.deployed_at,
            "triggered": self.triggered,
        }


# ---------------------------------------------------------------------------
# Main Predictive Canary Engine
# ---------------------------------------------------------------------------

class PredictiveCanaryEngine:
    """
    SHADOW-ML Predictive Canary Engine v10.0

    Proactively places canary tokens where attackers will move next.
    Integrates with the lateral movement graph, attack path predictor,
    and canary token module for automated deployment.
    """

    VERSION = "10.0.0"

    def __init__(self, horizon: int = 3, auto_deploy: bool = True):
        self.graph = LateralMovementGraph()
        self.predictor = AttackPathPredictor(self.graph, horizon=horizon)
        self.selector = CanarySelector()
        self._auto_deploy = auto_deploy
        self._deployments: List[CanaryDeployment] = []
        self._stats: Dict[str, Any] = {
            "predictions_made": 0,
            "canaries_deployed": 0,
            "canaries_triggered": 0,
            "true_predictions": 0,  # canary triggered = attacker moved as predicted
        }
        logger.info("PredictiveCanaryEngine v%s initialised (horizon=%d)", self.VERSION, horizon)

    def register_host(
        self,
        node_id: str,
        ip: str,
        role: str,
        sensitivity: float = 0.5,
        services: Optional[List[str]] = None,
    ) -> NetworkNode:
        node = NetworkNode(
            node_id=node_id, ip=ip, role=role,
            sensitivity=sensitivity, services=services or [],
        )
        self.graph.add_node(node)
        return node

    def register_connection(self, from_id: str, to_id: str, weight: float = 0.1) -> None:
        """Register that from_id has network access to to_id."""
        self.graph.add_edge(from_id, to_id, weight)

    def observe_lateral_movement(self, from_id: str, to_id: str) -> None:
        """Record observed lateral movement (updates transition probabilities)."""
        self.graph.observe_lateral(from_id, to_id)
        node = self.graph._nodes.get(to_id)
        if node:
            node.compromised = True
            node.last_seen_lateral = time.time()

    def predict_and_deploy(
        self,
        compromised_nodes: Set[str],
        canaries_per_node: int = 2,
    ) -> List[CanaryDeployment]:
        """
        Predict next attack steps and deploy canaries on predicted targets.
        Returns list of CanaryDeployment records.
        """
        self._stats["predictions_made"] += 1
        predictions = self.predictor.predict_path(compromised_nodes)

        new_deployments = []
        seen_nodes = set()

        for pred in predictions:
            node_id = pred["node_id"]
            if node_id in seen_nodes:
                continue
            seen_nodes.add(node_id)

            node = self.graph._nodes.get(node_id)
            if not node:
                continue

            canary_options = self.selector.select(node, n=canaries_per_node)
            for option in canary_options:
                import hashlib
                dep_id = hashlib.sha256(
                    f"{node_id}_{option['type']}_{time.time()}".encode()
                ).hexdigest()[:12]

                deployment = CanaryDeployment(
                    deployment_id=dep_id,
                    node_id=node_id,
                    ip=node.ip,
                    canary_type=option["type"],
                    placement_path=option["placement"],
                    predicted_score=pred["predicted_score"],
                    step=pred["step"],
                )
                self._deployments.append(deployment)
                new_deployments.append(deployment)
                node.canaries_deployed += 1
                self._stats["canaries_deployed"] += 1

                logger.info(
                    "Predictive canary deployed: node=%s type=%s path=%s score=%.3f step=%d",
                    node_id, option["type"], option["placement"],
                    pred["predicted_score"], pred["step"],
                )

        return new_deployments

    def report_trigger(self, deployment_id: str, attacker_ip: str = "") -> Optional[CanaryDeployment]:
        """Called when a canary is triggered. Updates stats and returns deployment."""
        for dep in self._deployments:
            if dep.deployment_id == deployment_id:
                dep.triggered = True
                dep.triggered_at = time.time()
                dep.attacker_ip = attacker_ip
                self._stats["canaries_triggered"] += 1
                self._stats["true_predictions"] += 1
                logger.warning(
                    "PREDICTIVE CANARY TRIGGERED: node=%s type=%s attacker=%s",
                    dep.node_id, dep.canary_type, attacker_ip,
                )
                return dep
        return None

    def get_active_deployments(self) -> List[Dict[str, Any]]:
        return [d.to_dict() for d in self._deployments if not d.triggered]

    def get_stats(self) -> Dict[str, Any]:
        prediction_accuracy = (
            self._stats["true_predictions"] / max(1, self._stats["canaries_triggered"])
        )
        return {
            **self._stats,
            "active_deployments": sum(1 for d in self._deployments if not d.triggered),
            "triggered_deployments": sum(1 for d in self._deployments if d.triggered),
            "registered_nodes": len(self.graph._nodes),
            "prediction_accuracy": round(prediction_accuracy, 4),
        }

    def build_demo_network(self) -> None:
        """Build a representative airport network topology for demonstration."""
        nodes = [
            ("atc-primary",    "10.10.1.1",  "atc",       0.99),
            ("atc-backup",     "10.10.1.2",  "atc",       0.95),
            ("adsb-server",    "10.10.2.1",  "atc",       0.9),
            ("scada-01",       "10.20.1.1",  "scada",     0.95),
            ("scada-02",       "10.20.1.2",  "scada",     0.9),
            ("router-core",    "10.0.0.1",   "router",    0.8),
            ("workstation-01", "192.168.1.5","workstation",0.4),
            ("workstation-02", "192.168.1.6","workstation",0.4),
            ("file-server",    "10.0.10.1",  "server",    0.7),
        ]
        for nid, ip, role, sens in nodes:
            self.register_host(nid, ip, role, sens)

        edges = [
            ("workstation-01", "file-server",    0.7),
            ("workstation-01", "workstation-02", 0.5),
            ("workstation-02", "file-server",    0.6),
            ("file-server",    "router-core",    0.4),
            ("router-core",    "scada-01",       0.3),
            ("router-core",    "atc-primary",    0.3),
            ("scada-01",       "scada-02",       0.8),
            ("atc-primary",    "atc-backup",     0.6),
            ("atc-primary",    "adsb-server",    0.7),
        ]
        for src, dst, w in edges:
            self.register_connection(src, dst, w)
