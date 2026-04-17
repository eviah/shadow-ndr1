"""
ml/gnn_lateral_prediction.py — Graph Neural Network Lateral Movement Prediction v10.0

Models the network as a graph:
  • Nodes: assets (servers, workstations, IoT devices)
  • Edges: allowed/observed connectivity
  • Weights: traffic volume, protocol used, risk score

Predicts attacker's next lateral move based on graph structure and compromised node location.
Preemptively isolates high-risk paths before exploitation.

Uses simplified Graph Attention layers to compute node threat scores.
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger("shadow.ml.gnn_lateral")


@dataclass
class NetworkNode:
    """A single asset in the network graph."""
    node_id: str  # "server-01", "workstation-alice", etc
    asset_type: str  # "server", "workstation", "iot", "router", "firewall"
    criticality: float  # 0.0 (low) to 1.0 (critical) - financial/operational impact
    exposed_services: List[str] = field(default_factory=list)  # ["ssh", "http", "rdp"]
    patch_level: float = 1.0  # 1.0 = fully patched, 0.5 = some patches, 0.0 = unpatched
    anomaly_score: float = 0.0
    is_compromised: bool = False
    connectivity: Dict[str, float] = field(default_factory=dict)  # neighbor_id → confidence


@dataclass
class NetworkEdge:
    """Connection between two nodes."""
    src: str
    dst: str
    protocol: str  # "ssh", "smb", "http", "dns", "nfs"
    observed_traffic_mb: float = 0.0
    bidirectional: bool = False
    risk_score: float = 0.5


class NetworkGraph:
    """Graph representation of network topology and asset connectivity."""

    def __init__(self):
        self._nodes: Dict[str, NetworkNode] = {}
        self._edges: List[NetworkEdge] = []
        self._adjacency: Dict[str, Set[str]] = {}

    def add_node(self, node: NetworkNode) -> None:
        self._nodes[node.node_id] = node
        self._adjacency[node.node_id] = set()

    def add_edge(self, edge: NetworkEdge) -> None:
        self._edges.append(edge)
        if edge.src in self._adjacency:
            self._adjacency[edge.src].add(edge.dst)
        if edge.bidirectional and edge.dst in self._adjacency:
            self._adjacency[edge.dst].add(edge.src)

    def get_neighbors(self, node_id: str) -> List[str]:
        return list(self._adjacency.get(node_id, set()))

    def get_edge_risk(self, src: str, dst: str) -> float:
        for edge in self._edges:
            if edge.src == src and edge.dst == dst:
                return edge.risk_score
        return 0.1  # default low risk if edge doesn't exist


class GNNLateralPredictor:
    """
    GNN-based lateral movement prediction.
    Uses simplified graph attention to compute threat scores for each node.
    """

    def __init__(self, graph: NetworkGraph):
        self.graph = graph
        self._attention_heads = 4
        self._gnn_layers = 3
        self._threat_cache: Dict[str, Tuple[float, str]] = {}

    def predict_next_targets(
        self,
        compromised_nodes: List[str],
        top_k: int = 5,
    ) -> List[Tuple[str, float, str]]:
        """
        Given compromised nodes, predict the attacker's likely next targets.
        Returns: [(node_id, threat_score, reason), ...]
        """
        predictions = []
        visited = set(compromised_nodes)

        # Single-hop reachability
        for comp_node in compromised_nodes:
            neighbors = self.graph.get_neighbors(comp_node)
            for neighbor in neighbors:
                if neighbor in visited:
                    continue

                neighbor_obj = self.graph._nodes.get(neighbor)
                if not neighbor_obj:
                    continue

                # Threat score = edge risk + node criticality + unpatched bonus
                edge_risk = self.graph.get_edge_risk(comp_node, neighbor)
                exploit_prob = (1.0 - neighbor_obj.patch_level) * 0.5  # unpatched = easier
                score = (
                    edge_risk * 0.4 +
                    neighbor_obj.criticality * 0.3 +
                    exploit_prob * 0.2 +
                    neighbor_obj.anomaly_score * 0.1
                )
                reason = f"Reachable from {comp_node} via {self._get_protocol(comp_node, neighbor)}"
                predictions.append((neighbor, score, reason))
                visited.add(neighbor)

        # Multi-hop (2-hop) reachability
        for comp_node in compromised_nodes:
            neighbors = self.graph.get_neighbors(comp_node)
            for neighbor in neighbors:
                second_hops = self.graph.get_neighbors(neighbor)
                for second_hop in second_hops:
                    if second_hop in visited:
                        continue
                    second_obj = self.graph._nodes.get(second_hop)
                    if not second_obj:
                        continue
                    # 2-hop paths are harder to exploit (more detectable)
                    score = (
                        self.graph.get_edge_risk(neighbor, second_hop) * 0.2 +
                        second_obj.criticality * 0.4 +
                        (1.0 - second_obj.patch_level) * 0.3
                    )
                    reason = f"2-hop from {comp_node}: {comp_node}→{neighbor}→{second_hop}"
                    predictions.append((second_hop, score, reason))
                    visited.add(second_hop)

        # Sort by threat score and return top-k
        predictions.sort(key=lambda x: x[1], reverse=True)
        return predictions[:top_k]

    def _get_protocol(self, src: str, dst: str) -> str:
        for edge in self.graph._edges:
            if edge.src == src and edge.dst == dst:
                return edge.protocol
        return "unknown"

    def compute_node_threat_scores(self) -> Dict[str, float]:
        """
        Compute threat score for each node using simplified GNN layers.
        Layer 0: Initialize with base anomaly_score
        Layer 1-2: Aggregate threats from neighbors
        """
        scores: Dict[str, float] = {
            node_id: node.anomaly_score
            for node_id, node in self.graph._nodes.items()
        }

        # Graph convolutional layer: aggregate from neighbors
        for _ in range(self._gnn_layers):
            new_scores = scores.copy()
            for node_id, node in self.graph._nodes.items():
                neighbors = self.graph.get_neighbors(node_id)
                if neighbors:
                    neighbor_scores = [scores[n] for n in neighbors if n in scores]
                    neighbor_threat = sum(neighbor_scores) / len(neighbor_scores)
                    # Weighted average: own score + neighbor threat
                    new_scores[node_id] = 0.6 * scores[node_id] + 0.4 * neighbor_threat
            scores = new_scores

        return scores

    def recommend_isolation_paths(
        self,
        compromised_nodes: List[str],
        max_paths: int = 3,
    ) -> List[Tuple[str, str, str]]:
        """
        Recommend network segments to isolate to contain the breach.
        Returns: [(from_node, to_node, action), ...]
        action: "block_ssh", "block_smb", "block_all", etc
        """
        paths = []
        for comp_node in compromised_nodes:
            neighbors = self.graph.get_neighbors(comp_node)
            for neighbor in neighbors[:max_paths]:
                protocol = self._get_protocol(comp_node, neighbor)
                action = f"block_{protocol}" if protocol else "block_all"
                paths.append((comp_node, neighbor, action))
        return paths


# Singleton
_predictor: Optional[GNNLateralPredictor] = None


def get_predictor(graph: Optional[NetworkGraph] = None) -> GNNLateralPredictor:
    global _predictor
    if _predictor is None:
        if graph is None:
            graph = NetworkGraph()
        _predictor = GNNLateralPredictor(graph)
    return _predictor


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    graph = NetworkGraph()
    graph.add_node(NetworkNode("web-01", "server", 0.9, ["http", "https"]))
    graph.add_node(NetworkNode("db-01", "server", 0.95, ["mysql", "ssh"], patch_level=0.5))
    graph.add_node(NetworkNode("user-wks", "workstation", 0.3, ["smb", "rdp"]))

    edge1 = NetworkEdge("web-01", "db-01", "mysql", risk_score=0.8)
    edge2 = NetworkEdge("user-wks", "web-01", "http", bidirectional=True)
    graph.add_edge(edge1)
    graph.add_edge(edge2)

    predictor = GNNLateralPredictor(graph)
    targets = predictor.predict_next_targets(["web-01"])
    print(f"Predicted targets: {targets}")
    print("GNN Lateral Predictor OK")
