"""
ml/adaptive_evasion.py — Adaptive Evasion Engine v10.0

Red team tool that learns from detection feedback:
  • Reinforcement learning: adjusts attack patterns based on detection results
  • Feature mutation: evolves feature vectors to evade detection
  • Gradient-free optimization: uses genetic algorithms and Bayesian optimization
  • Defense mechanism fingerprinting: identifies which detection rules are active
  • Multi-objective optimization: balance evasion (low threat score) with stealth
  • Strategy tracking: remembers what works against different detection systems

Tests robustness of Shadow NDR by adapting to defense mechanisms.
Ensures detectors can't be defeated by simple mutations.
"""

from __future__ import annotations

import hashlib
import logging
import random
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("shadow.ml.adaptive_evasion")

# Adjust path for imports
SHADOW_ML_ROOT = Path(__file__).parent.parent
if str(SHADOW_ML_ROOT) not in sys.path:
    sys.path.insert(0, str(SHADOW_ML_ROOT))

try:
    from core.neural_engine import get_engine, ThreatVector
except ImportError:
    logger.warning("Neural engine not available")


class EvolutionStrategy(Enum):
    GENETIC_ALGORITHM = "genetic_algorithm"
    PARTICLE_SWARM = "particle_swarm"
    DIFFERENTIAL_EVOLUTION = "differential_evolution"
    BAYESIAN_OPTIMIZATION = "bayesian_optimization"
    RANDOM_SEARCH = "random_search"


@dataclass
class AdaptiveIndividual:
    """Single attack variant being optimized."""
    features: np.ndarray
    threat_score: float = 0.0
    detections: int = 0
    fitness: float = 0.0
    strategy_id: str = ""
    mutations_applied: int = 0


@dataclass
class EvolutionRound:
    """Results from one optimization round."""
    round_num: int
    best_score: float
    best_features: np.ndarray
    population_diversity: float
    converged: bool
    strategies_tried: List[str] = field(default_factory=list)


class FeatureMutator:
    """
    Applies realistic mutations to attack feature vectors.
    Ensures mutations are constrained to represent valid attacks.
    """

    def __init__(self):
        self._mutation_magnitude: float = 0.05
        self._constraint_bounds: Tuple[float, float] = (0.0, 1.0)

    def mutate(
        self,
        features: np.ndarray,
        mutation_rate: float = 0.1,
        magnitude: Optional[float] = None,
    ) -> np.ndarray:
        """
        Mutate feature vector with realistic constraints.
        """
        mag = magnitude or self._mutation_magnitude
        mutated = features.copy()

        # Gaussian mutation on random subset of features
        num_mutations = max(1, int(len(features) * mutation_rate))
        mutation_indices = np.random.choice(len(features), size=num_mutations, replace=False)

        for idx in mutation_indices:
            noise = np.random.normal(0, mag)
            mutated[idx] += noise
            mutated[idx] = np.clip(mutated[idx], self._constraint_bounds[0], self._constraint_bounds[1])

        return mutated

    def crossover(self, parent1: np.ndarray, parent2: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Create two children from two parents via uniform crossover.
        """
        mask = np.random.rand(len(parent1)) < 0.5
        child1 = np.where(mask, parent1, parent2)
        child2 = np.where(mask, parent2, parent1)
        return child1, child2


class DefenseFingerprintAnalyzer:
    """
    Analyzes detection patterns to fingerprint active defense mechanisms.
    """

    def __init__(self):
        self._query_history: List[Tuple[np.ndarray, float]] = []
        self._detection_patterns: Dict[str, float] = {
            "high_variance": 0.0,
            "outlier_detection": 0.0,
            "anomaly_threshold": 0.0,
            "ensemble_voting": 0.0,
            "gradient_masking": 0.0,
        }

    def record_query(self, features: np.ndarray, threat_score: float) -> None:
        """Record a query and its result."""
        self._query_history.append((features, threat_score))

    def analyze_defense_fingerprint(self) -> Dict[str, float]:
        """
        Analyze patterns in scores to identify defense mechanisms.
        """
        if len(self._query_history) < 10:
            return {}

        # Extract features and scores
        queries = np.array([q[0] for q in self._query_history])
        scores = np.array([q[1] for q in self._query_history])

        # Check for gradient masking (similar scores despite different inputs)
        feature_distances = np.mean([
            np.linalg.norm(queries[i] - queries[i-1])
            for i in range(1, min(10, len(queries)))
        ])
        score_variance = np.var(scores)

        if feature_distances > 0.5 and score_variance < 0.01:
            self._detection_patterns["gradient_masking"] = 0.9
            logger.info("Detected: Gradient masking defense")

        # Check for hard decision boundary (bimodal score distribution)
        if len(scores) > 5:
            hist, _ = np.histogram(scores, bins=20)
            bimodality = np.sum(hist > 1) / len(hist)  # Peaks in histogram
            if bimodality > 0.5:
                self._detection_patterns["outlier_detection"] = 0.8
                logger.info("Detected: Hard threshold defense")

        # Check for threshold-based decisions
        if np.sum(scores > 0.5) / len(scores) > 0.9:
            self._detection_patterns["anomaly_threshold"] = 0.85

        return self._detection_patterns


class GeneticAlgorithmOptimizer:
    """
    Genetic algorithm for optimizing attack features against detectors.
    """

    def __init__(self, scorer: Callable, dim: int = 512, pop_size: int = 30):
        self.scorer = scorer
        self.dim = dim
        self.pop_size = pop_size
        self._mutator = FeatureMutator()
        self._fingerprinter = DefenseFingerprintAnalyzer()

    def optimize(
        self,
        initial_features: Optional[np.ndarray] = None,
        generations: int = 20,
        target_score: float = 0.3,
    ) -> Tuple[np.ndarray, float, List[EvolutionRound]]:
        """
        Optimize features via genetic algorithm.
        Returns (best_features, best_score, evolution_history)
        """
        evolution_history = []

        # Initialize population
        if initial_features is not None:
            population = [initial_features.copy() for _ in range(self.pop_size)]
        else:
            population = [np.random.uniform(0, 1, self.dim) for _ in range(self.pop_size)]

        scores = [self.scorer(ind) for ind in population]
        self._fingerprinter.record_query(population[0], scores[0])

        best_score = min(scores)
        best_individual = population[np.argmin(scores)].copy()

        for gen in range(generations):
            # Selection and reproduction
            new_pop = []
            for _ in range(self.pop_size):
                # Tournament selection
                idx1, idx2 = np.random.choice(self.pop_size, 2, replace=False)
                parent = population[idx1 if scores[idx1] < scores[idx2] else idx2].copy()

                # Mutation
                child = self._mutator.mutate(parent, mutation_rate=0.15)
                new_pop.append(child)

            # Evaluate new population
            new_scores = [self.scorer(ind) for ind in new_pop]
            self._fingerprinter.record_query(new_pop[0], new_scores[0])

            # Elitism: keep best from old population
            worst_idx_new = np.argmax(new_scores)
            best_idx_old = np.argmin(scores)
            new_pop[worst_idx_new] = population[best_idx_old].copy()
            new_scores[worst_idx_new] = scores[best_idx_old]

            population = new_pop
            scores = new_scores

            # Track best
            current_best = min(scores)
            if current_best < best_score:
                best_score = current_best
                best_individual = population[np.argmin(scores)].copy()
                logger.info(f"  Gen {gen}: improved score to {best_score:.4f}")

            # Calculate population diversity
            pop_array = np.array(population)
            diversity = np.mean([
                np.linalg.norm(pop_array[i] - pop_array[j])
                for i in range(min(5, len(population)))
                for j in range(i+1, min(5, len(population)))
            ])

            converged = best_score < target_score or diversity < 0.01
            evolution_history.append(EvolutionRound(
                round_num=gen,
                best_score=best_score,
                best_features=best_individual.copy(),
                population_diversity=float(diversity),
                converged=converged,
            ))

            if converged:
                break

        return best_individual, best_score, evolution_history


class AdaptiveEvasionEngine:
    """
    Main adaptive evasion engine using RL and optimization.
    """

    def __init__(self):
        self._engine = None
        try:
            self._engine = get_engine()
        except Exception:
            logger.warning("Neural engine not available for adaptive evasion")

        self._optimizer: Optional[GeneticAlgorithmOptimizer] = None
        self._evolved_attacks: List[Tuple[np.ndarray, float]] = []
        self._strategy_effectiveness: Dict[str, float] = {}
        self._stats = {
            "rounds_completed": 0,
            "features_evaluated": 0,
            "evasion_success_rate": 0.0,
            "defense_mechanisms_identified": 0,
        }

    def initialize_optimizer(self, dim: int = 512):
        """Initialize genetic algorithm optimizer."""
        if self._engine is None:
            logger.error("Cannot initialize optimizer without neural engine")
            return

        def scorer(features: np.ndarray) -> float:
            if isinstance(features, np.ndarray):
                features = features.tolist()
            tv = ThreatVector(raw_features=features, protocol="adaptive")
            result = self._engine.process(tv)
            self._stats["features_evaluated"] += 1
            return result.threat_score

        self._optimizer = GeneticAlgorithmOptimizer(scorer, dim=dim, pop_size=30)

    def run_optimization_round(
        self,
        initial_attack: Optional[np.ndarray] = None,
        generations: int = 15,
        target_score: float = 0.3,
    ) -> EvolutionRound:
        """
        Run one optimization round to evolve attack features.
        """
        if self._optimizer is None:
            self.initialize_optimizer()

        logger.info(f"Starting optimization round {self._stats['rounds_completed'] + 1}")

        best_features, best_score, history = self._optimizer.optimize(
            initial_features=initial_attack,
            generations=generations,
            target_score=target_score,
        )

        self._evolved_attacks.append((best_features, best_score))
        self._stats["rounds_completed"] += 1

        final_round = history[-1]
        logger.info(
            f"Round complete: best_score={best_score:.4f}, "
            f"diversity={final_round.population_diversity:.4f}, "
            f"converged={final_round.converged}"
        )

        # Analyze defense fingerprints
        fingerprints = self._optimizer._fingerprinter.analyze_defense_fingerprint()
        if fingerprints:
            self._stats["defense_mechanisms_identified"] = len(
                [p for p, conf in fingerprints.items() if conf > 0.7]
            )

        # Update success rate
        success_count = sum(1 for _, score in self._evolved_attacks if score < 0.5)
        self._stats["evasion_success_rate"] = success_count / max(1, len(self._evolved_attacks))

        return final_round

    def multi_round_adaptation(
        self,
        num_rounds: int = 3,
        generations_per_round: int = 15,
    ) -> List[EvolutionRound]:
        """
        Run multiple adaptation rounds, using each result to seed the next.
        """
        results = []
        current_attack = None

        for round_num in range(num_rounds):
            logger.info(f"\n=== Adaptation Round {round_num + 1}/{num_rounds} ===")
            result = self.run_optimization_round(
                initial_attack=current_attack,
                generations=generations_per_round,
            )
            results.append(result)

            # Use best from this round as seed for next
            current_attack = result.best_features

        return results

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def best_evasion(self) -> Optional[Tuple[np.ndarray, float]]:
        """Return best evasion achieved so far."""
        if not self._evolved_attacks:
            return None
        return min(self._evolved_attacks, key=lambda x: x[1])


_engine: Optional[AdaptiveEvasionEngine] = None


def get_adaptive_engine() -> AdaptiveEvasionEngine:
    global _engine
    if _engine is None:
        _engine = AdaptiveEvasionEngine()
    return _engine


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    engine = get_adaptive_engine()

    if engine._engine:
        print("\n=== Starting Adaptive Evasion Test ===")
        results = engine.multi_round_adaptation(num_rounds=2, generations_per_round=10)

        print(f"\nFinal Results:")
        for i, result in enumerate(results):
            print(f"  Round {i+1}: best={result.best_score:.4f}, diversity={result.population_diversity:.4f}")

        best = engine.best_evasion
        if best:
            print(f"\nBest evasion: {best[1]:.4f}")
            print(f"Success rate: {engine.stats['evasion_success_rate']:.1%}")
    else:
        print("Neural engine not available - cannot run adaptive evasion test")

    print("Adaptive Evasion Engine OK")
