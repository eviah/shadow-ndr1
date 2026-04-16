#!/usr/bin/env python3
"""
SHADOW-ML BREACH SIMULATOR v6.1 - FAST EVOLUTIONARY ATTACKS
"""

import sys
import time
import random
import numpy as np
from pathlib import Path

SHADOW_ML_ROOT = Path("c:/Users/liorh/shadow-ndr/shadow-ml")
sys.path.insert(0, str(SHADOW_ML_ROOT))

from core.neural_engine import get_engine, ThreatVector

def main():
    print("\n" + "="*80)
    print(" SHADOW-ML BREACH SIMULATOR v6.1 - FAST ATTACKS")
    print("="*80)
    
    engine = get_engine()
    print(f"Target: {engine.VERSION}")
    
    dim = 512
    
    # Create malicious payload
    malicious = np.zeros(dim)
    for i in range(0, dim, 10):
        malicious[i] = 0.95
        if i+5 < dim:
            malicious[i+5] = 0.85
    malicious += np.random.normal(0, 0.03, dim)
    malicious = np.clip(malicious, 0, 1)
    
    def predict(features):
        if isinstance(features, np.ndarray):
            features = features.tolist()
        tv = ThreatVector(raw_features=features, protocol="adsb")
        out = engine.process(tv)
        return out.threat_score
    
    baseline = predict(malicious)
    print(f"\n🎯 Baseline: {baseline:.4f}")
    
    # Fast Genetic Algorithm
    print("\n1. Fast Genetic Algorithm...")
    start = time.time()
    
    pop_size = 30
    generations = 25
    sigma = 0.08
    
    # Initialize population
    pop = [malicious.copy() for _ in range(pop_size)]
    scores = [predict(ind) for ind in pop]
    
    best_score = min(scores)
    best_individual = pop[np.argmin(scores)].copy()
    
    for gen in range(generations):
        new_pop = []
        for _ in range(pop_size):
            # Tournament selection
            idx1, idx2 = random.sample(range(pop_size), 2)
            parent = pop[idx1 if scores[idx1] < scores[idx2] else idx2].copy()
            
            # Mutation
            mutation = np.random.normal(0, sigma * (1 - gen/generations), dim)
            child = np.clip(parent + mutation, 0, 1)
            new_pop.append(child)
        
        # Evaluate
        new_scores = [predict(ind) for ind in new_pop]
        
        # Elitism
        best_idx = np.argmin(scores)
        worst_idx = np.argmax(new_scores)
        new_pop[worst_idx] = pop[best_idx].copy()
        new_scores[worst_idx] = scores[best_idx]
        
        pop = new_pop
        scores = new_scores
        
        current_best = min(scores)
        if current_best < best_score:
            best_score = current_best
            best_individual = pop[np.argmin(scores)].copy()
            print(f"   Gen {gen}: best={best_score:.4f}")
        
        if best_score < 0.3:
            break
    
    elapsed = (time.time() - start) * 1000
    print(f"   ✓ Final: {best_score:.4f} (drop: {baseline-best_score:.4f}) in {elapsed:.0f}ms")
    
    # Simple Random Search (baseline)
    print("\n2. Random Search (1000 samples)...")
    start = time.time()
    
    best_random_score = baseline
    for _ in range(1000):
        noise = np.random.normal(0, 0.1, dim)
        candidate = np.clip(malicious + noise, 0, 1)
        score = predict(candidate)
        if score < best_random_score:
            best_random_score = score
            if best_random_score < 0.35:
                break
    
    elapsed = (time.time() - start) * 1000
    print(f"   ✓ Best random: {best_random_score:.4f} (drop: {baseline-best_random_score:.4f}) in {elapsed:.0f}ms")
    
    # SUMMARY
    print("\n" + "="*80)
    print(" FINAL VERDICT")
    print("="*80)
    print(f"Original score: {baseline:.4f}")
    print(f"Best evasion score: {best_score:.4f}")
    print(f"Score reduction: {baseline - best_score:.4f}")
    
    if best_score < 0.5:
        print(f"\n⚠️  VULNERABLE! Evasion successful (score < 0.5)")
        if best_score < 0.35:
            print("   → CRITICAL: Engine is highly vulnerable to evolutionary attacks")
        else:
            print("   → Engine can be bypassed with sufficient optimization")
    else:
        print(f"\n✅ ROBUST! No successful evasion")
    
    # Recommendation
    if best_score < 0.5:
        print("\n🔧 RECOMMENDATIONS:")
        print("   1. Implement adversarial training with evolutionary examples")
        print("   2. Add input denoising autoencoder")
        print("   3. Increase detection threshold or add ensemble voting")
        print("   4. Deploy canary tokens that detect unusual optimization patterns")
    
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
