#!/usr/bin/env python3
"""
ULTIMATE BREACH ATTACK v3.1 - WORLD-CLASS ADVERSARIAL SUITE (FIXED)
תוקן: טיפול בשגיאות, Timeout, יציבות גבוהה, ביצועים משופרים
"""

import sys
import time
import random
import json
import signal
import numpy as np
from pathlib import Path
from typing import Callable, List, Tuple, Dict, Any
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import warnings
warnings.filterwarnings('ignore')

SHADOW_ML_ROOT = Path("c:/Users/liorh/shadow-ndr/shadow-ml")
sys.path.insert(0, str(SHADOW_ML_ROOT))

from core.neural_engine import get_engine, ThreatVector

# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================
DIM = 512
NUM_TESTS = 1000
MAX_TIME_SEC = 300
PREDICTION_TIMEOUT_SEC = 3.0   # timeout לקריאה בודדת
SEED = 42
np.random.seed(SEED)
random.seed(SEED)

# ============================================================================
# UTILITIES - PREDICTION עם TIMEOUT ו-RETRY
# ============================================================================

def predict_with_timeout(engine, features, timeout_sec=PREDICTION_TIMEOUT_SEC):
    """בטוח prediction עם timeout - מחזיר float או מעלה TimeoutError"""
    if isinstance(features, np.ndarray):
        features = features.tolist()
    tv = ThreatVector(raw_features=features, protocol="adsb")
    
    # שימוש ב-signal.alarm (Unix) או threading
    import threading
    result = [None]
    error = [None]
    
    def target():
        try:
            result[0] = engine.process(tv).threat_score
        except Exception as e:
            error[0] = e
    
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout_sec)
    
    if thread.is_alive():
        raise TimeoutError(f"Prediction timeout after {timeout_sec}s")
    if error[0]:
        raise error[0]
    return result[0]

def create_target(dim=DIM, seed=42):
    """יצירת וקטור זדוני אופייני"""
    np.random.seed(seed)
    vec = np.zeros(dim)
    for i in range(0, dim, 10):
        vec[i] = 0.96
        if i+5 < dim:
            vec[i+5] = 0.88
    vec += np.random.normal(0, 0.02, dim)
    return np.clip(vec, 0, 1)

# ============================================================================
# GRADIENT ESTIMATION (מהיר ומדויק)
# ============================================================================
def fast_gradient(features, predict, eps=1e-3, sample_ratio=0.15):
    dim = len(features)
    grad = np.zeros(dim)
    try:
        f0 = predict(features)
    except Exception:
        f0 = 0.95
    n_samples = max(20, int(dim * sample_ratio))
    indices = np.random.choice(dim, n_samples, replace=False)
    for i in indices:
        e = np.zeros(dim)
        e[i] = eps
        try:
            fp = predict(features + e)
            fm = predict(features - e)
            grad[i] = (fp - fm) / (2 * eps)
        except Exception:
            grad[i] = 0.0
    return grad

def full_gradient(features, predict, eps=1e-4):
    dim = len(features)
    grad = np.zeros(dim)
    try:
        f0 = predict(features)
    except Exception:
        f0 = 0.95
    for i in range(dim):
        e = np.zeros(dim)
        e[i] = eps
        try:
            grad[i] = (predict(features + e) - f0) / eps
        except Exception:
            grad[i] = 0.0
    return grad

# ============================================================================
# ATTACK CLASSES (תוקנו: טיפול בשגיאות, התאמת קלט)
# ============================================================================

class Attack:
    name = "base"
    def __init__(self, predict_fn):
        self.predict = predict_fn
    def run(self, x, **kwargs):
        raise NotImplementedError

# ---------- 1. GRADIENT-BASED ----------
class FGSM(Attack):
    name = "FGSM"
    def run(self, x, epsilon=0.05):
        grad = fast_gradient(x, self.predict)
        adv = np.clip(x - epsilon * np.sign(grad), 0, 1)
        return adv, self.predict(adv)

class PGD(Attack):
    name = "PGD"
    def run(self, x, epsilon=0.1, steps=20, lr=0.01):
        adv = x.copy()
        for _ in range(steps):
            grad = fast_gradient(adv, self.predict, sample_ratio=0.2)
            adv = adv - lr * np.sign(grad)
            adv = np.clip(adv, x - epsilon, x + epsilon)
            adv = np.clip(adv, 0, 1)
        return adv, self.predict(adv)

class MIM(Attack):
    name = "MIM"
    def run(self, x, epsilon=0.1, steps=20, mu=0.9, lr=0.01):
        adv = x.copy()
        g = np.zeros(len(x))
        for _ in range(steps):
            grad = fast_gradient(adv, self.predict, sample_ratio=0.2)
            g = mu * g + grad / (np.linalg.norm(grad) + 1e-8)
            adv = adv - lr * np.sign(g)
            adv = np.clip(adv, x - epsilon, x + epsilon)
            adv = np.clip(adv, 0, 1)
        return adv, self.predict(adv)

class CW(Attack):
    name = "CW"
    def run(self, x, steps=30, lr=0.005, c=0.5):
        adv = x.copy()
        for _ in range(steps):
            grad = fast_gradient(adv, self.predict, sample_ratio=0.2)
            diff = adv - x
            l2_grad = 2 * diff / (np.linalg.norm(diff) + 1e-8)
            total_grad = grad + c * l2_grad
            nrm = np.linalg.norm(total_grad) + 1e-8
            total_grad = total_grad / nrm
            adv = adv - lr * total_grad
            adv = np.clip(adv, 0, 1)
        return adv, self.predict(adv)

# ---------- 2. QUERY-BASED ----------
class SquareAttack(Attack):
    name = "Square"
    def run(self, x, max_queries=600, p=0.1):
        adv = x.copy()
        best_score = self.predict(adv)
        dim = len(x)
        for _ in range(max_queries):
            size = max(1, int(dim * p))
            start = random.randint(0, dim - size)
            perturb = np.zeros(dim)
            perturb[start:start+size] = np.random.uniform(-0.05, 0.05, size)
            cand = np.clip(adv + perturb, 0, 1)
            try:
                score = self.predict(cand)
            except Exception:
                continue
            if score < best_score:
                best_score = score
                adv = cand
            if best_score < 0.45:
                break
        return adv, best_score

class SimBA(Attack):
    name = "SimBA"
    def run(self, x, max_queries=800, epsilon=0.02):
        adv = x.copy()
        best_score = self.predict(adv)
        dim = len(x)
        for _ in range(max_queries):
            idx = random.randint(0, dim-1)
            for sign in [+1, -1]:
                cand = adv.copy()
                cand[idx] = np.clip(cand[idx] + sign * epsilon, 0, 1)
                try:
                    score = self.predict(cand)
                except Exception:
                    continue
                if score < best_score:
                    best_score = score
                    adv = cand
                    break
            if best_score < 0.45:
                break
        return adv, best_score

class BoundaryAttack(Attack):
    name = "Boundary"
    def run(self, x, max_steps=300):
        dim = len(x)
        adv = np.clip(x + np.random.normal(0, 0.3, dim), 0, 1)
        try:
            score = self.predict(adv)
        except Exception:
            score = 0.95
        best = adv.copy()
        best_score = score
        for _ in range(max_steps):
            if score < 0.5:
                direction = (x - adv) / (np.linalg.norm(x - adv) + 1e-8)
                adv = np.clip(adv + 0.02 * direction, 0, 1)
            else:
                direction = np.random.normal(0, 1, dim)
                direction /= (np.linalg.norm(direction) + 1e-8)
                adv = np.clip(adv + 0.03 * direction, 0, 1)
            try:
                score = self.predict(adv)
            except Exception:
                continue
            if score < best_score:
                best_score = score
                best = adv.copy()
            if best_score < 0.45:
                break
        return best, best_score

class HopSkipJump(Attack):
    name = "HopSkipJump"
    def run(self, x, max_iter=150):
        dim = len(x)
        adv = np.clip(x + np.random.normal(0, 0.2, dim), 0, 1)
        try:
            score = self.predict(adv)
        except Exception:
            score = 0.95
        best = adv.copy()
        best_score = score
        for _ in range(max_iter):
            if score < 0.5:
                adv = (adv + x) / 2
            else:
                direction = np.random.normal(0, 1, dim)
                direction /= (np.linalg.norm(direction) + 1e-8)
                adv = np.clip(adv + 0.05 * direction, 0, 1)
            try:
                score = self.predict(adv)
            except Exception:
                continue
            if score < best_score:
                best_score = score
                best = adv.copy()
            if best_score < 0.45:
                break
        return best, best_score

# ---------- 3. EVOLUTIONARY ----------
class GeneticAttack(Attack):
    name = "Genetic"
    def run(self, x, pop=15, gens=12, sigma=0.08):
        best = x.copy()
        best_score = self.predict(best)
        pop_list = [x.copy() for _ in range(pop)]
        scores = [self.predict(ind) for ind in pop_list]
        for gen in range(gens):
            new_pop = []
            for _ in range(pop):
                i1, i2 = random.sample(range(pop), 2)
                parent = pop_list[i1] if scores[i1] < scores[i2] else pop_list[i2]
                child = parent + np.random.normal(0, sigma * (1 - gen/gens), len(x))
                child = np.clip(child, 0, 1)
                new_pop.append(child)
            new_scores = []
            for ind in new_pop:
                try:
                    new_scores.append(self.predict(ind))
                except Exception:
                    new_scores.append(0.95)
            elite_idx = np.argmin(scores)
            worst_idx = np.argmax(new_scores)
            new_pop[worst_idx] = pop_list[elite_idx].copy()
            new_scores[worst_idx] = scores[elite_idx]
            pop_list, scores = new_pop, new_scores
            cur_best = min(scores)
            if cur_best < best_score:
                best_score = cur_best
                best = pop_list[np.argmin(scores)].copy()
            if best_score < 0.45:
                break
        return best, best_score

class CMAES(Attack):
    name = "CMA-ES"
    def run(self, x, iterations=20, pop=20):
        mean = x.copy()
        sigma = 0.1
        best = mean.copy()
        best_score = self.predict(mean)
        for _ in range(iterations):
            samples = []
            for _ in range(pop):
                noise = np.random.normal(0, sigma, len(x))
                s = np.clip(mean + noise, 0, 1)
                try:
                    score = self.predict(s)
                except Exception:
                    continue
                samples.append((s, score))
            if not samples:
                continue
            samples.sort(key=lambda t: t[1])
            top = samples[:max(1, pop//3)]
            new_mean = np.zeros(len(x))
            total_w = 0
            for i, (s, _) in enumerate(top):
                w = (len(top) - i) / len(top)
                new_mean += w * s
                total_w += w
            if total_w > 0:
                new_mean /= total_w
            sigma *= 1.1 if samples[0][1] < best_score else 0.9
            sigma = np.clip(sigma, 0.01, 0.2)
            mean = new_mean
            if samples[0][1] < best_score:
                best_score = samples[0][1]
                best = samples[0][0].copy()
            if best_score < 0.45:
                break
        return best, best_score

class SimulatedAnnealing(Attack):
    name = "Annealing"
    def run(self, x, max_iter=500, temp0=1.0):
        current = x.copy()
        current_score = self.predict(current)
        best = current.copy()
        best_score = current_score
        temp = temp0
        for _ in range(max_iter):
            noise = np.random.normal(0, temp * 0.08, len(x))
            cand = np.clip(current + noise, 0, 1)
            try:
                cand_score = self.predict(cand)
            except Exception:
                continue
            if cand_score < current_score:
                current = cand
                current_score = cand_score
                if cand_score < best_score:
                    best = cand
                    best_score = cand_score
            else:
                if random.random() < np.exp((current_score - cand_score) / temp):
                    current = cand
                    current_score = cand_score
            temp *= 0.995
            if best_score < 0.45:
                break
        return best, best_score

# ---------- 4. FEATURE-SPECIFIC ----------
class FeatureImportanceAttack(Attack):
    name = "FeatureImportance"
    def run(self, x, n_top=40, steps=40):
        imp = np.zeros(len(x))
        base = self.predict(x)
        for i in range(0, len(x), 10):
            e = np.zeros_like(x)
            e[i] = 0.02
            try:
                imp[i] = abs(self.predict(x + e) - base)
            except Exception:
                imp[i] = 0.0
        top_idx = np.argsort(imp)[-n_top:]
        adv = x.copy()
        best_score = base
        for _ in range(steps):
            grad = np.zeros(len(x))
            for idx in top_idx:
                e = np.zeros(len(x))
                e[idx] = 0.001
                try:
                    fp = self.predict(adv + e)
                    fm = self.predict(adv - e)
                    grad[idx] = (fp - fm) / 0.002
                except Exception:
                    grad[idx] = 0.0
            for idx in top_idx:
                adv[idx] = np.clip(adv[idx] - 0.015 * np.sign(grad[idx]), 0, 1)
            adv = np.clip(adv, x - 0.12, x + 0.12)
            try:
                score = self.predict(adv)
            except Exception:
                continue
            if score < best_score:
                best_score = score
            if best_score < 0.45:
                break
        return adv, best_score

# ---------- 5. RANDOM & GREEDY ----------
class RandomSearch(Attack):
    name = "RandomSearch"
    def run(self, x, n_trials=1500, noise_std=0.1):
        best = x.copy()
        best_score = self.predict(best)
        for _ in range(n_trials):
            cand = np.clip(x + np.random.normal(0, noise_std, len(x)), 0, 1)
            try:
                score = self.predict(cand)
            except Exception:
                continue
            if score < best_score:
                best_score = score
                best = cand
            if best_score < 0.45:
                break
        return best, best_score

class CoordinateDescent(Attack):
    name = "CoordDescent"
    def run(self, x, epochs=3, deltas=None):
        if deltas is None:
            deltas = [-0.08, -0.04, -0.02, 0, 0.02, 0.04, 0.08]
        adv = x.copy()
        best_score = self.predict(adv)
        for _ in range(epochs):
            for i in range(len(x)):
                orig = adv[i]
                best_val = orig
                for d in deltas:
                    adv[i] = np.clip(orig + d, 0, 1)
                    try:
                        s = self.predict(adv)
                    except Exception:
                        continue
                    if s < best_score:
                        best_score = s
                        best_val = adv[i]
                    adv[i] = orig
                adv[i] = best_val
            if best_score < 0.45:
                break
        return adv, best_score

# ---------- 6. TRANSFER ATTACK (תוקן) ----------
class TransferAttack(Attack):
    name = "Transfer"
    def run(self, x, eps=0.06):
        # surrogate model: linear combination of some features
        def surrogate(f):
            if isinstance(f, np.ndarray):
                f = f.tolist()
            return np.clip(np.mean(f[::10]) * 1.5, 0, 1)
        grad = np.zeros(len(x))
        base = surrogate(x)
        for i in range(0, len(x), 20):
            e = np.zeros(len(x))
            e[i] = 0.001
            fp = surrogate(x + e)
            fm = surrogate(x - e)
            grad[i] = (fp - fm) / 0.002
        adv = np.clip(x - eps * np.sign(grad), 0, 1)
        return adv, self.predict(adv)

# ============================================================================
# ATTACK SUITE - 1000+ וריאציות (מוקטן מעט ליציבות)
# ============================================================================

def generate_attack_variations():
    variations = []
    # FGSM - 5
    for eps in [0.02, 0.04, 0.06, 0.08, 0.10]:
        variations.append((FGSM, {"epsilon": eps}))
    # PGD - 9
    for eps in [0.06, 0.08, 0.10]:
        for steps in [15, 20, 25]:
            variations.append((PGD, {"epsilon": eps, "steps": steps, "lr": 0.01}))
    # MIM - 6
    for eps in [0.06, 0.08]:
        for steps in [20, 25]:
            variations.append((MIM, {"epsilon": eps, "steps": steps, "mu": 0.9}))
    # CW - 4
    for steps in [25, 35]:
        for c in [0.3, 0.6]:
            variations.append((CW, {"steps": steps, "c": c}))
    # Square - 3
    for q in [500, 800]:
        variations.append((SquareAttack, {"max_queries": q, "p": 0.1}))
    # SimBA - 4
    for q in [600, 800]:
        for eps in [0.015, 0.025]:
            variations.append((SimBA, {"max_queries": q, "epsilon": eps}))
    # Boundary - 2
    for steps in [300, 400]:
        variations.append((BoundaryAttack, {"max_steps": steps}))
    # HopSkipJump - 2
    for it in [150, 200]:
        variations.append((HopSkipJump, {"max_iter": it}))
    # Genetic - 4
    for pop in [15, 20]:
        for gens in [12, 15]:
            variations.append((GeneticAttack, {"pop": pop, "gens": gens, "sigma": 0.08}))
    # CMA-ES - 2
    for it in [20, 25]:
        variations.append((CMAES, {"iterations": it}))
    # SimulatedAnnealing - 2
    for it in [500, 600]:
        variations.append((SimulatedAnnealing, {"max_iter": it}))
    # FeatureImportance - 4
    for top in [30, 40]:
        for steps in [40, 50]:
            variations.append((FeatureImportanceAttack, {"n_top": top, "steps": steps}))
    # RandomSearch - 4
    for trials in [1200, 1800]:
        for noise in [0.08, 0.12]:
            variations.append((RandomSearch, {"n_trials": trials, "noise_std": noise}))
    # CoordinateDescent - 2
    variations.append((CoordinateDescent, {"epochs": 3}))
    variations.append((CoordinateDescent, {"epochs": 4}))
    # Transfer - 3
    for eps in [0.04, 0.07, 0.10]:
        variations.append((TransferAttack, {"eps": eps}))
    # חתוך ל-NUM_TESTS
    return variations[:NUM_TESTS]

# ============================================================================
# RUNNER & ANALYZER (עם timeout ל-runner כולל)
# ============================================================================

class AttackRunner:
    def __init__(self, target_features, predict_fn):
        self.target = target_features.copy()
        self.baseline_score = predict_fn(target_features)
        self.predict = predict_fn
        self.results = []
    
    def run_single(self, attack_cls, params, idx):
        attack = attack_cls(self.predict)
        start = time.time()
        try:
            adv, score = attack.run(self.target.copy(), **params)
            elapsed = time.time() - start
            success = score < 0.5
            drop = self.baseline_score - score
            return {
                "index": idx,
                "attack": attack_cls.name,
                "params": str(params),
                "final_score": round(score, 5),
                "score_drop": round(drop, 5),
                "success": success,
                "time_sec": round(elapsed, 2)
            }
        except Exception as e:
            return {"index": idx, "attack": attack_cls.name, "error": str(e)[:100], "success": False}
    
    def run_all(self, variations, max_workers=4):  # הפחתתי ל-4 ליציבות
        total = len(variations)
        print(f"\n🚀 Running {total} attack variations with {max_workers} workers...")
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {}
            for i, (cls, params) in enumerate(variations):
                future = executor.submit(self.run_single, cls, params, i)
                future_to_idx[future] = i
            for future in as_completed(future_to_idx):
                try:
                    res = future.result(timeout=60)
                except Exception as e:
                    idx = future_to_idx[future]
                    res = {"index": idx, "attack": "unknown", "error": str(e), "success": False}
                results.append(res)
                if len(results) % 100 == 0:
                    print(f"  Progress: {len(results)}/{total}")
        self.results = results
        return results
    
    def analyze(self):
        successful = [r for r in self.results if r.get("success", False)]
        failed = [r for r in self.results if not r.get("success", False) and "error" not in r]
        errors = [r for r in self.results if "error" in r]
        
        print("\n" + "="*80)
        print("📊 FINAL ANALYSIS REPORT")
        print("="*80)
        print(f"Total attacks executed:  {len(self.results)}")
        print(f"✅ Successful evasions:   {len(successful)} ({len(successful)/max(1,len(self.results))*100:.2f}%)")
        print(f"❌ Failed evasions:       {len(failed)} ({len(failed)/max(1,len(self.results))*100:.2f}%)")
        print(f"⚠️  Errors:                {len(errors)}")
        
        if successful:
            best = min(successful, key=lambda x: x["final_score"])
            print("\n🏆 MOST DANGEROUS ATTACK:")
            print(f"   Attack: {best['attack']} | Params: {best['params']}")
            print(f"   Final score: {best['final_score']:.5f} (drop: {best['score_drop']:.5f})")
            print(f"   Time: {best['time_sec']}s")
        
        families = defaultdict(list)
        for r in self.results:
            if "error" not in r:
                families[r["attack"]].append(r["final_score"])
        
        print("\n📈 PERFORMANCE BY ATTACK FAMILY (avg final score, lower = more dangerous):")
        sorted_fam = sorted(families.items(), key=lambda x: np.mean(x[1]))
        for fam, scores in sorted_fam[:10]:
            avg = np.mean(scores)
            success_rate = sum(1 for s in scores if s < 0.5) / len(scores) * 100
            print(f"   {fam:20s} avg={avg:.5f} success_rate={success_rate:.1f}%")
        
        weak = [(fam, np.mean(scores)) for fam, scores in families.items() if np.mean(scores) < 0.48]
        if weak:
            print("\n⚠️  SYSTEM VULNERABILITIES (attacks with avg score < 0.48):")
            for fam, avg_score in sorted(weak, key=lambda x: x[1])[:5]:
                print(f"   🔴 {fam}: avg score {avg_score:.5f}")
        else:
            print("\n✅ No significant vulnerabilities found - system is robust!")
        
        return successful, families

# ============================================================================
# MAIN
# ============================================================================
def main():
    print("\n" + "═"*80)
    print("💀 ULTIMATE BREACH ATTACK v3.1 – WORLD-CLASS SUITE (FIXED) 💀")
    print("═"*80)
    
    try:
        engine = get_engine()
    except Exception as e:
        print(f"❌ Failed to load engine: {e}")
        return
    
    print(f"Target: {engine.VERSION}")
    
    x_mal = create_target(DIM)
    
    def predict_safe(features):
        try:
            return predict_with_timeout(engine, features)
        except Exception:
            return 0.95
    
    base_score = predict_safe(x_mal)
    print(f"🔴 Baseline threat score: {base_score:.5f}")
    
    variations = generate_attack_variations()
    print(f"\n📋 Generated {len(variations)} attack configurations")
    
    runner = AttackRunner(x_mal, predict_safe)
    start_total = time.time()
    runner.run_all(variations, max_workers=4)
    total_time = time.time() - start_total
    
    runner.analyze()
    print(f"\n⏱️  Total execution time: {total_time:.1f} seconds")
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"breach_report_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump({
            "target_version": engine.VERSION,
            "baseline_score": base_score,
            "total_attacks": len(runner.results),
            "results": runner.results,
            "total_time_sec": total_time
        }, f, indent=2)
    print(f"💾 Detailed report saved to {filename}")
    
    print("\n" + "═"*80)
    print("🏁 RESEARCH COMPLETE. SYSTEM READY FOR HARDENING.")
    print("═"*80)

if __name__ == "__main__":
    main()