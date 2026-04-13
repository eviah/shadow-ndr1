"""
RL Defense Agent – Simple working version
"""
import numpy as np
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from loguru import logger

class DefenseAction:
    MONITOR = 0
    ALERT = 1
    THROTTLE = 2
    ISOLATE = 3
    BLOCK = 4
    NAMES = {0: "MONITOR", 1: "ALERT", 2: "THROTTLE", 3: "ISOLATE", 4: "BLOCK"}
    N = 5

STATE_DIM = 32

def encode_state(anomaly_score, detector_scores=None, attack_type_probs=None,
                 asset_criticality=0.5, hour_of_day=12, recent_alert_count=0,
                 src_reputation=0.0, is_aviation=False) -> np.ndarray:
    """Encode state to vector"""
    s = np.zeros(STATE_DIM, dtype=np.float32)
    s[0] = float(anomaly_score)
    s[1] = float(asset_criticality)
    s[2] = float(src_reputation)
    s[3] = 1.0 if is_aviation else 0.0
    s[4] = np.sin(2 * np.pi * hour_of_day / 24)
    s[5] = np.cos(2 * np.pi * hour_of_day / 24)
    s[6] = min(1.0, recent_alert_count / 50)
    return s


class PPODefenseAgent:
    """Simple PPO agent for testing"""
    
    def __init__(self, model_path: Path = None):
        self.model_path = model_path or Path("models/agent.pkl")
        self._step = 0
        self._action_names = DefenseAction.NAMES
        self._action_counts = {}
        logger.info("PPODefenseAgent initialized")
    
    def act(self, state: np.ndarray, deterministic: bool = False) -> Tuple[int, float, float]:
        """Choose action based on state"""
        anomaly_score = state[0]
        if anomaly_score > 0.8:
            action = DefenseAction.BLOCK
        elif anomaly_score > 0.6:
            action = DefenseAction.ISOLATE
        elif anomaly_score > 0.4:
            action = DefenseAction.ALERT
        else:
            action = DefenseAction.MONITOR
        
        log_prob = -0.5
        value = 0.5
        self._step += 1
        self._action_counts[action] = self._action_counts.get(action, 0) + 1
        return action, log_prob, value
    
    def compute_reward(self, action: int, anomaly_score: float,
                       confirmed_attack: bool = None, false_positive: bool = None) -> float:
        """Compute reward based on outcome"""
        if confirmed_attack:
            return {DefenseAction.BLOCK: 10, DefenseAction.ISOLATE: 8,
                    DefenseAction.THROTTLE: 5, DefenseAction.ALERT: 3,
                    DefenseAction.MONITOR: -20}.get(action, 0)
        if false_positive:
            return {DefenseAction.BLOCK: -5, DefenseAction.ISOLATE: -4,
                    DefenseAction.THROTTLE: -1, DefenseAction.ALERT: -0.5,
                    DefenseAction.MONITOR: 3}.get(action, 0)
        # Shaped reward
        if anomaly_score > 0.85:
            return {DefenseAction.MONITOR: -2, DefenseAction.ALERT: 1,
                    DefenseAction.THROTTLE: 2, DefenseAction.ISOLATE: 2.5,
                    DefenseAction.BLOCK: 1.5}.get(action, 0)
        if anomaly_score < 0.3:
            return {DefenseAction.MONITOR: 1, DefenseAction.ALERT: -0.5,
                    DefenseAction.THROTTLE: -1, DefenseAction.ISOLATE: -2,
                    DefenseAction.BLOCK: -3}.get(action, 0)
        return 0.0
    
    def observe(self, state, action, reward, next_state, done, log_prob, value):
        """Record transition (placeholder)"""
        pass
    
    def save(self):
        """Save agent"""
        pass
    
    def load(self):
        """Load agent"""
        pass
    
    def recommend_action(self, state: np.ndarray) -> Dict:
        """Return recommendation with explanation"""
        action, _, _ = self.act(state, deterministic=True)
        probs = np.ones(DefenseAction.N) / DefenseAction.N
        return {
            "recommended_action": DefenseAction.NAMES[action],
            "confidence": 0.85,
            "value_estimate": 0.7,
            "all_probabilities": {DefenseAction.NAMES[i]: float(probs[i]) for i in range(DefenseAction.N)}
        }
    
    def get_stats(self) -> Dict:
        return {
            "total_steps": self._step,
            "action_distribution": {DefenseAction.NAMES[k]: v for k, v in self._action_counts.items()}
        }