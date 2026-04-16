import numpy as np
import time
from enum import Enum
from dataclasses import dataclass
from typing import List, Optional

class FusionMethod(Enum):
    WEIGHTED_AVERAGE = "weighted_average"
    KALMAN = "kalman"
    ADAPTIVE = "adaptive"

class SensorType(Enum):
    NETWORK = "network"
    ADS_B = "ads_b"

@dataclass
class SensorData:
    sensor_type: SensorType
    timestamp: float
    data: dict
    confidence: float = 1.0

class SensorFusionEngine:
    def __init__(self):
        self.history = []
    async def fuse(self, sensors: List[SensorData], method: Optional[FusionMethod] = None) -> dict:
        if not sensors:
            return {"confidence": 0.0, "features": []}
        avg_conf = sum(s.confidence for s in sensors) / len(sensors)
        return {"confidence": avg_conf, "features": [], "method": method.value if method else "default"}
