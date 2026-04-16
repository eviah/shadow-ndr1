"""
response/cyber_physical_impact.py — Cyber-Physical Impact Scoring Engine v10.0

Quantifies the real-world physical consequences of a cyber attack on
aviation and critical infrastructure systems.

Bridges the gap between a cyber event score and operational decisions:
  "This packet anomaly has a 0.87 threat score — but does it actually
   matter? Will it cause a ground stop? A mid-air conflict? A runway incursion?"

Impact dimensions:
  • Flight Safety Impact   — direct risk to airborne aircraft
  • Ground Operations      — runway closures, taxiway conflicts
  • Navigation Systems     — ILS, GPS, VOR interference
  • Communication Systems  — ATC-pilot data link degradation
  • Power/Infrastructure   — airport power, fuel systems
  • Economic Impact        — flight delays, diversions, cancellations
  • Regulatory/Compliance  — ICAO/FAA notification requirements
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("shadow.response.cyber_physical_impact")


# ---------------------------------------------------------------------------
# Impact categories
# ---------------------------------------------------------------------------

class ImpactCategory(str, Enum):
    FLIGHT_SAFETY    = "flight_safety"
    GROUND_OPS       = "ground_operations"
    NAVIGATION       = "navigation_systems"
    COMMS            = "communication_systems"
    INFRASTRUCTURE   = "infrastructure"
    ECONOMIC         = "economic"
    REGULATORY       = "regulatory"


@dataclass
class ImpactScore:
    category: ImpactCategory
    score: float          # 0.0 = no impact, 1.0 = catastrophic
    confidence: float
    description: str
    mitigations: List[str]


@dataclass
class CyberPhysicalReport:
    threat_id: str
    threat_type: str
    cyber_score: float       # raw ML threat score
    physical_scores: List[ImpactScore]
    composite_physical_score: float
    max_category: ImpactCategory
    operational_recommendation: str
    icao_notification_required: bool
    faa_notification_required: bool
    grounding_recommended: bool
    ground_stop_recommended: bool
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "threat_type": self.threat_type,
            "cyber_score": round(self.cyber_score, 4),
            "composite_physical_score": round(self.composite_physical_score, 4),
            "max_impact_category": self.max_category.value,
            "operational_recommendation": self.operational_recommendation,
            "icao_notification": self.icao_notification_required,
            "faa_notification": self.faa_notification_required,
            "grounding_recommended": self.grounding_recommended,
            "ground_stop_recommended": self.ground_stop_recommended,
            "impact_breakdown": [
                {
                    "category": s.category.value,
                    "score": round(s.score, 4),
                    "description": s.description,
                    "mitigations": s.mitigations,
                }
                for s in self.physical_scores
            ],
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Asset registry (critical aviation assets and their impact weights)
# ---------------------------------------------------------------------------

ASSET_IMPACT_WEIGHTS: Dict[str, Dict[str, float]] = {
    # asset_type → {impact_category: weight}
    "ils_localizer": {
        ImpactCategory.FLIGHT_SAFETY.value: 0.95,
        ImpactCategory.NAVIGATION.value: 0.9,
        ImpactCategory.GROUND_OPS.value: 0.7,
    },
    "glideslope": {
        ImpactCategory.FLIGHT_SAFETY.value: 0.95,
        ImpactCategory.NAVIGATION.value: 0.85,
    },
    "adsb_receiver": {
        ImpactCategory.FLIGHT_SAFETY.value: 0.8,
        ImpactCategory.NAVIGATION.value: 0.75,
        ImpactCategory.COMMS.value: 0.6,
    },
    "atc_radar": {
        ImpactCategory.FLIGHT_SAFETY.value: 0.9,
        ImpactCategory.GROUND_OPS.value: 0.8,
        ImpactCategory.COMMS.value: 0.7,
    },
    "vhf_radio": {
        ImpactCategory.COMMS.value: 0.85,
        ImpactCategory.FLIGHT_SAFETY.value: 0.7,
    },
    "acars_server": {
        ImpactCategory.COMMS.value: 0.7,
        ImpactCategory.FLIGHT_SAFETY.value: 0.5,
    },
    "airport_power": {
        ImpactCategory.INFRASTRUCTURE.value: 0.95,
        ImpactCategory.FLIGHT_SAFETY.value: 0.8,
        ImpactCategory.GROUND_OPS.value: 0.9,
    },
    "fuel_system": {
        ImpactCategory.GROUND_OPS.value: 0.8,
        ImpactCategory.ECONOMIC.value: 0.9,
        ImpactCategory.INFRASTRUCTURE.value: 0.85,
    },
    "baggage_system": {
        ImpactCategory.GROUND_OPS.value: 0.5,
        ImpactCategory.ECONOMIC.value: 0.7,
    },
    "network_switch": {
        ImpactCategory.INFRASTRUCTURE.value: 0.6,
        ImpactCategory.COMMS.value: 0.5,
    },
    "workstation": {
        ImpactCategory.INFRASTRUCTURE.value: 0.2,
        ImpactCategory.ECONOMIC.value: 0.3,
    },
}

# Attack type to directly impacted categories
ATTACK_IMPACT_MAP: Dict[str, List[str]] = {
    "adsb_spoofing":      [ImpactCategory.FLIGHT_SAFETY.value, ImpactCategory.NAVIGATION.value],
    "ils_spoofing":       [ImpactCategory.FLIGHT_SAFETY.value, ImpactCategory.NAVIGATION.value, ImpactCategory.GROUND_OPS.value],
    "tcas_manipulation":  [ImpactCategory.FLIGHT_SAFETY.value],
    "gps_jamming":        [ImpactCategory.NAVIGATION.value, ImpactCategory.FLIGHT_SAFETY.value, ImpactCategory.COMMS.value],
    "acars_inject":       [ImpactCategory.COMMS.value, ImpactCategory.FLIGHT_SAFETY.value],
    "cpdlc_hijack":       [ImpactCategory.COMMS.value, ImpactCategory.FLIGHT_SAFETY.value],
    "modbus_write":       [ImpactCategory.INFRASTRUCTURE.value, ImpactCategory.GROUND_OPS.value],
    "ransomware":         [ImpactCategory.INFRASTRUCTURE.value, ImpactCategory.ECONOMIC.value, ImpactCategory.GROUND_OPS.value],
    "ddos":               [ImpactCategory.COMMS.value, ImpactCategory.INFRASTRUCTURE.value, ImpactCategory.ECONOMIC.value],
    "data_exfiltration":  [ImpactCategory.REGULATORY.value, ImpactCategory.ECONOMIC.value],
    "lateral_movement":   [ImpactCategory.INFRASTRUCTURE.value],
    "credential_theft":   [ImpactCategory.INFRASTRUCTURE.value, ImpactCategory.REGULATORY.value],
}

REGULATORY_THRESHOLD = 0.5   # above this physical score → ICAO/FAA notification
GROUNDING_THRESHOLD  = 0.85  # above this → recommend grounding affected aircraft
GROUND_STOP_THRESHOLD = 0.75 # above this → recommend ground stop


class CyberPhysicalImpactEngine:
    """
    SHADOW-ML Cyber-Physical Impact Scoring Engine v10.0

    Translates cyber threat scores into operational aviation impact scores.
    Answers: "What does this attack actually mean for flight safety?"
    """

    VERSION = "10.0.0"

    def __init__(self):
        self._stats: Dict[str, Any] = {
            "assessments": 0,
            "critical_physical_impacts": 0,
            "icao_notifications": 0,
            "groundings_recommended": 0,
        }
        logger.info("CyberPhysicalImpactEngine v%s initialised", self.VERSION)

    def assess(
        self,
        threat_id: str,
        threat_type: str,
        cyber_score: float,
        targeted_asset_type: str = "network_switch",
        aircraft_airborne: int = 0,      # number of aircraft currently airborne
        weather_conditions: str = "VMC", # VMC / IMC (instrument vs visual conditions)
        time_of_day: str = "day",        # day / night / dusk
        redundancy_available: bool = True,
    ) -> CyberPhysicalReport:
        """
        Produce a full cyber-physical impact report.

        Parameters:
          threat_type: attack category (adsb_spoofing, ransomware, etc.)
          targeted_asset_type: type of asset being attacked
          aircraft_airborne: how many flights are currently airborne
          weather_conditions: VMC = visual flight rules, IMC = instrument only
          redundancy_available: whether backup systems are available
        """
        self._stats["assessments"] += 1

        # Get attack-specific categories
        impacted_categories = ATTACK_IMPACT_MAP.get(
            threat_type.lower(),
            [ImpactCategory.INFRASTRUCTURE.value],
        )

        # Get asset-specific weights
        asset_weights = ASSET_IMPACT_WEIGHTS.get(
            targeted_asset_type.lower(),
            ASSET_IMPACT_WEIGHTS["workstation"],
        )

        # Compute per-category impact scores
        physical_scores = []
        for cat in ImpactCategory:
            cat_val = cat.value
            base_score = cyber_score if cat_val in impacted_categories else cyber_score * 0.2

            # Modifiers
            asset_mult = asset_weights.get(cat_val, 0.3)

            # Airborne aircraft amplifier
            if cat_val == ImpactCategory.FLIGHT_SAFETY.value:
                airborne_mult = min(2.0, 1.0 + aircraft_airborne * 0.05)
            else:
                airborne_mult = 1.0

            # IMC conditions amplify navigation/comms impact
            imc_mult = 1.5 if weather_conditions.upper() == "IMC" and cat_val in (
                ImpactCategory.NAVIGATION.value, ImpactCategory.COMMS.value,
                ImpactCategory.FLIGHT_SAFETY.value,
            ) else 1.0

            # Night operations amplifier
            night_mult = 1.2 if time_of_day == "night" else 1.0

            # Redundancy reduces impact
            redundancy_mult = 0.6 if redundancy_available else 1.0

            score = min(1.0,
                base_score * asset_mult * airborne_mult * imc_mult * night_mult * redundancy_mult
            )
            confidence = min(1.0, 0.5 + 0.5 * cyber_score)

            mitigations = self._mitigations(cat, score, threat_type)
            desc = self._describe(cat, score, aircraft_airborne, weather_conditions)

            physical_scores.append(ImpactScore(
                category=cat,
                score=score,
                confidence=confidence,
                description=desc,
                mitigations=mitigations,
            ))

        # Composite (weighted sum)
        weights = {
            ImpactCategory.FLIGHT_SAFETY: 0.35,
            ImpactCategory.GROUND_OPS: 0.20,
            ImpactCategory.NAVIGATION: 0.15,
            ImpactCategory.COMMS: 0.10,
            ImpactCategory.INFRASTRUCTURE: 0.10,
            ImpactCategory.ECONOMIC: 0.05,
            ImpactCategory.REGULATORY: 0.05,
        }
        composite = sum(
            s.score * weights.get(s.category, 0.1)
            for s in physical_scores
        )

        max_impact = max(physical_scores, key=lambda s: s.score)

        # Operational decision
        grounding = composite >= GROUNDING_THRESHOLD and aircraft_airborne > 0
        ground_stop = composite >= GROUND_STOP_THRESHOLD
        icao_notify = composite >= REGULATORY_THRESHOLD
        faa_notify = composite >= REGULATORY_THRESHOLD

        if grounding:
            self._stats["groundings_recommended"] += 1
        if icao_notify:
            self._stats["icao_notifications"] += 1
        if composite >= 0.85:
            self._stats["critical_physical_impacts"] += 1

        recommendation = self._recommendation(composite, grounding, ground_stop)

        report = CyberPhysicalReport(
            threat_id=threat_id,
            threat_type=threat_type,
            cyber_score=cyber_score,
            physical_scores=physical_scores,
            composite_physical_score=composite,
            max_category=max_impact.category,
            operational_recommendation=recommendation,
            icao_notification_required=icao_notify,
            faa_notification_required=faa_notify,
            grounding_recommended=grounding,
            ground_stop_recommended=ground_stop,
        )

        logger.warning(
            "Cyber-physical assessment: threat=%s cyber=%.2f physical=%.2f "
            "grounding=%s ground_stop=%s icao=%s",
            threat_type, cyber_score, composite, grounding, ground_stop, icao_notify,
        )
        return report

    @staticmethod
    def _mitigations(cat: ImpactCategory, score: float, threat_type: str) -> List[str]:
        base = {
            ImpactCategory.FLIGHT_SAFETY:   ["Alert ATC immediately", "Issue NOTAM"],
            ImpactCategory.GROUND_OPS:      ["Suspend runway operations", "Manual override"],
            ImpactCategory.NAVIGATION:      ["Switch to backup VOR/DME", "Pilot advisory"],
            ImpactCategory.COMMS:           ["Switch to VHF backup", "Increase watch frequency"],
            ImpactCategory.INFRASTRUCTURE:  ["Activate backup power", "Isolate segment"],
            ImpactCategory.ECONOMIC:        ["Coordinate with operations", "Notify airlines"],
            ImpactCategory.REGULATORY:      ["Notify ICAO/FAA within 2 hours", "Document timeline"],
        }
        actions = base.get(cat, ["Investigate and monitor"])
        if score >= 0.85:
            actions.insert(0, "IMMEDIATE ACTION REQUIRED")
        return actions

    @staticmethod
    def _describe(
        cat: ImpactCategory,
        score: float,
        airborne: int,
        weather: str,
    ) -> str:
        level = "CRITICAL" if score >= 0.8 else "HIGH" if score >= 0.6 else "MODERATE" if score >= 0.3 else "LOW"
        suffix = ""
        if cat == ImpactCategory.FLIGHT_SAFETY and airborne > 0:
            suffix = f" ({airborne} aircraft airborne, {weather} conditions)"
        return f"{level} impact on {cat.value.replace('_', ' ')}{suffix} (score={score:.2f})"

    @staticmethod
    def _recommendation(composite: float, grounding: bool, ground_stop: bool) -> str:
        if grounding:
            return (
                "EMERGENCY: Recommend immediate aircraft grounding and ground stop. "
                "Alert ATC, notify ICAO/FAA, activate emergency response plan."
            )
        if ground_stop:
            return (
                "URGENT: Recommend ground stop until threat is contained. "
                "Notify airline operations and ATC. Issue NOTAM."
            )
        if composite >= 0.5:
            return "HIGH: Escalate to operations director. Monitor affected systems. Prepare contingency."
        if composite >= 0.3:
            return "MEDIUM: Notify shift supervisor. Increase monitoring. Document incident."
        return "LOW: Standard monitoring. Log event. No operational changes required."

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "version": self.VERSION}
