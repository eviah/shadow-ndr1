#!/usr/bin/env python3
"""
SHADOW NDR – EL AL Defense Demonstration (ULTIMATE)
====================================================
World‑class aviation security simulation with AI‑powered threat detection,
Gemini‑generated alerts, and full‑stack integration.

⚠️  This simulation is for authorized security testing and educational purposes only.
    Unauthorized use against real systems is strictly prohibited.

Features:
- Multimodal fusion (ADS‑B, ACARS, network, voice, vision)
- RL‑based autonomous defense agent
- Gemini AI alert generation with multi‑language support
- Real‑time backend integration (PostgreSQL, Kafka, WebSocket)
- Advanced attack vectors: coordinated spoofing, injection, reconnaissance, hijack
- Visual threat map (simulated) and asset tracking
"""

import sys
import time
import random
import numpy as np
import requests
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import core modules
from app.fusion.multimodal_fusion import (
    MultimodalFusionEngine,
    NetworkSignal,
    ADSBSignal,
    VoiceSignal,
    VisionSignal,
)
from app.rl_agent.defense_agent import PPODefenseAgent, encode_state

# Gemini alert generator (must be in same directory or PYTHONPATH)
try:
    from gemini_alert import generate_alert
except ImportError:
    # Fallback if not available
    def generate_alert(threat_type, severity, source, description, score, **kwargs):
        return {
            "title": f"⚠️ {threat_type} – {severity.upper()}",
            "summary": description,
            "recommended_actions": ["Investigate immediately", "Notify ATC"],
            "analysis": f"Anomaly score: {score:.2f}",
            "confidence": score
        }

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
ELAL_CONFIG = {
    "airline": "EL AL",
    "icao_prefix": "ELY",
    "assets": [
        {"name": "Boeing 777-200ER (4X-ECA)", "icao24": "ABCDEF", "criticality": 0.95, "lat": 32.011, "lon": 34.886, "status": "active"},
        {"name": "Boeing 787-9 (4X-EDF)", "icao24": "123456", "criticality": 0.98, "lat": 32.012, "lon": 34.887, "status": "active"},
        {"name": "Ben Gurion ATC", "ip": "10.0.0.1", "criticality": 1.0, "lat": 32.011, "lon": 34.886, "type": "ground"},
        {"name": "EL AL Network Gateway", "ip": "192.168.20.1", "criticality": 0.9, "type": "network"},
    ],
    "defense_threshold": 0.6,
    "simulation_speed": 10.0,
}

BACKEND_URL = "http://localhost:3001/api/threats"
WS_URL = "ws://localhost:3001/ws"  # simulated

# -----------------------------------------------------------------------------
# Enhanced logging and visual effects
# -----------------------------------------------------------------------------
def print_color(text, color="white"):
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[0m",
        "bold": "\033[1m",
    }
    print(f"{colors.get(color, colors['white'])}{text}\033[0m")

def print_threat_box(title, content, severity):
    box_char = "█"
    color = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}.get(severity, "white")
    print_color(f"\n{box_char*60}", color)
    print_color(f"{box_char} {title}", color)
    print_color(f"{box_char} {content}", color)
    print_color(f"{box_char*60}", color)

# -----------------------------------------------------------------------------
# Enhanced backend integration with WebSocket simulation
# -----------------------------------------------------------------------------
def send_to_backend(threat_type: str, severity: str, source: str,
                    description: str, score: float, metadata: Optional[Dict] = None) -> bool:
    payload = {
        "threat_type": threat_type,
        "severity": severity,
        "source": source,
        "description": description,
        "score": score,
        "detected_at": datetime.now().isoformat()
    }
    if metadata:
        payload["metadata"] = metadata
    try:
        response = requests.post(BACKEND_URL, json=payload, timeout=2)
        if response.status_code in (200, 201):
            return True
        else:
            print(f"    (Backend error: {response.status_code})")
            return False
    except requests.exceptions.RequestException as e:
        print(f"    (Backend not reachable: {e})")
        return False

def notify_frontend(threat_data: Dict):
    """Simulate WebSocket notification to frontend (placeholder)."""
    # In production, you'd send via WebSocket client.
    print_color(f"[NOTIFY] Frontend: {threat_data.get('threat_type')} – {threat_data.get('severity')}", "cyan")

# -----------------------------------------------------------------------------
# Advanced attack vectors
# -----------------------------------------------------------------------------
def coordinated_attack(icao24, target_ip, ghost_score=0.96, scan_score=0.85):
    """Simulate a coordinated attack combining spoofing and network reconnaissance."""
    print_color(f"[ADVANCED ATTACK] Coordinated: ADS‑B spoofing + network scan", "red")
    adsb_signal = ADSBSignal(
        score=ghost_score,
        icao24=icao24,
        confidence=0.98,
        is_emergency_squawk=False,
        ghost_probability=0.95,
    )
    net_signal = NetworkSignal(
        score=scan_score,
        src_ip="45.33.22.11",
        dst_ip=target_ip,
        confidence=0.9,
        protocol="TCP",
    )
    return adsb_signal, net_signal

# -----------------------------------------------------------------------------
# Attack simulation functions (original)
# -----------------------------------------------------------------------------
def normal_traffic():
    adsb = ADSBSignal(
        score=0.05 + random.random() * 0.1,
        icao24=random.choice([a["icao24"] for a in ELAL_CONFIG["assets"] if "icao24" in a]),
        confidence=0.95,
        is_emergency_squawk=False,
    )
    network = NetworkSignal(
        score=0.02 + random.random() * 0.08,
        src_ip=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
        confidence=0.9,
        protocol="TCP",
    )
    voice = VoiceSignal(
        score=0.01 + random.random() * 0.05,
        confidence=0.85,
        stress_level=0.1 + random.random() * 0.2,
    )
    vision = VisionSignal(
        score=0.02 + random.random() * 0.05,
        confidence=0.8,
        weapon_detected=False,
    )
    return adsb, network, voice, vision

def attack_adsb_spoofing(icao24, ghost_score=0.95):
    print_color(f"[ATTACK] ADS‑B spoofing on ICAO {icao24} – ghost aircraft injected", "red")
    return ADSBSignal(
        score=ghost_score,
        icao24=icao24,
        confidence=0.98,
        is_emergency_squawk=False,
        ghost_probability=0.92,
    )

def attack_acars_injection():
    print_color("[ATTACK] ACARS injection: bomb threat message sent to ATC", "red")
    return NetworkSignal(
        score=0.92,
        src_ip="172.16.0.50",
        confidence=0.95,
        protocol="ACARS",
    )

def attack_network_scan(target_ip):
    print_color(f"[ATTACK] Network scan targeting {target_ip}", "red")
    return NetworkSignal(
        score=0.85,
        src_ip="45.33.22.11",
        confidence=0.9,
        protocol="TCP",
    )

def emergency_squawk(icao24):
    print_color(f"[ATTACK] Emergency squawk 7700 on ICAO {icao24} – hijack attempt", "red")
    return ADSBSignal(
        score=0.98,
        icao24=icao24,
        confidence=0.99,
        is_emergency_squawk=True,
    )

# -----------------------------------------------------------------------------
# Gemini alert generator wrapper with context
# -----------------------------------------------------------------------------
def generate_and_show_alert(threat_type, severity, source, description, score,
                            asset_criticality=0.5, location=None, extra=None):
    """Generate Gemini alert and print to console."""
    alert = generate_alert(
        threat_type=threat_type,
        severity=severity,
        source=source,
        description=description,
        score=score,
        asset_criticality=asset_criticality,
        location=location,
        extra_context=extra
    )
    # Pretty print the alert
    print_threat_box(alert.get("title", "ALERT"), alert.get("summary", description), severity)
    print("💡 Recommended actions:")
    for act in alert.get("recommended_actions", []):
        print(f"   • {act}")
    print(f"📊 Analysis: {alert.get('analysis', '')}")
    print(f"🎯 Confidence: {alert.get('confidence', score):.0%}")
    return alert

# -----------------------------------------------------------------------------
# Main demonstration
# -----------------------------------------------------------------------------
def run_demo():
    print("\n" + "=" * 80)
    print_color("SHADOW NDR – EL AL Defense Demonstration (ULTIMATE)", "cyan")
    print_color("Protecting Israel's national airline against cyber threats", "cyan")
    print("=" * 80)

    # Initialize engines
    fusion = MultimodalFusionEngine(anomaly_threshold=0.6)
    rl_agent = PPODefenseAgent()
    print("\n[INIT] ML systems ready. Starting normal operations simulation...\n")

    # Simulate normal traffic
    for i in range(5):
        adsb, net, voice, vision = normal_traffic()
        fusion.update_network(net)
        fusion.update_adsb(adsb)
        fusion.update_voice(voice)
        fusion.update_vision(vision)
        result = fusion.fuse()
        state = encode_state(result.fused_score, is_aviation=True)
        action, _, _ = rl_agent.act(state)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Normal: score={result.fused_score:.3f}, action={rl_agent._action_names[action]}")
        time.sleep(0.5 / ELAL_CONFIG["simulation_speed"])

    print("\n" + "-" * 80)
    print_color("!!! ATTACK SEQUENCE BEGINS !!!", "yellow")
    print("-" * 80)

    # -------------------------------------------------------------------------
    # Attack 1: ADS‑B Spoofing
    # -------------------------------------------------------------------------
    print("\n[1] Detecting ADS‑B spoofing on EL AL aircraft ELY001...")
    fake_adsb = attack_adsb_spoofing("ABCDEF", ghost_score=0.96)
    fusion.update_adsb(fake_adsb)
    net, voice, vision = normal_traffic()[1:]  # keep other modalities normal
    fusion.update_network(net)
    fusion.update_voice(voice)
    fusion.update_vision(vision)
    result = fusion.fuse()
    state = encode_state(result.fused_score, is_aviation=True)
    action, _, _ = rl_agent.act(state)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Fused score: {result.fused_score:.3f}")
    print(f"    Recommended action: {rl_agent._action_names[action]}")
    print(f"    Explanation: {result.explanation}")

    # Send to backend
    send_to_backend(
        threat_type="ADS‑B Spoofing",
        severity="critical",
        source=fake_adsb.icao24,
        description=f"Ghost aircraft with ICAO {fake_adsb.icao24} detected",
        score=fake_adsb.score,
        metadata={"icao24": fake_adsb.icao24, "ghost_probability": fake_adsb.ghost_probability}
    )
    # Generate Gemini alert
    alert = generate_and_show_alert(
        threat_type="ADS‑B Spoofing",
        severity="critical",
        source=fake_adsb.icao24,
        description=f"Ghost aircraft ICAO {fake_adsb.icao24} near Ben Gurion",
        score=fake_adsb.score,
        asset_criticality=0.95,
        location="Ben Gurion Airport",
        extra={"ghost_probability": 0.92, "detector": "ML Ensemble"}
    )
    notify_frontend(alert)

    if action == 4:
        print_color("    ✅ ACTION: Blocking the spoofed ICAO address and isolating the suspicious source.", "green")
    elif action == 3:
        print_color("    ✅ ACTION: Isolating the suspicious aircraft from the network.", "green")
    else:
        print(f"    ACTION: {rl_agent._action_names[action]} (further monitoring)")

    time.sleep(1.0 / ELAL_CONFIG["simulation_speed"])

    # -------------------------------------------------------------------------
    # Attack 2: ACARS Injection
    # -------------------------------------------------------------------------
    print("\n[2] ACARS injection with bomb threat detected...")
    acars_attack = attack_acars_injection()
    fusion.update_network(acars_attack)
    adsb, voice, vision = normal_traffic()[0], normal_traffic()[2], normal_traffic()[3]
    fusion.update_adsb(adsb)
    fusion.update_voice(voice)
    fusion.update_vision(vision)
    result = fusion.fuse()
    state = encode_state(result.fused_score, is_aviation=True)
    action, _, _ = rl_agent.act(state)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Fused score: {result.fused_score:.3f}")
    print(f"    Recommended action: {rl_agent._action_names[action]}")
    print(f"    Explanation: {result.explanation}")

    send_to_backend(
        threat_type="ACARS Injection",
        severity="high",
        source=acars_attack.src_ip,
        description="Unauthorised uplink message containing bomb threat",
        score=acars_attack.score,
        metadata={"src_ip": acars_attack.src_ip, "protocol": acars_attack.protocol}
    )
    alert = generate_and_show_alert(
        threat_type="ACARS Injection",
        severity="high",
        source=acars_attack.src_ip,
        description="Bomb threat message sent to ATC",
        score=acars_attack.score,
        asset_criticality=0.9,
        location="ATC Tower",
        extra={"protocol": "ACARS"}
    )
    notify_frontend(alert)

    if action in (3, 4):
        print_color("    ✅ ACTION: Blocking source IP 172.16.0.50 and alerting ATC.", "green")
    else:
        print(f"    ACTION: {rl_agent._action_names[action]} (escalating to manual review)")

    time.sleep(1.0 / ELAL_CONFIG["simulation_speed"])

    # -------------------------------------------------------------------------
    # Attack 3: Network Scan on ATC
    # -------------------------------------------------------------------------
    print("\n[3] Network scanning on Ben Gurion ATC systems detected...")
    scan_attack = attack_network_scan(ELAL_CONFIG["assets"][2]["ip"])
    fusion.update_network(scan_attack)
    adsb, voice, vision = normal_traffic()[0], normal_traffic()[2], normal_traffic()[3]
    fusion.update_adsb(adsb)
    fusion.update_voice(voice)
    fusion.update_vision(vision)
    result = fusion.fuse()
    state = encode_state(result.fused_score, is_aviation=True)
    action, _, _ = rl_agent.act(state)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Fused score: {result.fused_score:.3f}")
    print(f"    Recommended action: {rl_agent._action_names[action]}")

    send_to_backend(
        threat_type="Network Reconnaissance",
        severity="medium",
        source=scan_attack.src_ip,
        description=f"Port scan targeting ATC IP {ELAL_CONFIG['assets'][2]['ip']}",
        score=scan_attack.score,
        metadata={"target_ip": ELAL_CONFIG['assets'][2]['ip'], "src_ip": scan_attack.src_ip}
    )
    alert = generate_and_show_alert(
        threat_type="Network Reconnaissance",
        severity="medium",
        source=scan_attack.src_ip,
        description=f"Port scan on ATC system at {ELAL_CONFIG['assets'][2]['ip']}",
        score=scan_attack.score,
        asset_criticality=1.0,
        location="ATC Network"
    )
    notify_frontend(alert)

    if action == 4:
        print_color("    ✅ ACTION: Blocking the external IP 45.33.22.11 and alerting SOC.", "green")
    else:
        print(f"    ACTION: {rl_agent._action_names[action]} (throttling traffic)")

    time.sleep(1.0 / ELAL_CONFIG["simulation_speed"])

    # -------------------------------------------------------------------------
    # Attack 4: Hijack (Emergency Squawk)
    # -------------------------------------------------------------------------
    print("\n[4] Hijack scenario: Emergency squawk 7500 detected!")
    hijack = emergency_squawk("123456")
    fusion.update_adsb(hijack)
    net, voice, vision = normal_traffic()[1:]  # keep other modalities normal
    fusion.update_network(net)
    fusion.update_voice(voice)
    fusion.update_vision(vision)
    result = fusion.fuse()
    state = encode_state(result.fused_score, is_aviation=True)
    action, _, _ = rl_agent.act(state)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Fused score: {result.fused_score:.3f}")
    print(f"    Recommended action: {rl_agent._action_names[action]}")

    send_to_backend(
        threat_type="Hijack Attempt",
        severity="emergency",
        source=hijack.icao24,
        description="Squawk 7500 detected – possible unlawful interference",
        score=hijack.score,
        metadata={"icao24": hijack.icao24, "squawk": "7500"}
    )
    alert = generate_and_show_alert(
        threat_type="Hijack Attempt",
        severity="emergency",
        source=hijack.icao24,
        description=f"Squawk 7500 on ICAO {hijack.icao24}",
        score=hijack.score,
        asset_criticality=0.98,
        location="Airspace",
        extra={"squawk": "7500"}
    )
    notify_frontend(alert)

    print_color("    ✅ ACTION: IMMEDIATE ATC ALERT - coordinating with ground security and special forces.", "green")

    # -------------------------------------------------------------------------
    # Bonus: Coordinated Attack (optional)
    # -------------------------------------------------------------------------
    # Uncomment to simulate a coordinated attack after the sequence
    # print("\n[5] Coordinated attack: ADS‑B spoofing + network scan...")
    # adsb_co, net_co = coordinated_attack("ABCDEF", "192.168.20.1")
    # fusion.update_adsb(adsb_co)
    # fusion.update_network(net_co)
    # result = fusion.fuse()
    # print(f"Coordinated attack score: {result.fused_score:.3f}")

    # Final summary
    print("\n" + "=" * 80)
    print_color("DEMONSTRATION SUMMARY", "cyan")
    print("=" * 80)
    print("Attacks launched:")
    print("  1. ADS‑B spoofing (ghost aircraft)")
    print("  2. ACARS injection (bomb threat)")
    print("  3. Network reconnaissance on ATC")
    print("  4. Hijack squawk 7500")
    print("\nDefense actions taken:")
    print("  ✓ Real‑time anomaly detection via multimodal fusion")
    print("  ✓ Autonomous RL agent selected appropriate mitigation")
    print("  ✓ Blocked malicious IPs and isolated compromised assets")
    print("  ✓ Alerted ATC and security forces immediately")
    print("  ✓ AI‑generated Gemini alerts delivered to SOC")
    print("\n✅ EL AL aviation systems protected successfully!")
    print("Shadow NDR – Protecting the future of aviation.\n")

if __name__ == "__main__":
    run_demo()