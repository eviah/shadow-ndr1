#!/usr/bin/env python3
"""
SHADOW NDR – AUTOMATIC THREAT SIMULATOR (BACKGROUND SERVICE) with GEMINI AI
================================================================================
Runs continuously, generates threats, enriches them with Gemini AI (score + alert text),
and sends to Backend every few seconds.
"""

import time
import random
import requests
import threading
from datetime import datetime
from pathlib import Path
import sys
import json
import hashlib

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Import Gemini alert generator (fallback if not available)
try:
    from gemini_alert import generate_alert
except ImportError:
    # Fallback if gemini_alert not found
    def generate_alert(threat_type, severity, source, description, score, **kwargs):
        return {
            "title": f"⚠️ {threat_type} – {severity.upper()}",
            "summary": description,
            "recommended_actions": ["Investigate immediately", "Notify ATC"],
            "analysis": f"Anomaly score: {score:.2f}",
            "confidence": score
        }

# Configuration
BACKEND_URL = "http://localhost:3001/api/threats"
LOGIN_URL = "http://localhost:3001/api/auth/login"
THREAT_INTERVAL = 15  # seconds between threats

# Base threat templates (without Gemini score – we'll let Gemini decide or fallback)
THREATS = [
    {"threat_type": "ADS-B Spoofing", "severity": "critical", "source_ip": "192.168.1.45", "description": "Ghost aircraft injected into airspace", "base_score": 0.96},
    {"threat_type": "ACARS Injection", "severity": "high", "source_ip": "10.0.0.23", "description": "Unauthorised bomb threat message", "base_score": 0.87},
    {"threat_type": "GPS Jamming", "severity": "medium", "source_ip": "172.16.8.9", "description": "GPS signal degradation", "base_score": 0.71},
    {"threat_type": "Mode S Hijack", "severity": "critical", "source_ip": "192.168.10.200", "description": "Squawk 7500 detected", "base_score": 0.94},
    {"threat_type": "Ransomware", "severity": "critical", "source_ip": "185.165.29.101", "description": "Encrypting critical files", "base_score": 0.99},
    {"threat_type": "Trojan (Zeus)", "severity": "high", "source_ip": "185.165.29.102", "description": "Credential theft", "base_score": 0.95},
    {"threat_type": "Worm", "severity": "high", "source_ip": "10.0.0.1", "description": "Self-replicating across network", "base_score": 0.88},
    {"threat_type": "Botnet (Mirai)", "severity": "critical", "source_ip": "45.33.22.11", "description": "IoT devices recruited for DDoS", "base_score": 0.97},
]

def get_auth_token():
    """Get JWT token for backend authentication."""
    try:
        resp = requests.post(LOGIN_URL, json={'username': 'elal_admin', 'password': 'shadow123'}, timeout=2)
        if resp.status_code == 200:
            return resp.json().get('accessToken')
    except:
        pass
    return None

def enrich_with_gemini(threat):
    """
    Call Gemini API to generate an alert (score, analysis, recommended actions).
    Returns a dict with 'score', 'gemini_alert', 'confidence'.
    """
    # Try to get Gemini alert (it already includes score and analysis)
    try:
        gemini_result = generate_alert(
            threat_type=threat["threat_type"],
            severity=threat["severity"],
            source=threat["source_ip"],
            description=threat["description"],
            score=threat.get("base_score", 0.5),
            asset_criticality=0.7,
            location="Airspace / Network",
            extra_context={"source": "auto_simulator"}
        )
        # Gemini result contains 'confidence' and 'analysis' etc.
        # Use its 'confidence' as the score (0-1) or keep base score.
        gemini_score = gemini_result.get("confidence", threat.get("base_score", 0.5))
        # Also we can send the whole alert text to frontend via metadata
        return {
            "score": round(gemini_score, 4),
            "gemini_alert": gemini_result,
            "confidence": gemini_result.get("confidence", 0.5)
        }
    except Exception as e:
        print(f"⚠️ Gemini enrichment failed: {e}. Using fallback.")
        # Fallback: use base score and a simple alert
        fallback_alert = {
            "title": f"⚠️ {threat['threat_type']} – {threat['severity'].upper()}",
            "summary": threat["description"],
            "recommended_actions": ["Investigate", "Notify SOC"],
            "analysis": f"Anomaly score: {threat['base_score']:.2f}",
            "confidence": threat["base_score"]
        }
        return {
            "score": threat["base_score"],
            "gemini_alert": fallback_alert,
            "confidence": threat["base_score"]
        }

def send_threat(threat, headers):
    """Send a single threat to backend, enriched with Gemini."""
    # Get Gemini enrichment
    enriched = enrich_with_gemini(threat)
    score = enriched["score"]
    gemini_data = enriched["gemini_alert"]

    # Prepare payload for backend (including Gemini analysis as metadata)
    payload = {
        "threat_type": threat["threat_type"],
        "severity": threat["severity"],
        "source_ip": threat["source_ip"],
        "description": threat["description"],
        "score": score,
        "detected_at": datetime.now().isoformat(),
        "metadata": {
            "gemini_analysis": gemini_data.get("analysis", ""),
            "recommended_actions": gemini_data.get("recommended_actions", []),
            "confidence": enriched["confidence"],
            "title": gemini_data.get("title", "")
        }
    }

    try:
        response = requests.post(BACKEND_URL, json=payload, headers=headers, timeout=2)
        if response.status_code in (200, 201):
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ {threat['threat_type']} | Score: {score:.3f} | Gemini analysis sent")
            return True
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Backend error {response.status_code} for {threat['threat_type']}")
            return False
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Failed to send {threat['threat_type']}: {e}")
        return False

def main():
    print("=" * 70)
    print("🔴 SHADOW NDR – AUTOMATIC THREAT SIMULATOR with GEMINI AI")
    print("=" * 70)
    print(f"Sending threats to backend every {THREAT_INTERVAL} seconds")
    print("Each threat is enriched with Gemini (score + alert text).")
    print("Press Ctrl+C to stop\n")

    # Get auth token
    token = get_auth_token()
    if not token:
        print("❌ Failed to get auth token. Make sure backend is running.")
        return

    headers = {'Authorization': f'Bearer {token}'}
    print("✅ Authenticated with backend\n")

    threat_index = 0
    try:
        while True:
            threat = THREATS[threat_index % len(THREATS)].copy()
            # Randomize IP and description slightly to avoid exact duplicates
            threat["source_ip"] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            threat["description"] = f"{threat['description']} (detected at {datetime.now().strftime('%H:%M:%S')})"
            send_threat(threat, headers)
            threat_index += 1
            time.sleep(THREAT_INTERVAL)
    except KeyboardInterrupt:
        print("\n⏹️ Stopping simulator...")

if __name__ == "__main__":
    main()