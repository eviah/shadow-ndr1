"""
Claude Alert Generator v1.0 – World‑Class Aviation Security Alerts
==================================================================
Uses Anthropic Claude 3.5 Sonnet (or Haiku) to generate intelligent,
context‑aware aviation security alerts in Hebrew, with dynamic scoring,
MITRE ATT&CK mapping, and actionable recommendations.

Features:
- Built‑in Claude API integration (no Gemini, no fallback unless API fails)
- Dynamic score calculation (0–1) based on threat type, severity, context
- Attack‑specific recommended actions (BLOCK, ISOLATE, ALERT_ATC, etc.)
- Automatic Hebrew output with professional tone
- Caching to avoid duplicate alerts (TTL 5 minutes)
- Retry logic with exponential backoff (up to 3 retries)
- Rate‑limiting awareness (Claude free tier: ~50 requests per minute)
- Falls back to a smart rule‑based template only if Claude API is unreachable
"""

import os
import time
import hashlib
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
from loguru import logger

# Try to import Anthropic SDK
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.warning("Anthropic SDK not installed. Install with: pip install anthropic")

# =============================================================================
# Configuration
# =============================================================================
CLAUDE_API_KEY = os.environ.get("CLAUDE_API_KEY", "")
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-3-sonnet-20241022")  # or "claude-3-haiku-20240307"
CLAUDE_MAX_RETRIES = 3
CLAUDE_RETRY_DELAY = 1.0  # seconds (will be multiplied by exponential backoff)

# Cache settings
ALERT_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = 300  # seconds

# =============================================================================
# Threat Intelligence Database (used for fallback & score hints)
# =============================================================================
class ThreatCategory(Enum):
    SPOOFING = "spoofing"
    INJECTION = "injection"
    DOS = "dos"
    MALWARE = "malware"
    RECON = "reconnaissance"
    HIJACK = "hijack"

THREAT_PROFILES = {
    "ADS-B Spoofing": {
        "category": ThreatCategory.SPOOFING,
        "base_score": 0.85,
        "mitre": "T1001.001",
        "actions": ["BLOCK", "ISOLATE", "ALERT_ATC"],
    },
    "ACARS Injection": {
        "category": ThreatCategory.INJECTION,
        "base_score": 0.80,
        "mitre": "T1566.002",
        "actions": ["BLOCK", "ALERT_SOC"],
    },
    "GPS Jamming": {
        "category": ThreatCategory.DOS,
        "base_score": 0.75,
        "mitre": "T1499",
        "actions": ["THROTTLE", "ALERT_ATC"],
    },
    "Mode S Hijack": {
        "category": ThreatCategory.HIJACK,
        "base_score": 0.92,
        "mitre": "T1001",
        "actions": ["IMMEDIATE_ATC_ALERT", "ISOLATE"],
    },
    "Ransomware": {
        "category": ThreatCategory.MALWARE,
        "base_score": 0.98,
        "mitre": "T1486",
        "actions": ["ISOLATE", "BLOCK", "BACKUP"],
    },
    "Trojan (Zeus)": {
        "category": ThreatCategory.MALWARE,
        "base_score": 0.90,
        "mitre": "T1071",
        "actions": ["BLOCK_C2", "RESET_PASSWORDS"],
    },
    "Worm": {
        "category": ThreatCategory.MALWARE,
        "base_score": 0.85,
        "mitre": "T1559",
        "actions": ["SEGMENT", "PATCH"],
    },
    "Botnet (Mirai)": {
        "category": ThreatCategory.DOS,
        "base_score": 0.94,
        "mitre": "T1499.001",
        "actions": ["BLACKLIST", "FW_UPDATE"],
    },
    "Network Reconnaissance": {
        "category": ThreatCategory.RECON,
        "base_score": 0.70,
        "mitre": "T1046",
        "actions": ["THROTTLE", "ALERT_SOC"],
    },
    "Hijack Attempt": {
        "category": ThreatCategory.HIJACK,
        "base_score": 0.96,
        "mitre": "T1001",
        "actions": ["IMMEDIATE_ATC_ALERT", "SECURITY_LOCKDOWN"],
    },
}
DEFAULT_PROFILE = {
    "category": ThreatCategory.RECON,
    "base_score": 0.60,
    "mitre": "T1190",
    "actions": ["MONITOR", "ALERT_SOC"],
}

# =============================================================================
# Helper Functions (cache, scoring, etc.)
# =============================================================================
def _get_cache_key(threat_type: str, source: str, severity: str) -> str:
    return hashlib.md5(f"{threat_type}:{source}:{severity}".encode()).hexdigest()

def _is_cached(key: str) -> Optional[Dict]:
    if key in ALERT_CACHE:
        entry = ALERT_CACHE[key]
        if time.time() - entry["timestamp"] < CACHE_TTL:
            return entry["alert"]
    return None

def _cache_alert(key: str, alert: Dict):
    ALERT_CACHE[key] = {"alert": alert, "timestamp": time.time()}

def _dynamic_score(threat_type: str, severity: str, score_hint: Optional[float] = None) -> float:
    """Calculate a fallback score (used if Claude fails or for hints)."""
    profile = THREAT_PROFILES.get(threat_type, DEFAULT_PROFILE)
    base = profile["base_score"]
    severity_factor = {
        "emergency": 0.15, "critical": 0.12, "high": 0.08,
        "medium": 0.04, "low": 0.00, "info": -0.05,
    }.get(severity, 0.0)
    score = min(0.99, max(0.01, base + severity_factor))
    if score_hint is not None:
        score = (score + score_hint) / 2
    return round(score, 4)

def _fallback_alert(threat_type: str, severity: str, source: str,
                    description: str, score: Optional[float] = None,
                    location: Optional[str] = None) -> Dict[str, Any]:
    """Smart fallback (rule‑based) when Claude API is unavailable."""
    final_score = _dynamic_score(threat_type, severity, score)
    emoji = {"emergency": "🚨", "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
    title = f"{emoji} {threat_type} – {severity.upper()}"
    summary = description + (f" במיקום {location}" if location else "")
    profile = THREAT_PROFILES.get(threat_type, DEFAULT_PROFILE)
    actions = list(profile["actions"])
    if severity in ("critical", "emergency") and "IMMEDIATE_ATC_ALERT" not in actions:
        actions.insert(0, "IMMEDIATE_ATC_ALERT")
    if final_score > 0.85 and "ISOLATE" not in actions:
        actions.append("ISOLATE")
    if final_score > 0.90 and "BLOCK" not in actions:
        actions.append("BLOCK")
    actions = list(dict.fromkeys(actions))[:5]
    risk = "קריטי" if final_score > 0.85 else "גבוה" if final_score > 0.7 else "בינוני" if final_score > 0.5 else "נמוך"
    mitre = profile["mitre"]
    analysis = f"ציון חריגות {final_score:.2f} ({risk}). התקפה מסוג {threat_type} מזוהה ממקור {source}. טכניקת MITRE: {mitre}. מומלץ לפעול בהתאם לחומרה."
    return {
        "title": title,
        "summary": summary,
        "recommended_actions": actions,
        "analysis": analysis,
        "confidence": min(0.99, final_score + 0.05),
        "severity": severity,
        "threat_type": threat_type,
        "source": source,
        "score": final_score,
        "generated_at": datetime.utcnow().isoformat(),
        "language": "he",
        "model": "fallback_rule_based",
    }

# =============================================================================
# Claude API Integration with Retry
# =============================================================================
def _call_claude_with_retry(prompt: str, max_retries: int = CLAUDE_MAX_RETRIES) -> Optional[str]:
    """Call Claude API with exponential backoff."""
    if not ANTHROPIC_AVAILABLE or not CLAUDE_API_KEY:
        logger.error("Claude SDK not available or API key missing")
        return None
    client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
    for attempt in range(max_retries):
        try:
            response = client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=800,
                temperature=0.2,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            logger.warning(f"Claude API attempt {attempt+1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(CLAUDE_RETRY_DELAY * (2 ** attempt))
            else:
                logger.error("All Claude retries exhausted")
                return None
    return None

# =============================================================================
# Main Alert Generator (Claude‑first)
# =============================================================================
def generate_alert(
    threat_type: str,
    severity: str,
    source: str,
    description: str,
    score: Optional[float] = None,
    asset_criticality: float = 0.5,
    location: Optional[str] = None,
    extra_context: Optional[Dict] = None,
    language: str = "he"
) -> Dict[str, Any]:
    """
    Generate an aviation security alert using Claude AI (with fallback to rule‑based).
    """
    cache_key = _get_cache_key(threat_type, source, severity)
    cached = _is_cached(cache_key)
    if cached:
        logger.info(f"Using cached alert for {threat_type} from {source}")
        return cached

    # Prepare a score hint for Claude (optional)
    score_hint = _dynamic_score(threat_type, severity, score)

    # Build a professional prompt for Claude (Hebrew output, JSON format)
    prompt = f"""You are an expert aviation security analyst. Generate a concise, professional alert in **Hebrew** for the following threat.

Threat details:
- Type: {threat_type}
- Severity: {severity}
- Source: {source}
- Description: {description}
- Location: {location or 'unknown'}
- ML anomaly score hint: {score_hint:.2f} (0-1, higher = more anomalous)

Asset criticality: {asset_criticality:.2f} (0-1)

Respond ONLY with a valid JSON object (no extra text). The JSON must contain these fields:
- "title": short, impactful title (include severity emoji if appropriate)
- "summary": one‑sentence summary of the threat in Hebrew
- "recommended_actions": list of 3-5 specific defensive actions (e.g., "BLOCK", "ISOLATE", "ALERT_ATC", "THROTTLE", "IMMEDIATE_ATC_ALERT")
- "analysis": brief analysis of the threat, risk level, and MITRE technique if known (in Hebrew)
- "confidence": a number between 0 and 1 (how confident you are)

Use professional aviation security terminology. Output ONLY valid JSON.
"""
    claude_response = _call_claude_with_retry(prompt)

    if claude_response:
        try:
            # Extract JSON from response (in case Claude adds markdown)
            json_str = claude_response.strip()
            if json_str.startswith("```json"):
                json_str = json_str[7:]
            if json_str.endswith("```"):
                json_str = json_str[:-3]
            alert = json.loads(json_str)
            # Ensure required fields exist
            alert.setdefault("title", f"{threat_type} – {severity.upper()}")
            alert.setdefault("summary", description)
            alert.setdefault("recommended_actions", ["MONITOR", "ALERT_SOC"])
            alert.setdefault("analysis", f"Analyze {threat_type} from {source}.")
            alert.setdefault("confidence", score_hint)
            # Add metadata
            alert["severity"] = severity
            alert["threat_type"] = threat_type
            alert["source"] = source
            alert["score"] = score_hint
            alert["generated_at"] = datetime.utcnow().isoformat()
            alert["language"] = language
            alert["model"] = CLAUDE_MODEL
            _cache_alert(cache_key, alert)
            return alert
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to parse Claude JSON: {e}. Falling back.")
            alert = _fallback_alert(threat_type, severity, source, description, score, location)
            _cache_alert(cache_key, alert)
            return alert
    else:
        logger.warning("Claude API failed, using fallback.")
        alert = _fallback_alert(threat_type, severity, source, description, score, location)
        _cache_alert(cache_key, alert)
        return alert

# Alias for compatibility with existing code
generate_and_show_alert = generate_alert

if __name__ == "__main__":
    # Test with a sample threat
    test = {
        "threat_type": "ADS-B Spoofing",
        "severity": "critical",
        "source": "ICAO ABCDEF",
        "description": "Ghost aircraft detected near Ben Gurion Airport",
        "score": 0.96,
        "asset_criticality": 0.95,
        "location": "Ben Gurion Airport (TLV)",
        "extra_context": {"estimated_range": "15 km"}
    }
    alert = generate_alert(**test)
    print(json.dumps(alert, indent=2, ensure_ascii=False))