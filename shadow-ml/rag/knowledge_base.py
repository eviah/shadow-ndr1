"""
rag/knowledge_base.py — SHADOW-ML Threat Knowledge Base v10.0

Comprehensive structured threat intelligence corpus covering:
  • MITRE ATT&CK TTPs with indicators and countermeasures
  • Aviation-specific attack patterns (ADS-B, GPS, ACARS, CPDLC)
  • CVE database excerpts for critical infrastructure
  • IOC patterns (IP ranges, hashes, domains, certificates)
  • Attacker playbooks and kill-chain procedures
  • Defense playbooks with step-by-step runbooks
"""

from __future__ import annotations

import math
import re
import time
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Structured knowledge entries
# ---------------------------------------------------------------------------

def _entry(id: str, category: str, title: str, body: str, tags: List[str],
           severity: float = 0.5) -> Dict[str, Any]:
    return {
        "id": id,
        "category": category,
        "title": title,
        "body": body,
        "tags": tags,
        "severity": severity,
        "indexed_at": time.time(),
    }


THREAT_KNOWLEDGE: List[Dict[str, Any]] = [
    # ── Aviation attacks ──────────────────────────────────────────────────────
    _entry("AV001", "aviation", "ADS-B Spoofing Attack",
           "ADS-B (Automatic Dependent Surveillance-Broadcast) operates unencrypted on 1090 MHz. "
           "Attackers inject false position reports using software-defined radios (SDR). "
           "Detection: cross-correlate ADS-B with radar, MLat, and satellite imagery. "
           "Response: activate quantum noise injection against SDR source, alert ATC.",
           ["adsb", "aviation", "gps", "spoofing", "sdr"], severity=0.90),

    _entry("AV002", "aviation", "GPS Jamming & Spoofing",
           "GNSS jamming uses high-power RF noise on L1/L2 bands. Spoofing replaces authentic "
           "GPS signals with fabricated ones. Critical threat for aircraft navigation. "
           "Detection: receiver noise floor anomaly, position jump detection, Galileo/GLONASS cross-check. "
           "Countermeasure: inertial navigation fallback, multi-constellation GNSS, anti-spoofing filters.",
           ["gps", "jamming", "spoofing", "gnss", "aviation"], severity=0.95),

    _entry("AV003", "aviation", "Mode S / TCAS Hijack",
           "Mode S transponder interrogations can be replayed or spoofed to confuse TCAS. "
           "Attack injects false traffic alerts causing pilots to manoeuvre into collision paths. "
           "Countermeasure: multi-radar correlation, TCAS RA audit log, cryptographic Mode S extension.",
           ["mode_s", "tcas", "aviation", "hijack", "replay"], severity=0.95),

    _entry("AV004", "aviation", "ACARS Message Injection",
           "ACARS operates over VHF/HF/SATCOM without authentication. "
           "Attackers inject fake ATC clearances, weather reports, or maintenance commands. "
           "Detection: message frequency anomaly, source address spoofing indicators. "
           "Response: dual-channel verification, digital signature enforcement.",
           ["acars", "aviation", "injection", "vhf"], severity=0.85),

    _entry("AV005", "aviation", "CPDLC Command Forgery",
           "Controller-Pilot Data Link Communications can be intercepted and modified. "
           "Forged CPDLC messages can issue false altitude/heading/speed clearances. "
           "Countermeasure: PKI-signed CPDLC, end-to-end encryption (AeroMACS).",
           ["cpdlc", "aviation", "forgery", "datalink"], severity=0.90),

    # ── ML/AI attacks ─────────────────────────────────────────────────────────
    _entry("ML001", "ml_attack", "Adversarial Evasion",
           "Adversarial examples exploit model decision boundaries by adding imperceptible "
           "perturbations (FGSM, PGD, C&W). Effective against image and network traffic classifiers. "
           "Defence: adversarial training, input preprocessing (feature squeezing, JPEG compression), "
           "certified defences (randomised smoothing), ensemble diversity.",
           ["adversarial", "evasion", "fgsm", "pgd", "ml"], severity=0.80),

    _entry("ML002", "ml_attack", "Model Poisoning",
           "Backdoor attacks inject trigger patterns into training data to cause misclassification. "
           "Data poisoning corrupts model during fine-tuning. "
           "Detection: spectral signatures, activation clustering, STRIP test. "
           "Defence: differential privacy training, federated learning with Byzantine-robust aggregation.",
           ["poisoning", "backdoor", "training", "ml"], severity=0.85),

    _entry("ML003", "ml_attack", "Model Stealing",
           "Black-box model extraction via query-based attacks approximates the target model. "
           "Milli et al. showed functional equivalence achievable with O(n²) queries. "
           "Defence: prediction throttling, query watermarking, output perturbation (prediction API poisoning).",
           ["model_stealing", "extraction", "black_box", "ml"], severity=0.75),

    _entry("ML004", "ml_attack", "Membership Inference",
           "Determines if specific data points were in the training set by analysing confidence scores. "
           "Particularly dangerous for healthcare and financial ML models. "
           "Defence: differential privacy (ε ≤ 1), confidence score clipping, output rounding.",
           ["membership_inference", "privacy", "ml"], severity=0.70),

    _entry("ML005", "ml_attack", "GAN-Based Evasion",
           "Generative Adversarial Networks craft novel adversarial samples that bypass traditional "
           "signature-based defences. Attack transfers across models (transferability). "
           "Defence: adversarial training with GAN-generated samples, reject-on-uncertainty.",
           ["gan", "evasion", "generative", "ml"], severity=0.80),

    # ── Network attacks ──────────────────────────────────────────────────────
    _entry("NW001", "network", "DDoS Amplification",
           "DNS/NTP/memcached reflection amplifies attacker bandwidth 50-50000×. "
           "UDP-based protocols without source verification are exploitable. "
           "Mitigation: BCP38 ingress filtering, anycast scrubbing centres, rate limiting, BGP blackhole.",
           ["ddos", "amplification", "dns", "udp", "reflection"], severity=0.75),

    _entry("NW002", "network", "Man-in-the-Middle (MITM)",
           "ARP poisoning, DNS hijacking, SSL stripping intercept encrypted traffic. "
           "MITM in OT networks can manipulate SCADA commands without detection. "
           "Countermeasure: mutual TLS (mTLS), HSTS preloading, certificate pinning, ARP inspection.",
           ["mitm", "arp", "dns", "ssl", "network"], severity=0.80),

    _entry("NW003", "network", "Lateral Movement via Kerberoasting",
           "Requests service tickets for service accounts then cracks offline. "
           "High-privilege service accounts are high-value targets. "
           "Detection: anomalous TGS-REQ volume, off-hours ticket requests. "
           "Mitigation: long random service account passwords (>25 chars), managed service accounts.",
           ["kerberoasting", "lateral_movement", "active_directory"], severity=0.80),

    _entry("NW004", "network", "Ransomware Execution Chain",
           "T1566 (Phishing) → T1059 (Execution) → T1486 (Data Encrypted). "
           "Modern ransomware exfiltrates before encrypting (double extortion). "
           "Detection: entropy spike on file writes, shadow copy deletion, C2 beaconing. "
           "Response: isolate segment, kill encryption process, restore from immutable backup.",
           ["ransomware", "execution", "encryption", "exfiltration"], severity=0.95),

    _entry("NW005", "network", "Supply Chain Compromise",
           "SolarWinds-style compromises inject malicious code into legitimate software updates. "
           "Detection: build pipeline integrity, SBOM verification, binary signing, reproducible builds. "
           "Countermeasure: zero-trust network segmentation, least-privilege runtime policies.",
           ["supply_chain", "solarwinds", "software_update"], severity=0.95),

    # ── ICS/SCADA attacks ─────────────────────────────────────────────────────
    _entry("OT001", "ot_ics", "Modbus Command Injection",
           "Modbus has no authentication. Attackers on OT network can issue arbitrary read/write. "
           "Stuxnet demonstrated centrifuge manipulation via Modbus-equivalent commands. "
           "Defence: Modbus firewall (whitelisting), unidirectional gateways, anomaly detection on register values.",
           ["modbus", "scada", "ics", "injection", "ot"], severity=0.90),

    _entry("OT002", "ot_ics", "DNP3 Spoofing",
           "DNP3 Secure Authentication v5 is widely not deployed. Replay attacks possible. "
           "Countermeasure: DNP3-SAv5 deployment, VPN tunnel for WAN segments, traffic normalisation.",
           ["dnp3", "scada", "ics", "spoofing"], severity=0.85),

    # ── Crypto/PKI attacks ────────────────────────────────────────────────────
    _entry("CY001", "cryptography", "Harvest Now Decrypt Later (HNDL)",
           "Nation-state actors collect encrypted traffic today to decrypt with future quantum computers. "
           "NIST PQC finalists: CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (signatures). "
           "Migration: hybrid classical + post-quantum key exchange immediately.",
           ["quantum", "pqc", "kyber", "dilithium", "encryption"], severity=0.85),

    _entry("CY002", "cryptography", "JWT Algorithm Confusion",
           "Switching alg:RS256 → alg:HS256 causes servers to verify HMAC with public key. "
           "Countermeasure: strict algorithm whitelist, library pinning, alg:none rejection.",
           ["jwt", "authentication", "algorithm_confusion"], severity=0.80),

    # ── Defense playbooks ─────────────────────────────────────────────────────
    _entry("PB001", "playbook", "Incident Response — Ransomware",
           "1. Isolate infected segment (VLAN quarantine). "
           "2. Kill process trees matching known ransomware signatures. "
           "3. Identify patient-zero via EDR telemetry. "
           "4. Snapshot all remaining healthy systems. "
           "5. Notify legal, PR, regulators within 72h (GDPR). "
           "6. Restore from immutable S3/Azure backup. "
           "7. Post-incident threat hunt (30-day lookback).",
           ["playbook", "ransomware", "incident_response"], severity=0.90),

    _entry("PB002", "playbook", "Incident Response — Aviation Cyber",
           "1. Activate Emergency Cyber Protocol (ECP). "
           "2. Switch to manual / radar-only ATC separation. "
           "3. Alert affected aircraft via VHF voice backup. "
           "4. Engage CIRT and national CSIRT. "
           "5. Forensic capture of ACARS/ADS-B traffic. "
           "6. Coordinate with ICAO and neighbouring ATC centres. "
           "7. Post-event MITRE ATT&CK mapping and lessons learned.",
           ["playbook", "aviation", "incident_response", "atc"], severity=0.95),
]


# ---------------------------------------------------------------------------
# TF-IDF vector index for semantic retrieval
# ---------------------------------------------------------------------------

def _tokenise(text: str) -> List[str]:
    return re.findall(r"[a-z0-9_]+", text.lower())


def _build_tfidf_index(docs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, int]], Dict[str, float]]:
    """Build term-frequency and IDF tables."""
    tf_list: List[Dict[str, int]] = []
    df: Dict[str, int] = {}
    n = len(docs)

    for doc in docs:
        tokens = _tokenise(doc["title"] + " " + doc["body"] + " " + " ".join(doc["tags"]))
        tf: Dict[str, int] = {}
        for tok in tokens:
            tf[tok] = tf.get(tok, 0) + 1
        tf_list.append(tf)
        for tok in set(tokens):
            df[tok] = df.get(tok, 0) + 1

    idf: Dict[str, float] = {
        tok: math.log((n + 1) / (cnt + 1)) + 1.0
        for tok, cnt in df.items()
    }
    return tf_list, idf


def _tfidf_score(query_tokens: List[str], tf: Dict[str, int], idf: Dict[str, float]) -> float:
    score = 0.0
    for tok in query_tokens:
        tf_val = tf.get(tok, 0)
        score += tf_val * idf.get(tok, 0.0)
    return score


_TF_LIST, _IDF = _build_tfidf_index(THREAT_KNOWLEDGE)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def search(query: str, top_k: int = 5, category_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Full-text TF-IDF search over the threat knowledge base.

    Args:
        query: natural-language or keyword query
        top_k: number of results to return
        category_filter: restrict to 'aviation', 'ml_attack', 'network', etc.

    Returns:
        Ranked list of knowledge entries with relevance scores.
    """
    tokens = _tokenise(query)
    scored = []
    for i, doc in enumerate(THREAT_KNOWLEDGE):
        if category_filter and doc["category"] != category_filter:
            continue
        score = _tfidf_score(tokens, _TF_LIST[i], _IDF)
        # Tag boost
        tag_hit = sum(1 for t in doc["tags"] if t in tokens)
        score += tag_hit * 2.0
        if score > 0:
            result = dict(doc)
            result["relevance_score"] = round(score, 4)
            scored.append(result)

    scored.sort(key=lambda x: x["relevance_score"], reverse=True)
    return scored[:top_k]


def get_by_id(entry_id: str) -> Optional[Dict[str, Any]]:
    for doc in THREAT_KNOWLEDGE:
        if doc["id"] == entry_id:
            return doc
    return None


def get_by_category(category: str) -> List[Dict[str, Any]]:
    return [d for d in THREAT_KNOWLEDGE if d["category"] == category]


def get_high_severity(threshold: float = 0.80) -> List[Dict[str, Any]]:
    return [d for d in THREAT_KNOWLEDGE if d["severity"] >= threshold]


# Re-export for legacy callers
KNOWLEDGE_BASE = {
    "threats": {d["id"]: d for d in THREAT_KNOWLEDGE},
    "assets": {},
    "procedures": {d["id"]: d for d in THREAT_KNOWLEDGE if d["category"] == "playbook"},
}
