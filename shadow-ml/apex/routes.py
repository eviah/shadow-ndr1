"""
APEX FastAPI router — exposes the four advanced capabilities:

  POST /apex/proof/verify      — neural-symbolic Proof of Breach (Z3)
  POST /apex/ghost/spawn       — ghost-traffic swarm generation
  POST /apex/vault/seal        — shard + encrypt weight blob
  POST /apex/vault/unseal      — threshold-recover weight blob
  POST /apex/swarm/aggregate   — federated aggregation round
  GET  /apex/status            — capability & backend status
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger("shadow.apex")

router = APIRouter(prefix="/apex", tags=["apex"])


# ─── Proof of Breach ──────────────────────────────────────────────────────

class FrameIn(BaseModel):
    t: float
    lat: float
    lon: float
    alt_ft: float
    speed_kts: float
    heading_deg: float
    icao24: int
    callsign: str = ""
    source_sensor_id: str = "unknown"


class ProofRequest(BaseModel):
    kind: str = Field(..., description="BreachKind value")
    frames: List[FrameIn]
    registered_icao: Optional[int] = None
    registered_callsign: Optional[str] = None
    last_known_t: Optional[float] = None
    last_known_lat: Optional[float] = None
    last_known_lon: Optional[float] = None
    neural_score: float = 0.0
    tenant_id: str = "default"


@router.post("/proof/verify")
async def proof_verify(req: ProofRequest) -> Dict[str, Any]:
    try:
        from apex.proof.verifier import (
            BreachKind, ObservedFrame, ProofObligation, get_verifier,
        )
    except ImportError as e:
        raise HTTPException(503, f"verifier unavailable: {e}")

    try:
        kind = BreachKind(req.kind)
    except ValueError:
        raise HTTPException(400, f"invalid kind: {req.kind}")

    frames = [ObservedFrame(**f.model_dump()) for f in req.frames]
    oblig = ProofObligation(
        kind=kind,
        frames=frames,
        registered_icao=req.registered_icao,
        registered_callsign=req.registered_callsign,
        last_known_t=req.last_known_t,
        last_known_lat=req.last_known_lat,
        last_known_lon=req.last_known_lon,
        neural_score=req.neural_score,
        tenant_id=req.tenant_id,
    )

    proof = get_verifier().verify(oblig)
    return {
        "verdict": proof.verdict,
        "kind": proof.kind.value if hasattr(proof.kind, "value") else str(proof.kind),
        "obligation_hash": proof.obligation_hash,
        "solver_ms": proof.solver_ms,
        "neural_score": proof.neural_score,
        "proof_terms": proof.proof_terms,
        "witness": proof.witness,
        "reason": proof.reason,
    }


# ─── Ghost Traffic ────────────────────────────────────────────────────────

class GhostRequest(BaseModel):
    protected_icao: int
    center_lat: float
    center_lon: float
    center_alt_ft: int
    count: int = 6
    radius_nm: float = 40.0


@router.post("/ghost/spawn")
async def ghost_spawn(req: GhostRequest) -> Dict[str, Any]:
    try:
        from apex.deception.ghost_traffic import (
            GhostTrafficEmitter, spawn_ghost_swarm,
        )
    except ImportError as e:
        raise HTTPException(503, f"ghost-traffic unavailable: {e}")

    ghosts = spawn_ghost_swarm(
        real_icao=req.protected_icao,
        center_lat=req.center_lat,
        center_lon=req.center_lon,
        center_alt_ft=req.center_alt_ft,
        count=req.count,
        radius_nm=req.radius_nm,
    )
    emitter = GhostTrafficEmitter()
    frames = emitter.emit_ghost_cycle(ghosts)
    return {
        "ghosts": [
            {
                "icao24": g.icao_hex,
                "callsign": g.callsign,
                "lat": g.lat, "lon": g.lon,
                "alt_ft": g.alt_ft,
                "speed_kts": g.speed_kts,
                "heading_deg": g.heading_deg,
            } for g in ghosts
        ],
        "frames": [
            {"icao24": f"{f.icao24:06X}", "kind": f.kind,
             "hex": f.frame_hex, "transmitted": f.transmitted}
            for f in frames
        ],
        "stats": emitter.stats(),
    }


# ─── Weight Vault (seal / unseal) ─────────────────────────────────────────

_vaults: Dict[str, Any] = {}  # in-memory dev store: model_id → EncryptedModel


class VaultSealRequest(BaseModel):
    model_id: str
    weights_b64: str
    k_threshold: int = 3
    custodians: Dict[str, str]  # name → base64 pubkey


class VaultUnsealRequest(BaseModel):
    model_id: str
    custodian_secrets: Dict[str, str]  # name → base64 secret


@router.post("/vault/seal")
async def vault_seal(req: VaultSealRequest) -> Dict[str, Any]:
    try:
        from apex.quantum.weight_slicing import QuantumWeightVault, KEM_NAME
    except ImportError as e:
        raise HTTPException(503, f"quantum-vault unavailable: {e}")

    try:
        weights = base64.b64decode(req.weights_b64)
        pubs = {k: base64.b64decode(v) for k, v in req.custodians.items()}
    except Exception as e:
        raise HTTPException(400, f"bad base64: {e}")

    vault = QuantumWeightVault(pubs)
    sealed = vault.seal(weights, model_id=req.model_id,
                        k_threshold=req.k_threshold)
    _vaults[req.model_id] = sealed
    return {
        "model_id": sealed.model_id,
        "kem": KEM_NAME,
        "k_threshold": sealed.k_threshold,
        "shards": [s.to_dict() for s in sealed.shards],
        "weight_digest": sealed.weight_digest,
        "ciphertext_bytes": len(sealed.ciphertext),
    }


@router.post("/vault/unseal")
async def vault_unseal(req: VaultUnsealRequest) -> Dict[str, Any]:
    try:
        from apex.quantum.weight_slicing import QuantumWeightVault
    except ImportError as e:
        raise HTTPException(503, f"quantum-vault unavailable: {e}")

    sealed = _vaults.get(req.model_id)
    if sealed is None:
        raise HTTPException(404, f"no sealed model {req.model_id}")

    try:
        secs = {k: base64.b64decode(v) for k, v in req.custodian_secrets.items()}
    except Exception as e:
        raise HTTPException(400, f"bad base64: {e}")

    try:
        weights = QuantumWeightVault.unseal(sealed, secs)
    except ValueError as e:
        raise HTTPException(400, str(e))

    return {
        "model_id": sealed.model_id,
        "weights_b64": base64.b64encode(weights).decode(),
        "weight_digest": sealed.weight_digest,
        "bytes": len(weights),
    }


# ─── Federated Swarm ──────────────────────────────────────────────────────

_aggregators: Dict[str, Any] = {}  # tenant_namespace → SwarmAggregator


class SwarmInitRequest(BaseModel):
    namespace: str = "default"
    dim: int
    l2_clip: float = 1.0
    noise_multiplier: float = 0.8
    learning_rate: float = 1.0
    min_participants: int = 2
    tenants: List[str]


class SwarmUpdateIn(BaseModel):
    tenant_id: str
    round_id: int
    gradient_b64: str
    num_samples: int
    signature_b64: str


class SwarmAggregateRequest(BaseModel):
    namespace: str = "default"
    updates: List[SwarmUpdateIn]


@router.post("/swarm/init")
async def swarm_init(req: SwarmInitRequest) -> Dict[str, Any]:
    try:
        from apex.federated.swarm_forensics import (
            AggregatorConfig, SwarmAggregator,
        )
    except ImportError as e:
        raise HTTPException(503, f"federated unavailable: {e}")

    cfg = AggregatorConfig(
        dim=req.dim, l2_clip=req.l2_clip,
        noise_multiplier=req.noise_multiplier,
        learning_rate=req.learning_rate,
        min_participants=req.min_participants,
    )
    agg = SwarmAggregator(cfg)
    issued = {tid: base64.b64encode(agg.register_tenant(tid)).decode()
              for tid in req.tenants}
    _aggregators[req.namespace] = agg
    return {
        "namespace": req.namespace,
        "dim": req.dim,
        "tenant_secrets_b64": issued,
        "digest": agg.snapshot_digest(),
    }


@router.post("/swarm/aggregate")
async def swarm_aggregate(req: SwarmAggregateRequest) -> Dict[str, Any]:
    try:
        import numpy as np
        from apex.federated.swarm_forensics import GradientUpdate
    except ImportError as e:
        raise HTTPException(503, f"federated unavailable: {e}")

    agg = _aggregators.get(req.namespace)
    if agg is None:
        raise HTTPException(404, f"no aggregator for namespace {req.namespace}")

    updates: List[GradientUpdate] = []
    for u in req.updates:
        try:
            grad = np.frombuffer(base64.b64decode(u.gradient_b64),
                                dtype=np.float32)
        except Exception as e:
            raise HTTPException(400, f"bad gradient b64 for {u.tenant_id}: {e}")
        upd = GradientUpdate(
            tenant_id=u.tenant_id,
            round_id=u.round_id,
            gradient=grad,
            num_samples=u.num_samples,
        )
        try:
            upd.signature = base64.b64decode(u.signature_b64)
        except Exception as e:
            raise HTTPException(400, f"bad signature b64: {e}")
        updates.append(upd)

    try:
        res = agg.aggregate(updates)
    except RuntimeError as e:
        raise HTTPException(400, str(e))

    return {
        "round_id": res.round_id,
        "participants": res.participants,
        "clipped_count": res.clipped_count,
        "noise_sigma": res.noise_sigma,
        "epoch_ms": res.epoch_ms,
        "digest": agg.snapshot_digest(),
    }


# ─── Status ───────────────────────────────────────────────────────────────

@router.get("/status")
async def status() -> Dict[str, Any]:
    caps = {}
    try:
        from apex.proof.verifier import HAVE_Z3
        caps["proof_of_breach"] = {"ok": True, "z3_installed": HAVE_Z3}
    except Exception as e:
        caps["proof_of_breach"] = {"ok": False, "error": str(e)}

    try:
        import apex.deception.ghost_traffic  # noqa: F401
        caps["ghost_traffic"] = {"ok": True, "rf_transmit": False,
                                 "note": "SDR hardware required for TX"}
    except Exception as e:
        caps["ghost_traffic"] = {"ok": False, "error": str(e)}

    try:
        from apex.quantum.weight_slicing import HAVE_KYBER, HAVE_AEAD, KEM_NAME
        caps["quantum_vault"] = {
            "ok": True, "kem": KEM_NAME,
            "post_quantum": HAVE_KYBER, "aead": HAVE_AEAD,
        }
    except Exception as e:
        caps["quantum_vault"] = {"ok": False, "error": str(e)}

    try:
        import apex.federated.swarm_forensics  # noqa: F401
        caps["federated_swarm"] = {"ok": True,
                                   "namespaces": list(_aggregators.keys())}
    except Exception as e:
        caps["federated_swarm"] = {"ok": False, "error": str(e)}

    return {"apex_version": "1.0", "capabilities": caps}
