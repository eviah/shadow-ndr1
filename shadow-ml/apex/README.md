# APEX — Advanced Aviation Security Modules

Four capabilities bolted onto the Shadow-NDR ML service.

| # | Module | What it does | Hardware caveats |
|---|--------|--------------|------------------|
| 1 | `proof/verifier.py`        | Neural-Symbolic Proof of Breach via Z3 SMT solver (ADS-B kinematic, GPS-jump, ICAO-impersonation) | — |
| 2 | `deception/ghost_traffic.py` | Valid ADS-B DF17 Mode-S frames for a ghost swarm around protected aircraft | RF TX needs SDR (HackRF/LimeSDR) |
| 3 | `quantum/weight_slicing.py`  | Shamir-split + Kyber-wrapped AES-GCM weight vault with threshold recovery | `pqcrypto` optional; falls back to HKDF stub (not post-quantum) |
| 4 | `federated/swarm_forensics.py` | FedAvg with DP-Gaussian noise + HMAC-authenticated gradient submissions | — |

## HTTP surface

The `apex/routes.py` router mounts under `/apex/*` in [main.py](../main.py):

```
POST /apex/proof/verify       — submit frames + neural score, get SMT verdict
POST /apex/ghost/spawn        — spawn N ghost aircraft, get DF17 frames
POST /apex/vault/seal         — encrypt+shard a weight blob
POST /apex/vault/unseal       — threshold-recover a sealed blob
POST /apex/swarm/init         — bootstrap an aggregator for a tenant pool
POST /apex/swarm/aggregate    — run one federated round
GET  /apex/status             — capability matrix + backend versions
```

## Running the self-demos

```
python -m apex.proof.verifier
python -m apex.deception.ghost_traffic
python -m apex.quantum.weight_slicing
python -m apex.federated.swarm_forensics
```

## Dependencies

Already in [../requirements.txt](../requirements.txt):

- `z3-solver` — required for proof verification
- `cryptography` — used for AES-GCM (has clean-room fallback)
- `numpy` — federated aggregation
- `pqcrypto` — optional; enables real CRYSTALS-Kyber-768
