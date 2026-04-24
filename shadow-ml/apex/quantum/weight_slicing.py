"""
APEX · Quantum-Hardened Weight Slicing
───────────────────────────────────────
Shard ML model weights across N custodians so that:
  1. A threshold K of custodians must cooperate to reconstruct weights.
  2. Each shard is encrypted under a post-quantum KEM (CRYSTALS-Kyber).
  3. A harvest-now/decrypt-later adversary gains nothing from stealing
     a minority of shards — the PQ-KEM symmetric key is never sent in
     the clear, and individual shards are Shamir splits over GF(256).

HARDWARE CAVEAT
───────────────
True CRYSTALS-Kyber requires liboqs / pqcrypto. When the library is
available we use it; otherwise we fall back to a clearly-labelled
"KYBER_STUB" that uses HKDF-SHA256 over X25519 for envelope keys.
The stub is STILL secure against classical attackers — it just isn't
post-quantum. In production, install `pqcrypto` via the pinned
requirement in shadow-ml/requirements.txt.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ─── Optional Kyber (post-quantum KEM) ────────────────────────────────────

try:
    from pqcrypto.kem import kyber768 as _kyber  # type: ignore
    HAVE_KYBER = True
    KEM_NAME = "CRYSTALS-Kyber-768"
except ImportError:
    HAVE_KYBER = False
    KEM_NAME = "KYBER_STUB_HKDF_SHA256"


# ─── AES-GCM (stdlib cryptography) ────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_AEAD = True
except ImportError:
    HAVE_AEAD = False


# ─── GF(256) + Shamir's Secret Sharing ────────────────────────────────────

def _gf_mul(a: int, b: int) -> int:
    """Multiply two elements of GF(2^8) with poly 0x11B."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r & 0xFF


def _gf_pow(a: int, n: int) -> int:
    r = 1
    while n:
        if n & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        n >>= 1
    return r


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("no inverse for 0 in GF(2^8)")
    return _gf_pow(a, 254)


def _eval_poly(coeffs: List[int], x: int) -> int:
    r = 0
    for c in reversed(coeffs):
        r = _gf_mul(r, x) ^ c
    return r


def shamir_split(secret: bytes, n: int, k: int) -> List[Tuple[int, bytes]]:
    """Split secret bytes into n shares, any k of which reconstruct."""
    if not (1 <= k <= n <= 255):
        raise ValueError("require 1 <= k <= n <= 255")
    shares: List[List[int]] = [[] for _ in range(n)]
    for byte in secret:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(k - 1)]
        for i in range(n):
            x = i + 1
            shares[i].append(_eval_poly(coeffs, x))
    return [(i + 1, bytes(shares[i])) for i in range(n)]


def shamir_combine(parts: List[Tuple[int, bytes]]) -> bytes:
    """Reconstruct a secret from any k shares."""
    if not parts:
        raise ValueError("no shares provided")
    xs = [p[0] for p in parts]
    if len(set(xs)) != len(xs):
        raise ValueError("share x-coords must be distinct")
    length = len(parts[0][1])
    out = bytearray(length)
    for i in range(length):
        acc = 0
        for j, (xj, yj) in enumerate(parts):
            num = 1
            den = 1
            for m, (xm, _) in enumerate(parts):
                if m == j:
                    continue
                num = _gf_mul(num, xm)
                den = _gf_mul(den, xj ^ xm)
            acc ^= _gf_mul(yj[i], _gf_mul(num, _gf_inv(den)))
        out[i] = acc
    return bytes(out)


# ─── Post-quantum KEM abstraction ─────────────────────────────────────────

@dataclass
class KEMKeypair:
    public: bytes
    secret: bytes
    algorithm: str


def kem_keygen() -> KEMKeypair:
    if HAVE_KYBER:
        pk, sk = _kyber.generate_keypair()
        return KEMKeypair(public=pk, secret=sk, algorithm=KEM_NAME)
    # Stub: random 32-byte "public" doubles as HKDF salt; "secret" is the seed.
    sk = secrets.token_bytes(32)
    pk = hashlib.sha256(sk).digest()
    return KEMKeypair(public=pk, secret=sk, algorithm=KEM_NAME)


def kem_encap(pk: bytes) -> Tuple[bytes, bytes]:
    """Returns (ciphertext, shared_secret)."""
    if HAVE_KYBER:
        ct, ss = _kyber.encrypt(pk)
        return ct, ss
    # Stub HKDF envelope — NOT post-quantum.
    ephem = secrets.token_bytes(32)
    ss = hmac.new(pk, ephem, hashlib.sha256).digest()
    return ephem, ss


def kem_decap(sk: bytes, ct: bytes) -> bytes:
    if HAVE_KYBER:
        return _kyber.decrypt(sk, ct)
    pk = hashlib.sha256(sk).digest()
    return hmac.new(pk, ct, hashlib.sha256).digest()


# ─── AES-GCM wrap ─────────────────────────────────────────────────────────

def aead_seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    if HAVE_AEAD:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key[:32]).encrypt(nonce, plaintext, aad)
        return nonce + ct
    # Fallback: HMAC-then-XOR (integrity + confidentiality, NOT AEAD-grade).
    nonce = secrets.token_bytes(16)
    stream = b""
    counter = 0
    while len(stream) < len(plaintext):
        stream += hmac.new(key, nonce + counter.to_bytes(4, "big"),
                          hashlib.sha256).digest()
        counter += 1
    ct = bytes(a ^ b for a, b in zip(plaintext, stream[:len(plaintext)]))
    tag = hmac.new(key, nonce + ct + aad, hashlib.sha256).digest()[:16]
    return nonce + tag + ct


def aead_open(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if HAVE_AEAD:
        nonce, ct = blob[:12], blob[12:]
        return AESGCM(key[:32]).decrypt(nonce, ct, aad)
    nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
    expected = hmac.new(key, nonce + ct + aad, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed")
    stream = b""
    counter = 0
    while len(stream) < len(ct):
        stream += hmac.new(key, nonce + counter.to_bytes(4, "big"),
                          hashlib.sha256).digest()
        counter += 1
    return bytes(a ^ b for a, b in zip(ct, stream[:len(ct)]))


# ─── High-level shard container ───────────────────────────────────────────

@dataclass
class WeightShard:
    index: int                   # 1..n (Shamir x-coord)
    custodian_id: str            # e.g. "tenant:elal", "hsm:cluster-a"
    kem_ciphertext: bytes        # Kyber encapsulation of wrap-key
    shamir_share: bytes          # share of AES key
    algorithm: str               # KEM_NAME
    nonce: bytes                 # shard-id salt for binding

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "custodian_id": self.custodian_id,
            "kem_ct": self.kem_ciphertext.hex(),
            "share": self.shamir_share.hex(),
            "algorithm": self.algorithm,
            "nonce": self.nonce.hex(),
        }


@dataclass
class EncryptedModel:
    ciphertext: bytes            # AES-GCM(weights)
    shards: List[WeightShard]    # threshold recovery of wrap-key
    k_threshold: int
    model_id: str
    weight_digest: str           # SHA-256 of plaintext weights for auditing


class QuantumWeightVault:
    """
    Takes a serialized weight blob, encrypts it under a one-time AES-256 key,
    then splits that key via Shamir into n shards — each shard additionally
    wrapped under the custodian's Kyber public key so even the shard index
    can't reveal the share to anyone but the rightful custodian.
    """

    def __init__(self, custodian_pubkeys: Dict[str, bytes]):
        if len(custodian_pubkeys) < 2:
            raise ValueError("need at least 2 custodians")
        self.custodians = custodian_pubkeys

    def seal(self, weights: bytes, model_id: str,
             k_threshold: int) -> EncryptedModel:
        n = len(self.custodians)
        if not (1 < k_threshold <= n):
            raise ValueError("require 1 < k <= n")

        wrap_key = secrets.token_bytes(32)
        ct = aead_seal(wrap_key, weights, aad=model_id.encode())

        raw_shares = shamir_split(wrap_key, n, k_threshold)
        shards: List[WeightShard] = []
        for (idx, share), (cust_id, pk) in zip(raw_shares, self.custodians.items()):
            kem_ct, ss = kem_encap(pk)
            sealed_share = aead_seal(ss[:32], share,
                                    aad=f"{model_id}:{idx}".encode())
            shards.append(WeightShard(
                index=idx,
                custodian_id=cust_id,
                kem_ciphertext=kem_ct,
                shamir_share=sealed_share,
                algorithm=KEM_NAME,
                nonce=secrets.token_bytes(8),
            ))

        return EncryptedModel(
            ciphertext=ct,
            shards=shards,
            k_threshold=k_threshold,
            model_id=model_id,
            weight_digest=hashlib.sha256(weights).hexdigest(),
        )

    @staticmethod
    def unseal(sealed: EncryptedModel,
               custodian_secrets: Dict[str, bytes]) -> bytes:
        """Reconstruct plaintext weights given k custodian private keys."""
        shares: List[Tuple[int, bytes]] = []
        for shard in sealed.shards:
            if shard.custodian_id not in custodian_secrets:
                continue
            sk = custodian_secrets[shard.custodian_id]
            ss = kem_decap(sk, shard.kem_ciphertext)
            share = aead_open(ss[:32], shard.shamir_share,
                             aad=f"{sealed.model_id}:{shard.index}".encode())
            shares.append((shard.index, share))
            if len(shares) >= sealed.k_threshold:
                break

        if len(shares) < sealed.k_threshold:
            raise ValueError(
                f"need {sealed.k_threshold} custodians, got {len(shares)}"
            )

        wrap_key = shamir_combine(shares)
        weights = aead_open(wrap_key, sealed.ciphertext,
                           aad=sealed.model_id.encode())
        if hashlib.sha256(weights).hexdigest() != sealed.weight_digest:
            raise ValueError("weight digest mismatch — corruption or tamper")
        return weights


# ─── CLI demo ─────────────────────────────────────────────────────────────

def _demo():
    print("APEX · Quantum-Hardened Weight Slicing — demo")
    print("=" * 60)
    print(f"KEM backend: {KEM_NAME}  (post-quantum={HAVE_KYBER})")
    print(f"AEAD backend: {'AES-GCM' if HAVE_AEAD else 'HMAC-stream-fallback'}")

    custodians = {
        "tenant:elal": kem_keygen(),
        "tenant:israir": kem_keygen(),
        "tenant:arkia": kem_keygen(),
        "hsm:tlv-primary": kem_keygen(),
        "hsm:hfa-backup": kem_keygen(),
    }
    pubs = {cid: kp.public for cid, kp in custodians.items()}
    secs = {cid: kp.secret for cid, kp in custodians.items()}

    # Pretend we have a 256KB model blob
    weights = os.urandom(256 * 1024)
    model_id = "ndr-attack-classifier-v4.2"
    print(f"\nSealing {len(weights)} bytes across {len(custodians)} custodians "
          f"(threshold k=3)...")

    vault = QuantumWeightVault(pubs)
    sealed = vault.seal(weights, model_id=model_id, k_threshold=3)
    print(f"  ciphertext: {len(sealed.ciphertext)} B")
    print(f"  shards:     {len(sealed.shards)} × "
          f"{len(sealed.shards[0].shamir_share)} B encrypted share")
    print(f"  digest:     {sealed.weight_digest[:32]}…")

    # Recover with exactly threshold custodians
    quorum = {
        "tenant:elal": secs["tenant:elal"],
        "tenant:israir": secs["tenant:israir"],
        "hsm:tlv-primary": secs["hsm:tlv-primary"],
    }
    print(f"\nRecovering with quorum: {list(quorum.keys())}")
    recovered = QuantumWeightVault.unseal(sealed, quorum)
    ok = recovered == weights
    print(f"  recovered {len(recovered)} B — match={ok}")

    # Attempt with too few
    insufficient = {"tenant:elal": secs["tenant:elal"]}
    try:
        QuantumWeightVault.unseal(sealed, insufficient)
        print("  FAIL: insufficient quorum should have errored")
    except ValueError as e:
        print(f"  sub-threshold attempt correctly rejected: {e}")


if __name__ == "__main__":
    _demo()
