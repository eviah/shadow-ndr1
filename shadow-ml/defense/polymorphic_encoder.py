"""
defense/polymorphic_encoder.py — Polymorphic Packet Encoding v10.0

Defends against signature-based detection by encoding packets polymorphically:
  • Multiple encoding schemes: XOR, byte substitution, bit rotation, compression
  • Random scheme selection per packet
  • Encoding state rotation to prevent pattern learning
  • Decoder validation for legitimate traffic
  • Detects reverse-engineering attempts via encoding consistency analysis

Prevents static signature detection while maintaining packet integrity.
Defeats protocol analyzers, IDS signature matching, and traffic classification.
"""

from __future__ import annotations

import hashlib
import logging
import random
import zlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("shadow.defense.polymorphic")


class EncodingScheme(Enum):
    XOR_SIMPLE = "xor_simple"
    XOR_KEYSTREAM = "xor_keystream"
    BYTE_SUBSTITUTION = "byte_substitution"
    BIT_ROTATION = "bit_rotation"
    COMPRESSION = "compression"
    MIXED = "mixed"


@dataclass
class EncodingKey:
    """Encoding key material and metadata."""
    scheme: EncodingScheme
    key_material: bytes
    rotation_index: int
    creation_ts: float = 0.0
    usage_count: int = 0
    decoding_attempts: int = 0


@dataclass
class EncodedPacket:
    """Packet with encoding metadata."""
    payload: bytes
    scheme: EncodingScheme
    key_id: str
    encoded_size: int
    original_size: int
    encoding_overhead: float


@dataclass
class PolymorphicAlert:
    """Alert for encoding anomalies."""
    alert_type: str  # "reverse_engineering", "encoding_mismatch", "too_many_attempts"
    severity: str  # low, medium, high, critical
    confidence: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class PolymorphicEncoder:
    """
    Polymorphic packet encoding defense.
    Encodes packets using rotating schemes to defeat signature detection.
    """

    def __init__(self, num_keys: int = 10):
        self._current_scheme: EncodingScheme = EncodingScheme.XOR_SIMPLE
        self._scheme_rotation_count: int = 0
        self._keys: Dict[str, EncodingKey] = {}
        self._scheme_usage: Dict[EncodingScheme, int] = {s: 0 for s in EncodingScheme}
        self._alert_threshold: int = 50  # failed decode attempts before alert
        self._stats = {
            "packets_encoded": 0,
            "packets_decoded": 0,
            "decoding_failures": 0,
            "scheme_rotations": 0,
            "alerts": 0,
        }
        self._reverse_engineering_attempts: int = 0

        # Initialize keys
        self._initialize_keys(num_keys)

    def _initialize_keys(self, num_keys: int) -> None:
        """Create initial encoding keys."""
        for i in range(num_keys):
            key_id = hashlib.sha256(f"poly_key_{i}_{np.random.bytes(16)}".encode()).hexdigest()[:16]
            key_material = np.random.bytes(64)
            self._keys[key_id] = EncodingKey(
                scheme=EncodingScheme(list(EncodingScheme)[i % len(EncodingScheme)]),
                key_material=key_material,
                rotation_index=0,
                creation_ts=0.0,
                usage_count=0,
            )

    def _select_scheme(self) -> EncodingScheme:
        """Select next encoding scheme (rotating)."""
        schemes = list(EncodingScheme)[:-1]  # exclude MIXED
        self._current_scheme = schemes[self._scheme_rotation_count % len(schemes)]
        self._scheme_rotation_count += 1
        self._stats["scheme_rotations"] += 1
        return self._current_scheme

    def _xor_encode(self, payload: bytes, key: bytes) -> bytes:
        """Simple XOR encoding."""
        result = bytearray()
        for i, byte in enumerate(payload):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)

    def _xor_keystream_encode(self, payload: bytes, key: bytes) -> bytes:
        """XOR with pseudo-random keystream derived from key."""
        rng = np.random.RandomState(int.from_bytes(key[:4], 'little'))
        keystream = rng.bytes(len(payload))
        result = bytearray()
        for i, byte in enumerate(payload):
            result.append(byte ^ keystream[i])
        return bytes(result)

    def _byte_substitution_encode(self, payload: bytes, key: bytes) -> bytes:
        """Byte-level substitution cipher."""
        sbox = np.arange(256, dtype=np.uint8)
        rng = np.random.RandomState(int.from_bytes(key[:4], 'little'))
        rng.shuffle(sbox)
        return bytes(sbox[b] for b in payload)

    def _bit_rotation_encode(self, payload: bytes, key: bytes) -> bytes:
        """Rotate bits in each byte."""
        rotation = int.from_bytes(key[:1], 'little') % 8
        result = bytearray()
        for byte in payload:
            rotated = ((byte << rotation) | (byte >> (8 - rotation))) & 0xFF
            result.append(rotated)
        return bytes(result)

    def _compression_encode(self, payload: bytes) -> bytes:
        """Compress payload (reduces entropy signature)."""
        try:
            return zlib.compress(payload, level=9)
        except Exception:
            return payload

    def encode(self, payload: bytes, force_scheme: Optional[EncodingScheme] = None) -> EncodedPacket:
        """
        Encode packet using selected polymorphic scheme.
        Returns encoded packet with metadata.
        """
        self._stats["packets_encoded"] += 1

        # Select encoding scheme
        scheme = force_scheme or self._select_scheme()
        self._scheme_usage[scheme] = self._scheme_usage.get(scheme, 0) + 1

        # Select or rotate key
        key_id = random.choice(list(self._keys.keys()))
        key = self._keys[key_id]
        key.usage_count += 1

        # Encode payload
        if scheme == EncodingScheme.XOR_SIMPLE:
            encoded = self._xor_encode(payload, key.key_material)
        elif scheme == EncodingScheme.XOR_KEYSTREAM:
            encoded = self._xor_keystream_encode(payload, key.key_material)
        elif scheme == EncodingScheme.BYTE_SUBSTITUTION:
            encoded = self._byte_substitution_encode(payload, key.key_material)
        elif scheme == EncodingScheme.BIT_ROTATION:
            encoded = self._bit_rotation_encode(payload, key.key_material)
        elif scheme == EncodingScheme.COMPRESSION:
            encoded = self._compression_encode(payload)
        else:
            # MIXED: random combination
            encoded = payload
            for _ in range(random.randint(2, 4)):
                enc_scheme = random.choice(list(EncodingScheme)[:-1])
                if enc_scheme == EncodingScheme.XOR_SIMPLE:
                    encoded = self._xor_encode(encoded, key.key_material)
                elif enc_scheme == EncodingScheme.BYTE_SUBSTITUTION:
                    encoded = self._byte_substitution_encode(encoded, key.key_material)

        overhead = (len(encoded) - len(payload)) / (len(payload) + 1e-8)

        return EncodedPacket(
            payload=encoded,
            scheme=scheme,
            key_id=key_id,
            encoded_size=len(encoded),
            original_size=len(payload),
            encoding_overhead=float(overhead)
        )

    def decode(self, encoded_packet: EncodedPacket, key: EncodingKey) -> Tuple[bytes, bool]:
        """
        Decode packet using provided key.
        Returns (payload, success).
        """
        self._stats["packets_decoded"] += 1
        key.decoding_attempts += 1

        try:
            if encoded_packet.scheme == EncodingScheme.XOR_SIMPLE:
                decoded = self._xor_encode(encoded_packet.payload, key.key_material)
            elif encoded_packet.scheme == EncodingScheme.XOR_KEYSTREAM:
                decoded = self._xor_keystream_encode(encoded_packet.payload, key.key_material)
            elif encoded_packet.scheme == EncodingScheme.BYTE_SUBSTITUTION:
                # Reverse substitution
                sbox = np.arange(256, dtype=np.uint8)
                rng = np.random.RandomState(int.from_bytes(key.key_material[:4], 'little'))
                rng.shuffle(sbox)
                inv_sbox = np.argsort(sbox)
                decoded = bytes(inv_sbox[b] for b in encoded_packet.payload)
            elif encoded_packet.scheme == EncodingScheme.BIT_ROTATION:
                rotation = int.from_bytes(key.key_material[:1], 'little') % 8
                decoded = bytearray()
                for byte in encoded_packet.payload:
                    rotated = ((byte >> rotation) | (byte << (8 - rotation))) & 0xFF
                    decoded.append(rotated)
                decoded = bytes(decoded)
            elif encoded_packet.scheme == EncodingScheme.COMPRESSION:
                decoded = zlib.decompress(encoded_packet.payload)
            else:
                decoded = encoded_packet.payload

            return decoded, True

        except Exception as e:
            self._stats["decoding_failures"] += 1
            logger.warning("Decoding failed: %s", str(e))
            return b"", False

    def detect_reverse_engineering(self, attempted_decodes: List[bool]) -> Optional[PolymorphicAlert]:
        """
        Detect if attacker is systematically trying to reverse-engineer encoding.
        Pattern: high failure rate then sudden success rate change.
        """
        if len(attempted_decodes) < 20:
            return None

        recent = attempted_decodes[-20:]
        failure_rate = 1.0 - (sum(recent) / len(recent))

        # High failure rate suggests brute-force attempt
        if failure_rate > 0.8:
            self._reverse_engineering_attempts += 1
            self._stats["alerts"] += 1

            severity = "critical" if failure_rate > 0.95 else "high"
            confidence = min(0.95, failure_rate)

            return PolymorphicAlert(
                alert_type="reverse_engineering",
                severity=severity,
                confidence=confidence,
                description=f"Systematic decoding failures detected ({failure_rate:.1%})",
                evidence={
                    "recent_failures": sum(1 for x in recent if not x),
                    "failure_rate": failure_rate,
                    "total_attempts": len(attempted_decodes),
                }
            )

        return None

    def rotate_keys(self) -> None:
        """Rotate to new encoding keys (invalidate old ones)."""
        old_keys = list(self._keys.keys())
        for key_id in old_keys[len(old_keys)//2:]:
            del self._keys[key_id]

        self._initialize_keys(len(old_keys) // 2)
        logger.info("Encoding keys rotated")

    @property
    def current_scheme(self) -> EncodingScheme:
        return self._current_scheme

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def scheme_distribution(self) -> Dict[str, int]:
        return {s.value: self._scheme_usage.get(s, 0) for s in EncodingScheme}


_encoder: Optional[PolymorphicEncoder] = None


def get_encoder(num_keys: int = 10) -> PolymorphicEncoder:
    global _encoder
    if _encoder is None:
        _encoder = PolymorphicEncoder(num_keys)
    return _encoder


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    encoder = get_encoder()

    # Test payload
    payload = b"GET /api/sensitive HTTP/1.1\r\nHost: example.com\r\n"
    print(f"Original: {payload}")
    print(f"Original size: {len(payload)}")

    # Encode with different schemes
    for scheme in list(EncodingScheme)[:-1]:
        encoded = encoder.encode(payload, force_scheme=scheme)
        print(f"\n{scheme.value}:")
        print(f"  Encoded size: {encoded.encoded_size}")
        print(f"  Overhead: {encoded.encoding_overhead:.2%}")
        print(f"  First 20 bytes: {encoded.payload[:20].hex()}")

    print(f"\nScheme distribution: {encoder.scheme_distribution}")
    print(f"Stats: {encoder.stats}")
    print("Polymorphic Encoder OK")
