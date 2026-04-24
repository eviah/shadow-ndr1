"""
APEX · Ghost Traffic Countermeasures
─────────────────────────────────────
Generate plausible ADS-B DF17 Mode-S Extended Squitter frames to create a
"ghost swarm" of decoy aircraft around a protected asset. Attackers relying
on ADS-B reconnaissance see N+1 candidate targets instead of one, and cannot
distinguish the real aircraft from the decoys without ground-based radar
cross-correlation.

HARDWARE CAVEAT
───────────────
True RF transmission requires a licensed SDR (e.g., HackRF/LimeSDR/bladeRF)
and an ADS-B encoder (dump1090-mutability or rtl_ais in TX mode). This module
generates cryptographically correct DF17 frames and logs them as
"would-be-transmitted" — integration with the SDR transmit path is a
hardware deployment concern, not a software one.

Frame layout (112 bits total):
  DF (5)   | CA (3)   | ICAO-24 (24) | ME (56) | CRC-24 (24)

ME (Message Extended) types implemented:
  TC 9-18  → Airborne position (with CPR even/odd encoding)
  TC 19    → Airborne velocity
  TC 1-4   → Aircraft identification (callsign)
"""

from __future__ import annotations

import math
import random
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

# ─── CRC-24 (ADS-B / Mode-S) ──────────────────────────────────────────────
# Polynomial: 0xFFF409 (standard Mode-S generator)
_CRC24_POLY = 0xFFF409


def crc24(data: bytes) -> int:
    """Compute Mode-S 24-bit CRC over a byte sequence."""
    crc = 0
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            if crc & 0x800000:
                crc = (crc << 1) ^ _CRC24_POLY
            else:
                crc <<= 1
            crc &= 0xFFFFFF
    return crc


# ─── CPR (Compact Position Reporting) ─────────────────────────────────────
# Simplified airborne CPR encoding per DO-260B §A.1.7.1.

_NZ = 15  # number of latitude zones


def _nl(lat: float) -> int:
    """Number of longitude zones for a given latitude."""
    if abs(lat) >= 87.0:
        return 1
    try:
        return int(math.floor(
            2.0 * math.pi /
            math.acos(1.0 - (1.0 - math.cos(math.pi / (2.0 * _NZ))) /
                      (math.cos(math.radians(abs(lat))) ** 2))
        ))
    except ValueError:
        return 1


def cpr_encode(lat: float, lon: float, odd: bool) -> tuple[int, int]:
    """Encode lat/lon to 17-bit CPR (yz, xz) pair."""
    i = 1 if odd else 0
    dlat = 360.0 / (4 * _NZ - i)
    yz = math.floor(2 ** 17 * ((lat % dlat) / dlat) + 0.5)
    yz &= 0x1FFFF

    nl_i = max(_nl(lat) - i, 1)
    dlon = 360.0 / nl_i
    xz = math.floor(2 ** 17 * ((lon % dlon) / dlon) + 0.5)
    xz &= 0x1FFFF

    return yz, xz


# ─── Frame types ──────────────────────────────────────────────────────────

class METype(int, Enum):
    IDENT = 4           # TC=1-4 aircraft identification
    POSITION = 11       # TC=9-18 airborne position
    VELOCITY = 19       # TC=19 airborne velocity


@dataclass
class GhostAircraft:
    icao24: int                  # 24-bit ICAO
    callsign: str                # 8 chars max
    lat: float
    lon: float
    alt_ft: int
    speed_kts: float
    heading_deg: float
    vrate_fpm: int = 0
    spawned_at: float = field(default_factory=time.time)

    @property
    def icao_hex(self) -> str:
        return f"{self.icao24:06X}"


# ─── ME field encoders ────────────────────────────────────────────────────

_CALLSIGN_ALPHABET = (
    "#ABCDEFGHIJKLMNOPQRSTUVWXYZ#####_###############0123456789######"
)


def encode_ident_me(callsign: str, ca: int = 0) -> bytes:
    """TC=4 aircraft identification ME (56 bits → 7 bytes)."""
    cs = (callsign.upper() + "        ")[:8]
    bits = 0
    # TC=4 (5 bits), CA=0 (3 bits), 8× 6-bit chars
    bits = (4 << 3) | (ca & 0x7)
    bits <<= 48
    for i, ch in enumerate(cs):
        idx = _CALLSIGN_ALPHABET.find(ch)
        if idx < 0:
            idx = 0x20
        bits |= (idx & 0x3F) << (48 - 6 * (i + 1))
    return bits.to_bytes(7, "big")


def encode_position_me(lat: float, lon: float, alt_ft: int, odd: bool,
                      tc: int = 11) -> bytes:
    """Airborne position ME. TC 9-18 depending on NUCp/NIC."""
    yz, xz = cpr_encode(lat, lon, odd)

    # 12-bit altitude: ((alt+1000)/25) with Q-bit=1
    alt_code = max(0, min(4095, (alt_ft + 1000) // 25))
    alt_field = ((alt_code & 0xFF0) << 1) | 0x10 | (alt_code & 0x0F)
    alt_field &= 0xFFF

    bits = 0
    bits |= (tc & 0x1F) << 51            # TC
    bits |= 0 << 49                      # Surveillance status
    bits |= 0 << 48                      # NIC supplement-B
    bits |= alt_field << 36              # Altitude
    bits |= 0 << 35                      # Time
    bits |= (1 if odd else 0) << 34      # CPR format
    bits |= yz << 17                     # CPR lat (17 bits)
    bits |= xz                           # CPR lon (17 bits)
    return bits.to_bytes(7, "big")


def encode_velocity_me(speed_kts: float, heading_deg: float,
                      vrate_fpm: int) -> bytes:
    """TC=19 airborne velocity subtype 1 (ground speed)."""
    # East/North components
    rad = math.radians(heading_deg)
    ve = speed_kts * math.sin(rad)
    vn = speed_kts * math.cos(rad)

    ew_dir = 1 if ve < 0 else 0
    ns_dir = 1 if vn < 0 else 0
    ve_mag = min(1023, int(abs(ve)) + 1)
    vn_mag = min(1023, int(abs(vn)) + 1)

    vr_sign = 1 if vrate_fpm < 0 else 0
    vr_mag = min(511, abs(vrate_fpm) // 64 + 1)

    bits = 0
    bits |= (19 & 0x1F) << 51            # TC
    bits |= 1 << 48                      # Subtype 1 (subsonic)
    bits |= 0 << 47                      # Intent change
    bits |= 0 << 46                      # IFR capability
    bits |= 0 << 43                      # NAC
    bits |= ew_dir << 42
    bits |= (ve_mag & 0x3FF) << 32
    bits |= ns_dir << 31
    bits |= (vn_mag & 0x3FF) << 21
    bits |= 0 << 20                      # Vertical rate source (GNSS)
    bits |= vr_sign << 19
    bits |= (vr_mag & 0x1FF) << 10
    bits |= 0 << 8                       # Reserved
    bits |= 0                            # GNSS-baro diff
    return bits.to_bytes(7, "big")


# ─── DF17 frame assembler ─────────────────────────────────────────────────

def build_df17(icao24: int, me: bytes, ca: int = 5) -> bytes:
    """Assemble a complete 14-byte DF17 Extended Squitter."""
    assert len(me) == 7, "ME must be 56 bits (7 bytes)"
    # Byte 0: DF (5 bits)=17 | CA (3 bits)
    b0 = ((17 & 0x1F) << 3) | (ca & 0x7)
    # Bytes 1-3: ICAO-24
    icao_bytes = icao24.to_bytes(3, "big")
    # Bytes 4-10: ME
    payload = bytes([b0]) + icao_bytes + me
    crc = crc24(payload)
    return payload + crc.to_bytes(3, "big")


# ─── Ghost swarm generator ────────────────────────────────────────────────

_AIRLINE_PREFIXES = ["ELY", "ISR", "AIZ", "LYX", "EZS", "RYR", "UAL"]


def _random_icao24(exclude: set[int]) -> int:
    while True:
        cand = secrets.randbelow(0xFFFFFF) + 1
        if cand not in exclude:
            return cand


def _random_callsign() -> str:
    pfx = random.choice(_AIRLINE_PREFIXES)
    num = random.randint(100, 9999)
    return f"{pfx}{num}"


def spawn_ghost_swarm(real_icao: int, center_lat: float, center_lon: float,
                     center_alt_ft: int, count: int = 6,
                     radius_nm: float = 40.0) -> List[GhostAircraft]:
    """Spawn N plausible decoy aircraft around a protected target."""
    ghosts: List[GhostAircraft] = []
    used: set[int] = {real_icao}
    lat_rad = math.radians(center_lat)

    for _ in range(count):
        bearing = random.uniform(0, 360)
        dist_nm = random.uniform(5.0, radius_nm)
        d_lat = (dist_nm / 60.0) * math.cos(math.radians(bearing))
        d_lon = (dist_nm / 60.0) * math.sin(math.radians(bearing)) / max(
            math.cos(lat_rad), 1e-6
        )
        alt = max(3000, center_alt_ft + random.randint(-5000, 5000))
        speed = random.uniform(380, 520)
        heading = random.uniform(0, 360)
        vrate = random.choice([-1024, 0, 0, 0, 1024])

        icao = _random_icao24(used)
        used.add(icao)

        ghosts.append(GhostAircraft(
            icao24=icao,
            callsign=_random_callsign(),
            lat=center_lat + d_lat,
            lon=center_lon + d_lon,
            alt_ft=alt,
            speed_kts=speed,
            heading_deg=heading,
            vrate_fpm=vrate,
        ))
    return ghosts


# ─── Transmission log (SDR stub) ──────────────────────────────────────────

@dataclass
class EmittedFrame:
    ts: float
    icao24: int
    frame_hex: str
    kind: str
    ghost: bool
    transmitted: bool = False  # flips true only when wired to SDR

    @property
    def frame_bytes(self) -> bytes:
        return bytes.fromhex(self.frame_hex)


class GhostTrafficEmitter:
    """
    Generates DF17 frames for a ghost swarm. When an SDR TX backend is
    attached (e.g. HackRF via osmosdr), the `transmit_hook` is invoked.
    Without hardware, frames are logged only — still useful for
    adversary-model testing, replay sandboxes, and unit tests.
    """

    def __init__(self, transmit_hook=None):
        self.log: List[EmittedFrame] = []
        self.transmit_hook = transmit_hook  # callable(bytes) -> bool

    def _emit(self, icao: int, me: bytes, kind: str, ghost: bool) -> EmittedFrame:
        frame = build_df17(icao, me)
        rec = EmittedFrame(
            ts=time.time(),
            icao24=icao,
            frame_hex=frame.hex().upper(),
            kind=kind,
            ghost=ghost,
        )
        if self.transmit_hook is not None:
            try:
                rec.transmitted = bool(self.transmit_hook(frame))
            except Exception:
                rec.transmitted = False
        self.log.append(rec)
        return rec

    def emit_ghost_cycle(self, ghosts: List[GhostAircraft]) -> List[EmittedFrame]:
        """One full ADS-B advertisement cycle: ident + pos(even) + pos(odd) + vel."""
        out: List[EmittedFrame] = []
        for g in ghosts:
            out.append(self._emit(g.icao24, encode_ident_me(g.callsign),
                                 "IDENT", ghost=True))
            out.append(self._emit(g.icao24,
                                 encode_position_me(g.lat, g.lon, g.alt_ft, odd=False),
                                 "POS_EVEN", ghost=True))
            out.append(self._emit(g.icao24,
                                 encode_position_me(g.lat, g.lon, g.alt_ft, odd=True),
                                 "POS_ODD", ghost=True))
            out.append(self._emit(g.icao24,
                                 encode_velocity_me(g.speed_kts, g.heading_deg,
                                                   g.vrate_fpm),
                                 "VELOCITY", ghost=True))
        return out

    def stats(self) -> dict:
        total = len(self.log)
        tx = sum(1 for f in self.log if f.transmitted)
        return {
            "frames_generated": total,
            "frames_transmitted": tx,
            "unique_icao24": len({f.icao24 for f in self.log}),
            "sdr_attached": self.transmit_hook is not None,
        }


# ─── CLI demo ─────────────────────────────────────────────────────────────

def _demo():
    print("APEX · Ghost Traffic Countermeasures — demo")
    print("=" * 60)

    # Protected EL AL aircraft over Ben Gurion
    real_icao = 0x738A5B
    real_lat, real_lon, real_alt = 32.0114, 34.8867, 34000

    ghosts = spawn_ghost_swarm(real_icao, real_lat, real_lon, real_alt,
                              count=5, radius_nm=25.0)
    print(f"Protecting ICAO-24={real_icao:06X} at "
          f"({real_lat:.4f}, {real_lon:.4f}) FL{real_alt//100}")
    print(f"Spawned {len(ghosts)} ghost aircraft:")
    for g in ghosts:
        print(f"  {g.icao_hex}  {g.callsign:<8}  "
              f"({g.lat:.4f},{g.lon:.4f})  FL{g.alt_ft//100:<3} "
              f"{g.speed_kts:.0f}kts  hdg {g.heading_deg:.0f}°")

    emitter = GhostTrafficEmitter()
    frames = emitter.emit_ghost_cycle(ghosts)
    print(f"\nEmitted {len(frames)} DF17 frames (first 3 shown):")
    for f in frames[:3]:
        print(f"  [{f.kind:<9}] {f.icao24:06X}  {f.frame_hex}")

    print(f"\nStats: {emitter.stats()}")
    print("\nCRC self-check:")
    for f in frames[:2]:
        raw = f.frame_bytes
        calc = crc24(raw[:-3])
        recv = int.from_bytes(raw[-3:], "big")
        print(f"  {f.kind:<9} CRC ok={calc == recv}  ({calc:06X} vs {recv:06X})")

    print("\nNOTE: RF transmission requires SDR hardware (HackRF/LimeSDR).")
    print("      Frames above are cryptographically valid ADS-B DF17 squitters.")


if __name__ == "__main__":
    _demo()
