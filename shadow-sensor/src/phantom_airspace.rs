//! Phantom Airspace — Autonomous Honey-Aircraft Propagation
//!
//! Virtual aircraft fleet that emits Mode-S/ADS-B squitters into the local
//! protocol space. When an attacker probes one of the phantoms (e.g., scans
//! the spoofed control channel, replies to a simulated TCAS interrogation, or
//! attempts a man-in-the-middle on the ground/air datalink), the engine
//! propagates *new* phantoms in a tactical radius around the probe so the
//! attacker keeps following decoys instead of finding real assets.
//!
//! The protocol emulation is intentionally low-fidelity — enough to fool a
//! pcap-driven scanner or a Shodan-style fingerprinter, not a full RF
//! transmitter. The output of `tick()` is a byte-array stream that downstream
//! transports (ZeroMQ, mock SDR sink, decoy interface) can broadcast.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// ICAO 24-bit address (3 bytes).
pub type Icao24 = [u8; 3];

/// One virtual aircraft.
#[derive(Clone, Debug)]
pub struct PhantomAircraft {
    pub icao: Icao24,
    pub callsign: String,
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub alt_ft: i32,
    pub heading_deg: f32,
    pub speed_kt: f32,
    pub vrate_fpm: i32,
    pub squawk: u16,
    pub spawned_at: u64,
    /// True once an attacker has interacted with this phantom.
    pub probed: bool,
    /// Per-phantom propagation budget. Each probe consumes one unit.
    pub propagation_budget: u8,
}

/// Probe event observed against a phantom.
#[derive(Clone, Debug)]
pub struct ProbeEvent {
    pub icao: Icao24,
    pub source: String,
    pub kind: ProbeKind,
    pub timestamp: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    /// TCAS-style interrogation reply.
    TcasInterrogation,
    /// ADS-B squitter being queried back.
    AdsbReply,
    /// Mode-S identification request.
    ModeSIdent,
    /// Datalink (ACARS-shaped) ping.
    DatalinkPing,
}

/// Engine state.
pub struct PhantomAirspace {
    fleet: Arc<RwLock<HashMap<Icao24, PhantomAircraft>>>,
    /// Center of our protected airspace (Tel Aviv FIR by default).
    home_lat: f64,
    home_lon: f64,
    /// Maximum simultaneous phantoms before propagation is throttled.
    max_fleet: usize,
    /// Per-probe propagation factor: how many new phantoms we spawn around
    /// the attacker's last probe.
    propagation_factor: u8,
}

impl PhantomAirspace {
    /// Construct a phantom airspace centered on (lat, lon). Defaults to
    /// Ben-Gurion Airport (LLBG, 32.0114N 34.8867E).
    pub fn new(home_lat: f64, home_lon: f64) -> Self {
        PhantomAirspace {
            fleet: Arc::new(RwLock::new(HashMap::new())),
            home_lat,
            home_lon,
            max_fleet: 256,
            propagation_factor: 3,
        }
    }

    pub fn for_llbg() -> Self {
        Self::new(32.0114, 34.8867)
    }

    pub async fn fleet_size(&self) -> usize {
        self.fleet.read().await.len()
    }

    /// Inject N initial phantoms within a given radius (km).
    pub async fn seed(&self, count: usize, radius_km: f64) {
        for i in 0..count {
            let phantom = self.synthesize(i as u32, radius_km);
            self.fleet.write().await.insert(phantom.icao, phantom);
        }
    }

    /// Advance simulation by `dt_secs` seconds. Returns the broadcast frames
    /// for this tick (one ADS-B squitter per active phantom).
    pub async fn tick(&self, dt_secs: f64) -> Vec<Vec<u8>> {
        let mut fleet = self.fleet.write().await;
        let mut frames = Vec::with_capacity(fleet.len());
        for ph in fleet.values_mut() {
            // Update kinematics (great-circle approximation, flat-earth at
            // these scales).
            let theta = (ph.heading_deg as f64).to_radians();
            let dist_nm = (ph.speed_kt as f64) * dt_secs / 3600.0;
            let dist_deg = dist_nm / 60.0;
            ph.lat_deg += theta.cos() * dist_deg;
            ph.lon_deg +=
                theta.sin() * dist_deg / (ph.lat_deg.to_radians().cos().max(1e-6));
            ph.alt_ft = (ph.alt_ft as f64 + (ph.vrate_fpm as f64) * dt_secs / 60.0) as i32;

            frames.push(encode_adsb_position_squitter(ph));
        }
        frames
    }

    /// Record a probe event. Returns the propagated ICAOs (newly spawned).
    pub async fn observe_probe(&self, event: ProbeEvent) -> Vec<Icao24> {
        let mut new_icaos = Vec::new();

        let (lat, lon, alt, should_propagate) = {
            let mut fleet = self.fleet.write().await;
            let ph = match fleet.get_mut(&event.icao) {
                Some(p) => p,
                None => return new_icaos,
            };
            ph.probed = true;
            let propagate = ph.propagation_budget > 0;
            if propagate {
                ph.propagation_budget -= 1;
            }
            (ph.lat_deg, ph.lon_deg, ph.alt_ft, propagate)
        };

        if !should_propagate {
            return new_icaos;
        }

        let cur_size = self.fleet.read().await.len();
        if cur_size >= self.max_fleet {
            return new_icaos;
        }

        let factor = match event.kind {
            // TCAS replies are rare and high-confidence — propagate aggressively.
            ProbeKind::TcasInterrogation => self.propagation_factor + 2,
            ProbeKind::AdsbReply => self.propagation_factor,
            ProbeKind::ModeSIdent => self.propagation_factor,
            ProbeKind::DatalinkPing => self.propagation_factor.saturating_sub(1).max(1),
        };

        let mut fleet = self.fleet.write().await;
        for k in 0..factor {
            if fleet.len() >= self.max_fleet {
                break;
            }
            let phantom = self.spawn_near(lat, lon, alt, k as u32 + event.timestamp as u32);
            new_icaos.push(phantom.icao);
            fleet.insert(phantom.icao, phantom);
        }
        new_icaos
    }

    fn synthesize(&self, idx: u32, radius_km: f64) -> PhantomAircraft {
        // Deterministic-but-spread-out placement: stride by golden-ratio angle.
        let theta = (idx as f64) * 2.399_963_2_f64; // ~137.5°
        let r_km = radius_km * ((idx as f64) * 0.137).fract().sqrt();
        let dlat = (r_km / 111.0) * theta.cos();
        let dlon = (r_km / (111.0 * self.home_lat.to_radians().cos().max(1e-6))) * theta.sin();
        PhantomAircraft {
            icao: synth_icao(idx),
            callsign: synth_callsign(idx),
            lat_deg: self.home_lat + dlat,
            lon_deg: self.home_lon + dlon,
            alt_ft: 25_000 + ((idx as i32) * 137) % 12_000,
            heading_deg: ((idx as f32) * 47.0) % 360.0,
            speed_kt: 380.0 + ((idx % 9) as f32) * 12.0,
            vrate_fpm: 0,
            squawk: 1000 + (idx as u16 % 6000),
            spawned_at: now_secs(),
            probed: false,
            propagation_budget: 3,
        }
    }

    fn spawn_near(&self, lat: f64, lon: f64, alt: i32, salt: u32) -> PhantomAircraft {
        let theta = (salt as f64) * 1.234_567;
        let r_km = 8.0 + ((salt % 17) as f64);
        let dlat = (r_km / 111.0) * theta.cos();
        let dlon = (r_km / (111.0 * lat.to_radians().cos().max(1e-6))) * theta.sin();
        PhantomAircraft {
            icao: synth_icao(salt.wrapping_mul(2654435761)),
            callsign: synth_callsign(salt),
            lat_deg: lat + dlat,
            lon_deg: lon + dlon,
            alt_ft: alt + ((salt as i32) % 4000) - 2000,
            heading_deg: ((salt as f32) * 17.0) % 360.0,
            speed_kt: 360.0 + ((salt % 7) as f32) * 14.0,
            vrate_fpm: 0,
            squawk: 1000 + (salt as u16 % 6000),
            spawned_at: now_secs(),
            probed: false,
            propagation_budget: 2,
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn synth_icao(seed: u32) -> Icao24 {
    let mixed = seed.wrapping_mul(0x9E37_79B9) ^ 0xA1B2_C3D4;
    [
        ((mixed >> 16) & 0xFF) as u8,
        ((mixed >> 8) & 0xFF) as u8,
        (mixed & 0xFF) as u8,
    ]
}

fn synth_callsign(idx: u32) -> String {
    const PREFIXES: &[&str] = &["ELY", "ISR", "AUA", "LYE", "BAW", "DLH", "TUI", "EZY"];
    let prefix = PREFIXES[(idx as usize) % PREFIXES.len()];
    format!("{}{:04}", prefix, 1000 + (idx % 9000))
}

/// Build an ADS-B DF17 position extended squitter (Mode-S) frame.
/// Layout (14 bytes / 112 bits):
///   DF=17 (5b) | CA=5 (3b) | ICAO (24b) | TC=11 (5b) | ... | CRC (24b)
/// We emit a structurally valid frame with placeholder CPR-encoded position.
pub fn encode_adsb_position_squitter(ph: &PhantomAircraft) -> Vec<u8> {
    let mut frame = vec![0u8; 14];
    // DF=17, CA=5
    frame[0] = (17 << 3) | 5;
    frame[1] = ph.icao[0];
    frame[2] = ph.icao[1];
    frame[3] = ph.icao[2];

    // ME field: TC=11 (airborne pos, baro alt), surveillance status=0
    frame[4] = 11 << 3;
    // Encoded altitude: q-bit set, 25-foot resolution.
    let alt_code = (((ph.alt_ft + 1000) / 25).clamp(0, 0xFFF)) as u16;
    frame[5] = ((alt_code >> 4) & 0xFF) as u8;
    frame[6] = ((alt_code & 0x0F) << 4) as u8 | 0x80; // F=1, even encoding

    // CPR-encoded latitude/longitude (17 bits each). We pack them as two
    // 17-bit big-endian integers across bytes 7..11 with the trailing 6 bits
    // unused. Real CPR encoding lives in the parser; for honey-aircraft a
    // structurally valid payload is sufficient to fool fingerprinters.
    let lat_cpr = cpr_encode(ph.lat_deg, true);
    let lon_cpr = cpr_encode(ph.lon_deg, true);
    frame[6] |= ((lat_cpr >> 15) & 0x03) as u8;
    frame[7] = ((lat_cpr >> 7) & 0xFF) as u8;
    frame[8] = ((lat_cpr & 0x7F) << 1) as u8 | (((lon_cpr >> 16) & 0x01) as u8);
    frame[9] = ((lon_cpr >> 8) & 0xFF) as u8;
    frame[10] = (lon_cpr & 0xFF) as u8;

    // Bytes 11..14 hold the Mode-S CRC. We use Mode-S parity (poly 0xFFF409).
    let crc = mode_s_crc(&frame[..11]);
    frame[11] = ((crc >> 16) & 0xFF) as u8;
    frame[12] = ((crc >> 8) & 0xFF) as u8;
    frame[13] = (crc & 0xFF) as u8;
    frame
}

fn cpr_encode(coord: f64, even: bool) -> u32 {
    // Simplified CPR-style 17-bit encoding. Full RTCA DO-260B encoding uses
    // distinct dlat/dlon zones (15 vs 19 latitude bands); for honey-aircraft
    // we wrap the coordinate into [0,1) and quantize to 17 bits.
    let nb = if even { 60.0 } else { 59.0 };
    let _ = nb;
    let x = coord.fract().abs();
    ((x * (1u32 << 17) as f64) as u32) & 0x1FFFF
}

/// Mode-S 24-bit CRC, polynomial 0x1FFF409.
pub fn mode_s_crc(bytes: &[u8]) -> u32 {
    const POLY: u32 = 0x1FFF409;
    let mut reg: u32 = 0;
    for &b in bytes {
        for bit in (0..8).rev() {
            let in_bit = ((b >> bit) & 1) as u32;
            let top = (reg >> 23) & 1;
            reg = ((reg << 1) | in_bit) & 0x00FF_FFFF;
            if (top ^ in_bit) != 0 {
                reg ^= POLY & 0x00FF_FFFF;
            }
        }
    }
    reg & 0x00FF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn seed_creates_fleet() {
        let air = PhantomAirspace::for_llbg();
        air.seed(8, 50.0).await;
        assert_eq!(air.fleet_size().await, 8);
    }

    #[tokio::test]
    async fn tick_emits_one_frame_per_phantom() {
        let air = PhantomAirspace::for_llbg();
        air.seed(4, 25.0).await;
        let frames = air.tick(1.0).await;
        assert_eq!(frames.len(), 4);
        for f in &frames {
            assert_eq!(f.len(), 14);
            // DF should be 17 (extended squitter).
            assert_eq!((f[0] >> 3) & 0x1F, 17);
        }
    }

    #[tokio::test]
    async fn probe_propagates_new_decoys() {
        let air = PhantomAirspace::for_llbg();
        air.seed(2, 25.0).await;
        let icao = {
            let fleet = air.fleet.read().await;
            *fleet.keys().next().unwrap()
        };
        let n0 = air.fleet_size().await;
        let new = air
            .observe_probe(ProbeEvent {
                icao,
                source: "scanner-A".to_string(),
                kind: ProbeKind::TcasInterrogation,
                timestamp: 1,
            })
            .await;
        let n1 = air.fleet_size().await;
        assert!(!new.is_empty(), "TCAS probe must spawn at least one decoy");
        assert!(n1 > n0, "fleet must grow after a probe");
    }

    #[tokio::test]
    async fn propagation_budget_is_finite() {
        let air = PhantomAirspace::for_llbg();
        air.seed(1, 10.0).await;
        let icao = {
            let fleet = air.fleet.read().await;
            *fleet.keys().next().unwrap()
        };
        // Hammer the same phantom 10 times — budget=3 means at most 3 propagation
        // events (then 0 new spawns).
        let mut spawns = Vec::new();
        for ts in 0..10u64 {
            let n = air
                .observe_probe(ProbeEvent {
                    icao,
                    source: "scanner-X".to_string(),
                    kind: ProbeKind::AdsbReply,
                    timestamp: ts,
                })
                .await;
            spawns.push(n.len());
        }
        let nonzero = spawns.iter().filter(|n| **n > 0).count();
        assert!(
            nonzero <= 3,
            "propagation budget must cap repeat probes ({:?})",
            spawns
        );
    }

    #[test]
    fn mode_s_crc_is_deterministic() {
        let a = mode_s_crc(&[0x8D, 0x40, 0x62, 0x1D, 0x58, 0xC3]);
        let b = mode_s_crc(&[0x8D, 0x40, 0x62, 0x1D, 0x58, 0xC3]);
        assert_eq!(a, b);
        let c = mode_s_crc(&[0x8D, 0x40, 0x62, 0x1D, 0x58, 0xC4]);
        assert_ne!(a, c);
    }

    #[test]
    fn synth_icao_is_unique_for_distinct_seeds() {
        let a = synth_icao(0);
        let b = synth_icao(1);
        let c = synth_icao(2);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }
}
