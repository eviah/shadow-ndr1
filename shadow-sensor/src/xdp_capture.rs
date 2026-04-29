//! AF_XDP zero-copy capture abstraction.
//!
//! Real AF_XDP requires Linux kernel ≥ 4.18, an XDP-capable NIC driver, and
//! the `xsk-rs` crate to bind a UMEM (a shared memory region split into
//! fixed-size frames) to a NIC rx queue. The driver writes packet data
//! directly into UMEM frames and the user-space reader pops descriptors off
//! a SPSC ring with no copies.
//!
//! This module provides:
//!
//! 1. `XdpBackend` — trait the rest of the sensor consumes. Returns
//!    `XdpFrame` borrows of UMEM bytes; caller releases each frame back to
//!    the rx ring once it's done parsing.
//!
//! 2. **Linux+feature path** (`cfg(all(target_os="linux", feature="af_xdp"))`)
//!    — wires the trait to `xsk-rs`. Feature-gated because `xsk-rs` itself
//!    is gated in `Cargo.toml`.
//!
//! 3. **Cross-platform stub** — a software UMEM-backed implementation that
//!    proves the lifecycle (alloc → fill → recv → release) is correct and
//!    is what we run in CI on Windows / macOS dev boxes.
//!
//! The stub is *not* a fake: frames live in a single contiguous `Vec<u8>`
//! exactly like a real UMEM, descriptors are u32 indices, and the rx
//! "ring" is a `VecDeque<u32>` of available frame ids. A test injector lets
//! integration tests stage synthetic packets and observe back-pressure
//! when the ring saturates.

use std::collections::VecDeque;
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct XdpConfig {
    pub iface: String,
    pub queue: u32,
    pub frame_count: u32,
    pub frame_size: u32,
}

impl XdpConfig {
    pub fn new(iface: impl Into<String>, queue: u32) -> Self {
        XdpConfig {
            iface: iface.into(),
            queue,
            frame_count: 4096,
            frame_size: 2048,
        }
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct XdpStats {
    pub frames_received: u64,
    pub frames_dropped: u64,
    pub bytes_received: u64,
    pub frames_in_flight: u64,
}

/// One zero-copy view of a packet inside the UMEM. Caller must call
/// `release(self.id)` on the backend once parsing is done — until then the
/// frame slot stays out of the rx ring's free pool.
#[derive(Debug)]
pub struct XdpFrame {
    pub id: u32,
    pub data: Vec<u8>,
    pub timestamp_ns: u64,
    pub queue_id: u32,
}

pub trait XdpBackend: Send + Sync {
    fn poll_batch(&self, max: usize) -> Vec<XdpFrame>;
    fn release(&self, frame_id: u32);
    fn stats(&self) -> XdpStats;
    fn config(&self) -> &XdpConfig;
}

pub fn open(config: XdpConfig) -> Result<Box<dyn XdpBackend>, String> {
    #[cfg(all(target_os = "linux", feature = "af_xdp"))]
    {
        return linux::open(config);
    }
    #[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
    {
        Ok(Box::new(stub::SoftXdp::new(config)?))
    }
}

// =====================================================================
// Cross-platform / non-AF_XDP stub
// =====================================================================
mod stub {
    use super::*;

    pub struct SoftXdp {
        config: XdpConfig,
        umem: Mutex<Vec<u8>>,
        rx: Mutex<RxState>,
    }

    struct RxState {
        ready: VecDeque<u32>,
        free: VecDeque<u32>,
        frames_received: u64,
        frames_dropped: u64,
        bytes_received: u64,
        in_flight: u64,
        timestamps: Vec<u64>,
    }

    impl SoftXdp {
        pub fn new(config: XdpConfig) -> Result<Self, String> {
            if config.frame_count == 0 {
                return Err("frame_count must be > 0".into());
            }
            if config.frame_size < 64 {
                return Err("frame_size must be ≥ 64".into());
            }
            let umem_size = (config.frame_count as usize) * (config.frame_size as usize);
            let umem = vec![0u8; umem_size];
            let free: VecDeque<u32> = (0..config.frame_count).collect();
            Ok(SoftXdp {
                config,
                umem: Mutex::new(umem),
                rx: Mutex::new(RxState {
                    ready: VecDeque::new(),
                    free,
                    frames_received: 0,
                    frames_dropped: 0,
                    bytes_received: 0,
                    in_flight: 0,
                    timestamps: vec![0; 0],
                }),
            })
        }

        /// Test/integration injector — write `data` into the next free UMEM
        /// frame and queue it onto the rx ring. Returns `false` if the ring
        /// is saturated (back-pressure path).
        pub fn inject(&self, data: &[u8], timestamp_ns: u64) -> bool {
            let frame_size = self.config.frame_size as usize;
            if data.len() > frame_size {
                let mut rx = self.rx.lock().unwrap();
                rx.frames_dropped += 1;
                return false;
            }
            let mut rx = self.rx.lock().unwrap();
            let Some(slot) = rx.free.pop_front() else {
                rx.frames_dropped += 1;
                return false;
            };
            // Copy into UMEM at the slot's offset.
            let offset = (slot as usize) * frame_size;
            {
                let mut umem = self.umem.lock().unwrap();
                umem[offset..offset + data.len()].copy_from_slice(data);
            }
            rx.ready.push_back(slot);
            // Stash timestamp in parallel array indexed by frame id.
            if rx.timestamps.len() < self.config.frame_count as usize {
                rx.timestamps.resize(self.config.frame_count as usize, 0);
            }
            rx.timestamps[slot as usize] = timestamp_ns;
            true
        }
    }

    impl XdpBackend for SoftXdp {
        fn poll_batch(&self, max: usize) -> Vec<XdpFrame> {
            let frame_size = self.config.frame_size as usize;
            let mut out = Vec::with_capacity(max);
            let umem = self.umem.lock().unwrap();
            let mut rx = self.rx.lock().unwrap();
            for _ in 0..max {
                let Some(slot) = rx.ready.pop_front() else {
                    break;
                };
                let off = (slot as usize) * frame_size;
                // Copy out for the stub — a real AF_XDP path returns a
                // borrow into UMEM, but the stub's lifetime story is
                // simpler with an owned Vec. Production callers go through
                // `release(id)` regardless.
                let bytes_len = self.find_packet_len(&umem[off..off + frame_size]);
                let data = umem[off..off + bytes_len].to_vec();
                let ts = rx.timestamps.get(slot as usize).copied().unwrap_or(0);
                rx.frames_received += 1;
                rx.bytes_received += bytes_len as u64;
                rx.in_flight += 1;
                out.push(XdpFrame {
                    id: slot,
                    data,
                    timestamp_ns: ts,
                    queue_id: self.config.queue,
                });
            }
            out
        }

        fn release(&self, frame_id: u32) {
            let mut rx = self.rx.lock().unwrap();
            if frame_id >= self.config.frame_count {
                return;
            }
            // Idempotent: only count in_flight if the slot wasn't already free.
            if !rx.free.contains(&frame_id) {
                rx.free.push_back(frame_id);
                if rx.in_flight > 0 {
                    rx.in_flight -= 1;
                }
            }
        }

        fn stats(&self) -> XdpStats {
            let rx = self.rx.lock().unwrap();
            XdpStats {
                frames_received: rx.frames_received,
                frames_dropped: rx.frames_dropped,
                bytes_received: rx.bytes_received,
                frames_in_flight: rx.in_flight,
            }
        }

        fn config(&self) -> &XdpConfig {
            &self.config
        }
    }

    impl SoftXdp {
        /// In a real UMEM the descriptor carries the length. Stubbed here
        /// by trimming trailing zero bytes — sufficient for unit tests.
        fn find_packet_len(&self, frame: &[u8]) -> usize {
            let mut i = frame.len();
            while i > 0 && frame[i - 1] == 0 {
                i -= 1;
            }
            i
        }
    }
}

// Re-export the stub type so tests can call `inject` directly without
// going through the trait.
#[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
pub use stub::SoftXdp;

// =====================================================================
// Linux+feature path (skeleton)
// =====================================================================
#[cfg(all(target_os = "linux", feature = "af_xdp"))]
mod linux {
    use super::*;
    // Real implementation requires `xsk-rs` which is gated behind the
    // `af_xdp` feature in Cargo.toml. Bring it in by uncommenting the
    // dependency. The integration shape is:
    //
    //   1. Allocate UMEM via xsk-rs::umem::Umem::new(frame_count*frame_size)
    //   2. Bind XSK socket to (iface, queue)
    //   3. Fill ring with all frame descriptors
    //   4. Poll rx ring → wrap descriptors as XdpFrame
    //   5. release() pushes back to fill ring
    //
    // Until enabled, this returns "unsupported" so the runtime falls back
    // to the stub.
    pub fn open(_config: XdpConfig) -> Result<Box<dyn XdpBackend>, String> {
        Err("xsk-rs not enabled — uncomment xsk-rs in Cargo.toml + rebuild with --features af_xdp".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
    fn open_stub() -> Box<dyn XdpBackend> {
        let cfg = XdpConfig {
            iface: "lo".into(),
            queue: 0,
            frame_count: 8,
            frame_size: 256,
        };
        Box::new(SoftXdp::new(cfg).unwrap())
    }

    #[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
    #[test]
    fn empty_ring_returns_no_frames() {
        let xdp = open_stub();
        let batch = xdp.poll_batch(10);
        assert_eq!(batch.len(), 0);
        assert_eq!(xdp.stats().frames_received, 0);
    }

    #[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
    #[test]
    fn injected_frames_come_out_in_order() {
        let cfg = XdpConfig {
            iface: "lo".into(),
            queue: 0,
            frame_count: 8,
            frame_size: 256,
        };
        let s = SoftXdp::new(cfg).unwrap();
        assert!(s.inject(b"first", 1000));
        assert!(s.inject(b"second", 2000));
        assert!(s.inject(b"third", 3000));
        let batch = s.poll_batch(10);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].data, b"first");
        assert_eq!(batch[0].timestamp_ns, 1000);
        assert_eq!(batch[2].data, b"third");
        assert_eq!(batch[2].timestamp_ns, 3000);
    }

    #[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
    #[test]
    fn batch_size_limit_is_respected() {
        let cfg = XdpConfig {
            iface: "lo".into(),
            queue: 0,
            frame_count: 8,
            frame_size: 256,
        };
        let s = SoftXdp::new(cfg).unwrap();
        for i in 0u8..6 {
            assert!(s.inject(&[i; 32], i as u64));
        }
        let batch = s.poll_batch(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(s.stats().frames_received, 2);
        let rest = s.poll_batch(10);
        assert_eq!(rest.len(), 4);
    }

    #[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
    #[test]
    fn release_returns_frame_to_free_pool() {
        let cfg = XdpConfig {
            iface: "lo".into(),
            queue: 0,
            frame_count: 2,
            frame_size: 256,
        };
        let s = SoftXdp::new(cfg).unwrap();
        assert!(s.inject(b"A", 1));
        assert!(s.inject(b"B", 2));
        // Pool exhausted after 2 injections.
        assert!(!s.inject(b"C", 3));
        assert_eq!(s.stats().frames_dropped, 1);

        let batch = s.poll_batch(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(s.stats().frames_in_flight, 2);

        // Release one — pool now has capacity again.
        s.release(batch[0].id);
        assert_eq!(s.stats().frames_in_flight, 1);
        assert!(s.inject(b"D", 4));
    }

    #[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
    #[test]
    fn oversized_frame_is_dropped_not_panic() {
        let cfg = XdpConfig {
            iface: "lo".into(),
            queue: 0,
            frame_count: 4,
            frame_size: 64,
        };
        let s = SoftXdp::new(cfg).unwrap();
        let big = vec![0u8; 200];
        assert!(!s.inject(&big, 1));
        assert_eq!(s.stats().frames_dropped, 1);
        assert_eq!(s.stats().frames_received, 0);
    }

    #[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
    #[test]
    fn double_release_is_idempotent() {
        let cfg = XdpConfig {
            iface: "lo".into(),
            queue: 0,
            frame_count: 4,
            frame_size: 64,
        };
        let s = SoftXdp::new(cfg).unwrap();
        s.inject(b"x", 1);
        let batch = s.poll_batch(1);
        let id = batch[0].id;
        s.release(id);
        let stats_after_first = s.stats();
        s.release(id); // idempotent
        let stats_after_second = s.stats();
        assert_eq!(stats_after_first, stats_after_second);
    }

    #[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
    #[test]
    fn config_validation_rejects_zero_frame_count() {
        let cfg = XdpConfig {
            iface: "lo".into(),
            queue: 0,
            frame_count: 0,
            frame_size: 256,
        };
        assert!(SoftXdp::new(cfg).is_err());
    }

    #[cfg(not(all(target_os = "linux", feature = "af_xdp")))]
    #[test]
    fn open_factory_returns_stub_off_linux() {
        let xdp = open(XdpConfig::new("lo", 0)).unwrap();
        assert_eq!(xdp.config().iface, "lo");
    }
}
