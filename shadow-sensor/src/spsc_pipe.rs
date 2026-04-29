//! Lock-Free SPSC Ring + mmap-Backed Protobuf Pipeline
//!
//! Single-producer / single-consumer ring buffer over a memory-mapped file.
//! Designed to move pre-encoded (prost) protobuf packet records from the
//! capture thread to the processor thread without locking, system calls, or
//! heap allocation per record.
//!
//! Layout in shared memory:
//!
//!   [ Header (cacheline-padded head + tail + caps) | Slot[0] | Slot[1] | ... ]
//!
//! Each slot has:
//!
//!   [ u32 length | payload bytes... ]
//!
//! Producer writes into slot at `tail % capacity`, then publishes via
//! `tail.store(Release)`. Consumer reads `head` and `tail` (Acquire), copies
//! the payload, then `head.store(Release)`. This forms an `Acquire`/`Release`
//! pair that gives the consumer a happens-before view of the producer's write.

use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const CACHELINE: usize = 64;

/// Shared header laid out at the start of the mmap region. Both `head` and
/// `tail` are cacheline-padded so producer/consumer don't ping-pong.
#[repr(C, align(64))]
pub struct RingHeader {
    pub magic: u64,                 // 0xAVI0_RING
    pub version: u32,
    pub capacity: u32,              // number of slots (must be power of two)
    pub slot_size: u32,             // bytes per slot (incl. length prefix)
    pub _pad0: [u8; CACHELINE - 24],
    pub tail: AtomicU64,            // producer writes
    pub _pad1: [u8; CACHELINE - 8],
    pub head: AtomicU64,            // consumer writes
    pub _pad2: [u8; CACHELINE - 8],
}

const RING_MAGIC: u64 = 0x4156_4930_5249_4E47; // "AVI0RING"

/// SPSC pipe. The producer holds an `SpscProducer`; the consumer holds an
/// `SpscConsumer`. Both reference the same mmap region but enforce SPSC
/// discipline at the type level.
pub struct SpscPipe {
    _mmap: memmap2::MmapMut,
    base: *mut u8,
    capacity: usize,
    slot_size: usize,
}

unsafe impl Send for SpscPipe {}
unsafe impl Sync for SpscPipe {}

impl SpscPipe {
    /// Create a new pipe backed by the given file (truncates and resizes it).
    pub fn create<P: AsRef<Path>>(
        path: P,
        capacity: usize,
        slot_size: usize,
    ) -> std::io::Result<(SpscProducer, SpscConsumer)> {
        assert!(capacity.is_power_of_two(), "capacity must be power of two");
        assert!(slot_size >= 8, "slot_size too small");

        let total = std::mem::size_of::<RingHeader>() + capacity * slot_size;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(total as u64)?;

        let mmap = unsafe { memmap2::MmapOptions::new().len(total).map_mut(&file)? };
        let base = mmap.as_ptr() as *mut u8;

        unsafe {
            let header = base as *mut RingHeader;
            (*header).magic = RING_MAGIC;
            (*header).version = 1;
            (*header).capacity = capacity as u32;
            (*header).slot_size = slot_size as u32;
            (*header).tail = AtomicU64::new(0);
            (*header).head = AtomicU64::new(0);
        }

        let pipe = SpscPipe {
            _mmap: mmap,
            base,
            capacity,
            slot_size,
        };
        Ok(SpscPipe::split(pipe))
    }

    fn split(self) -> (SpscProducer, SpscConsumer) {
        let arc = std::sync::Arc::new(self);
        (
            SpscProducer { inner: arc.clone() },
            SpscConsumer { inner: arc },
        )
    }

    fn header(&self) -> &RingHeader {
        unsafe { &*(self.base as *const RingHeader) }
    }

    fn slot_ptr(&self, idx: usize) -> *mut u8 {
        unsafe {
            self.base
                .add(std::mem::size_of::<RingHeader>())
                .add(idx * self.slot_size)
        }
    }
}

pub struct SpscProducer {
    inner: std::sync::Arc<SpscPipe>,
}

pub struct SpscConsumer {
    inner: std::sync::Arc<SpscPipe>,
}

impl SpscProducer {
    /// Try to push a payload. Returns `false` if the ring is full (no copy).
    pub fn try_push(&self, payload: &[u8]) -> bool {
        let h = self.inner.header();
        let cap = self.inner.capacity as u64;
        let max_payload = self.inner.slot_size - 4;
        if payload.len() > max_payload {
            return false;
        }

        let tail = h.tail.load(Ordering::Relaxed);
        let head = h.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= cap {
            return false; // full
        }

        let idx = (tail & (cap - 1)) as usize;
        let slot = self.inner.slot_ptr(idx);
        unsafe {
            // length prefix
            let len_bytes = (payload.len() as u32).to_le_bytes();
            std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), slot, 4);
            // payload
            if !payload.is_empty() {
                std::ptr::copy_nonoverlapping(payload.as_ptr(), slot.add(4), payload.len());
            }
        }
        h.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }
}

impl SpscConsumer {
    /// Try to pop the next payload into `out`. Returns `Some(len)` on success.
    pub fn try_pop(&self, out: &mut Vec<u8>) -> Option<usize> {
        let h = self.inner.header();
        let cap = self.inner.capacity as u64;

        let head = h.head.load(Ordering::Relaxed);
        let tail = h.tail.load(Ordering::Acquire);
        if head == tail {
            return None; // empty
        }

        let idx = (head & (cap - 1)) as usize;
        let slot = self.inner.slot_ptr(idx);
        let len = unsafe {
            let mut buf = [0u8; 4];
            std::ptr::copy_nonoverlapping(slot, buf.as_mut_ptr(), 4);
            u32::from_le_bytes(buf) as usize
        };
        out.clear();
        out.reserve(len);
        unsafe {
            let dst = out.as_mut_ptr();
            std::ptr::copy_nonoverlapping(slot.add(4), dst, len);
            out.set_len(len);
        }
        h.head.store(head.wrapping_add(1), Ordering::Release);
        Some(len)
    }

    /// Number of records currently available to consume.
    pub fn pending(&self) -> u64 {
        let h = self.inner.header();
        let tail = h.tail.load(Ordering::Acquire);
        let head = h.head.load(Ordering::Relaxed);
        tail.wrapping_sub(head)
    }
}

/// Minimal protobuf record (prost-derivable). Kept here as a hand-rolled
/// encoder so we don't pull a build.rs dependency for a single message.
///
/// Wire format (proto3-compatible):
///   field 1 (timestamp_ns,  varint)
///   field 2 (src_ip,        bytes)
///   field 3 (dst_ip,        bytes)
///   field 4 (src_port,      varint)
///   field 5 (dst_port,      varint)
///   field 6 (proto,         varint)
///   field 7 (payload,       bytes)
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PacketRecord {
    pub timestamp_ns: u64,
    pub src_ip: Vec<u8>,
    pub dst_ip: Vec<u8>,
    pub src_port: u32,
    pub dst_port: u32,
    pub proto: u32,
    pub payload: Vec<u8>,
}

impl PacketRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.payload.len());
        write_varint_field(&mut out, 1, self.timestamp_ns);
        write_bytes_field(&mut out, 2, &self.src_ip);
        write_bytes_field(&mut out, 3, &self.dst_ip);
        write_varint_field(&mut out, 4, self.src_port as u64);
        write_varint_field(&mut out, 5, self.dst_port as u64);
        write_varint_field(&mut out, 6, self.proto as u64);
        write_bytes_field(&mut out, 7, &self.payload);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        let mut rec = PacketRecord::default();
        let mut i = 0usize;
        while i < buf.len() {
            let (tag, n) = read_varint(&buf[i..])?;
            i += n;
            let field = (tag >> 3) as u32;
            let wire = (tag & 0x7) as u32;
            match (field, wire) {
                (1, 0) => {
                    let (v, n) = read_varint(&buf[i..])?;
                    rec.timestamp_ns = v;
                    i += n;
                }
                (2, 2) => {
                    let (len, n) = read_varint(&buf[i..])?;
                    i += n;
                    rec.src_ip = buf[i..i + len as usize].to_vec();
                    i += len as usize;
                }
                (3, 2) => {
                    let (len, n) = read_varint(&buf[i..])?;
                    i += n;
                    rec.dst_ip = buf[i..i + len as usize].to_vec();
                    i += len as usize;
                }
                (4, 0) => {
                    let (v, n) = read_varint(&buf[i..])?;
                    rec.src_port = v as u32;
                    i += n;
                }
                (5, 0) => {
                    let (v, n) = read_varint(&buf[i..])?;
                    rec.dst_port = v as u32;
                    i += n;
                }
                (6, 0) => {
                    let (v, n) = read_varint(&buf[i..])?;
                    rec.proto = v as u32;
                    i += n;
                }
                (7, 2) => {
                    let (len, n) = read_varint(&buf[i..])?;
                    i += n;
                    rec.payload = buf[i..i + len as usize].to_vec();
                    i += len as usize;
                }
                _ => return None,
            }
        }
        Some(rec)
    }
}

fn write_varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    write_varint(out, ((field as u64) << 3) | 0);
    write_varint(out, value);
}

fn write_bytes_field(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    write_varint(out, ((field as u64) << 3) | 2);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        v |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn ring_push_pop_roundtrip() {
        let f = NamedTempFile::new().unwrap();
        let (prod, cons) = SpscPipe::create(f.path(), 64, 256).unwrap();

        for i in 0..32u8 {
            let payload = vec![i; 100];
            assert!(prod.try_push(&payload), "push #{i} failed");
        }
        let mut buf = Vec::new();
        for i in 0..32u8 {
            let len = cons.try_pop(&mut buf).expect("pop");
            assert_eq!(len, 100);
            assert!(buf.iter().all(|&b| b == i), "iter {i} mismatched");
        }
        assert!(cons.try_pop(&mut buf).is_none(), "should be empty now");
    }

    #[test]
    fn ring_full_returns_false() {
        let f = NamedTempFile::new().unwrap();
        let (prod, _cons) = SpscPipe::create(f.path(), 4, 64).unwrap();
        for _ in 0..4 {
            assert!(prod.try_push(b"hello"));
        }
        assert!(!prod.try_push(b"hello"), "5th push should fail (full)");
    }

    #[test]
    fn ring_wraps_correctly_past_capacity() {
        let f = NamedTempFile::new().unwrap();
        let (prod, cons) = SpscPipe::create(f.path(), 4, 64).unwrap();
        let mut buf = Vec::new();
        // Push and pop 3x capacity to force the index to wrap.
        for round in 0..3 {
            for i in 0..4u8 {
                let payload = [round as u8, i];
                assert!(prod.try_push(&payload));
            }
            for i in 0..4u8 {
                cons.try_pop(&mut buf).unwrap();
                assert_eq!(buf, vec![round as u8, i]);
            }
        }
    }

    #[test]
    fn protobuf_record_roundtrip() {
        let r = PacketRecord {
            timestamp_ns: 1_700_000_000_000_000_000,
            src_ip: vec![10, 0, 0, 1],
            dst_ip: vec![10, 0, 0, 2],
            src_port: 51234,
            dst_port: 443,
            proto: 6,
            payload: b"GET / HTTP/1.1\r\nHost: example\r\n\r\n".to_vec(),
        };
        let bytes = r.encode();
        let back = PacketRecord::decode(&bytes).expect("decode");
        assert_eq!(r, back);
    }

    #[test]
    fn ring_carries_protobuf_records() {
        let f = NamedTempFile::new().unwrap();
        let (prod, cons) = SpscPipe::create(f.path(), 32, 1024).unwrap();
        let mut buf = Vec::new();
        for i in 0..16u32 {
            let r = PacketRecord {
                timestamp_ns: i as u64 * 1_000_000,
                src_ip: vec![10, 0, 0, i as u8],
                dst_ip: vec![8, 8, 8, 8],
                src_port: 40000 + i,
                dst_port: 53,
                proto: 17,
                payload: vec![0xAB; 16],
            };
            assert!(prod.try_push(&r.encode()));
        }
        for i in 0..16u32 {
            cons.try_pop(&mut buf).unwrap();
            let r = PacketRecord::decode(&buf).expect("decode");
            assert_eq!(r.timestamp_ns, i as u64 * 1_000_000);
            assert_eq!(r.src_port, 40000 + i);
            assert_eq!(r.proto, 17);
        }
    }

    #[test]
    fn ring_concurrent_spsc() {
        use std::sync::Arc;
        use std::thread;

        let f = NamedTempFile::new().unwrap();
        let (prod, cons) = SpscPipe::create(f.path(), 1024, 64).unwrap();
        let prod = Arc::new(prod);
        let cons = Arc::new(cons);

        let p = prod.clone();
        let producer = thread::spawn(move || {
            let mut sent = 0u64;
            for i in 0..10_000u64 {
                let payload = i.to_le_bytes();
                while !p.try_push(&payload) {
                    std::hint::spin_loop();
                }
                sent += 1;
            }
            sent
        });

        let c = cons.clone();
        let consumer = thread::spawn(move || {
            let mut received = 0u64;
            let mut buf = Vec::new();
            let mut expected = 0u64;
            while received < 10_000 {
                if c.try_pop(&mut buf).is_some() {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&buf[..8]);
                    let v = u64::from_le_bytes(arr);
                    assert_eq!(v, expected, "out-of-order at {received}");
                    expected += 1;
                    received += 1;
                } else {
                    std::hint::spin_loop();
                }
            }
            received
        });

        assert_eq!(producer.join().unwrap(), 10_000);
        assert_eq!(consumer.join().unwrap(), 10_000);
    }
}
