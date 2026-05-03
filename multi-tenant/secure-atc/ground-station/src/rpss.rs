//! Randomized Proactive Secret Sharing (frontier upgrade #12).
//!
//! Byte-wise Shamir over GF(2^8). A 32-byte secret is split into `n`
//! shares such that any `t` reconstruct the original; fewer than `t`
//! reveal nothing. Every refresh epoch, holders run a Pedersen-style
//! resharing: each picks a refresh polynomial with constant term zero
//! and broadcasts evaluations; every holder XORs their incoming
//! evaluations into their share. The result is a fresh sharing of the
//! same secret. **Old shares from before a refresh cannot be combined
//! with new shares**, so the effective compromise window is one epoch
//! (~ 1 hour).
//!
//! GF(2^8) arithmetic is implemented from scratch — no external bigint
//! is required. The reduction polynomial is x^8 + x^4 + x^3 + x + 1
//! (Rijndael's polynomial), so multiplication tables match AES.

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// One holder's share of one byte. `x` is the holder's evaluation point;
/// `y` is the share value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GfPoint {
    pub x: u8,
    pub y: u8,
}

/// One holder's share of the full 32-byte secret.
#[derive(Clone, Debug)]
pub struct Share {
    pub holder: u8,
    pub epoch: u64,
    pub bytes: Zeroizing<[u8; 32]>,
}

/// GF(2^8) addition is XOR.
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(2^8) multiplication, Russian-peasant style with the AES poly.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b; // x^8 = x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    p
}

/// GF(2^8) inversion via Fermat's little theorem: x^254 == x^-1.
fn gf_inv(a: u8) -> u8 {
    debug_assert_ne!(a, 0, "no inverse for zero");
    let mut result = 1u8;
    let mut base = a;
    let mut exp: u32 = 254;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Evaluate a polynomial in GF(2^8) at point `x`. `coeffs[0]` is the
/// constant term.
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    let mut x_pow = 1u8;
    for &c in coeffs {
        acc = gf_add(acc, gf_mul(c, x_pow));
        x_pow = gf_mul(x_pow, x);
    }
    acc
}

/// Lagrange interpolation at x=0 over GF(2^8). Used to reconstruct.
fn interpolate_at_zero(points: &[GfPoint]) -> u8 {
    let mut acc = 0u8;
    for (i, pi) in points.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, pj) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            // L_i(0) = prod_{j != i} ( -x_j / (x_i - x_j) )
            // In GF(2), subtraction == addition, sign is irrelevant.
            num = gf_mul(num, pj.x);
            den = gf_mul(den, gf_add(pi.x, pj.x));
        }
        let term = gf_mul(pi.y, gf_mul(num, gf_inv(den)));
        acc = gf_add(acc, term);
    }
    acc
}

/// Distribute a 32-byte secret into `n` shares with reconstruction
/// threshold `t`. Holder ids are `1..=n` (avoid 0 — that's the secret
/// evaluation point).
pub fn split(secret: &[u8; 32], threshold: u8, n: u8) -> Vec<Share> {
    assert!(threshold <= n);
    assert!(threshold >= 1);
    assert!(n >= 1);
    assert!(n < 255, "GF(2^8) only has 255 distinct nonzero points");

    let mut rng = OsRng;
    let mut shares: Vec<Share> = (1..=n)
        .map(|h| Share {
            holder: h,
            epoch: 0,
            bytes: Zeroizing::new([0u8; 32]),
        })
        .collect();

    for byte_index in 0..32 {
        // Build a polynomial of degree `threshold-1` with
        // constant term = secret[byte_index] and random other
        // coefficients.
        let mut coeffs = vec![secret[byte_index]];
        for _ in 1..threshold {
            let mut buf = [0u8; 1];
            rng.fill_bytes(&mut buf);
            coeffs.push(buf[0]);
        }
        for share in shares.iter_mut() {
            share.bytes[byte_index] = eval_poly(&coeffs, share.holder);
        }
    }
    shares
}

/// Reconstruct the secret from at least `threshold` shares.
pub fn reconstruct(shares: &[Share]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for byte_index in 0..32 {
        let pts: Vec<GfPoint> = shares
            .iter()
            .map(|s| GfPoint {
                x: s.holder,
                y: s.bytes[byte_index],
            })
            .collect();
        out[byte_index] = interpolate_at_zero(&pts);
    }
    out
}

/// One refresh round. Every holder broadcasts a refresh polynomial
/// evaluated at every other holder; the local holder XORs the incoming
/// evaluations into its share. The constant term of every refresh poly
/// is zero, so the secret is preserved.
///
/// In production this runs as a multi-round MPC; here we model the
/// centralized version (the broadcasts are bytes-in / bytes-out).
pub fn refresh(shares: &mut [Share], threshold: u8) {
    assert!(!shares.is_empty());
    let n = shares.len() as u8;
    let mut rng = OsRng;

    for byte_index in 0..32 {
        // Each holder picks a refresh poly with f(0) = 0.
        let mut all_polys: Vec<Vec<u8>> = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let mut coeffs = vec![0u8]; // constant term = 0
            for _ in 1..threshold {
                let mut buf = [0u8; 1];
                rng.fill_bytes(&mut buf);
                coeffs.push(buf[0]);
            }
            all_polys.push(coeffs);
        }
        // Apply: every share gets XOR'd with the sum of all refresh
        // polynomials evaluated at its holder point.
        for share in shares.iter_mut() {
            let mut delta = 0u8;
            for poly in &all_polys {
                delta = gf_add(delta, eval_poly(poly, share.holder));
            }
            share.bytes[byte_index] = gf_add(share.bytes[byte_index], delta);
        }
    }
    for share in shares.iter_mut() {
        share.epoch += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_inv_round_trip() {
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "1/{a}");
        }
    }

    #[test]
    fn split_then_reconstruct() {
        let secret = *b"01234567890123456789012345678901";
        let shares = split(&secret, 3, 5);
        let recovered = reconstruct(&shares[..3]);
        assert_eq!(recovered, secret);
        let recovered2 = reconstruct(&shares[1..4]);
        assert_eq!(recovered2, secret);
    }

    #[test]
    fn fewer_than_threshold_does_not_reconstruct() {
        // Note: with <threshold shares, Lagrange yields a different
        // (incorrect) value. We just check we don't trip an assertion
        // and the result isn't the secret.
        let secret = *b"01234567890123456789012345678901";
        let shares = split(&secret, 3, 5);
        let bad = reconstruct(&shares[..2]);
        assert_ne!(bad, secret);
    }

    #[test]
    fn refresh_preserves_secret() {
        let secret = [0xA5u8; 32];
        let mut shares = split(&secret, 3, 5);
        refresh(&mut shares, 3);
        let recovered = reconstruct(&shares[..3]);
        assert_eq!(recovered, secret);
        assert_eq!(shares[0].epoch, 1);
    }

    #[test]
    fn refresh_invalidates_old_shares() {
        let secret = [0x99u8; 32];
        let mut shares = split(&secret, 3, 5);
        let old = shares[0].clone();
        refresh(&mut shares, 3);
        // Mix one old share with two refreshed ones — should NOT
        // reconstruct (the polynomials are inconsistent).
        let mixed = vec![old, shares[1].clone(), shares[2].clone()];
        let bad = reconstruct(&mixed);
        assert_ne!(bad, secret);
    }

    #[test]
    fn many_refreshes_preserve_secret() {
        let secret = [0xCDu8; 32];
        let mut shares = split(&secret, 3, 5);
        for _ in 0..50 {
            refresh(&mut shares, 3);
        }
        let recovered = reconstruct(&shares[..3]);
        assert_eq!(recovered, secret);
        assert_eq!(shares[0].epoch, 50);
    }
}
