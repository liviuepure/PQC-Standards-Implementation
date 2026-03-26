//! Hash and sampling functions for ML-DSA (FIPS 204).
//!
//! Provides SHAKE-based hashing, matrix/vector expansion, and challenge sampling.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use crate::field::Q;

/// H(data, output_len) — variable-length hash using SHAKE-256.
pub fn h(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// H(a || b, output_len) — SHAKE-256 with two-part input.
pub fn h_two(a: &[u8], b: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(a);
    hasher.update(b);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// Generate the k x l matrix A in NTT domain from seed rho.
///
/// For each entry (i, j): XOF = SHAKE-128(rho || j || i), then rejection
/// sample coefficients < q by reading 3 bytes at a time (24 bits, mask top bit).
pub fn expand_a(rho: &[u8; 32], k: usize, l: usize) -> Vec<Vec<[u32; 256]>> {
    let mut a_hat = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(l);
        for j in 0..l {
            let mut hasher = Shake128::default();
            hasher.update(rho);
            hasher.update(&[j as u8, i as u8]);
            let mut reader = hasher.finalize_xof();

            let mut poly = [0u32; 256];
            let mut idx = 0;
            let mut buf = [0u8; 3];
            while idx < 256 {
                reader.read(&mut buf);
                let val = (buf[0] as u32)
                    | ((buf[1] as u32) << 8)
                    | (((buf[2] & 0x7F) as u32) << 16);
                if val < Q {
                    poly[idx] = val;
                    idx += 1;
                }
            }
            row.push(poly);
        }
        a_hat.push(row);
    }
    a_hat
}

/// Generate secret vectors s1 (length l) and s2 (length k) from seed sigma.
///
/// For each polynomial, use SHAKE-256(sigma || 2-byte nonce) and sample
/// coefficients in [-eta, eta] via rejection sampling.
pub fn expand_s(
    sigma: &[u8; 64],
    eta: u32,
    k: usize,
    l: usize,
) -> (Vec<[u32; 256]>, Vec<[u32; 256]>) {
    let mut s1 = Vec::with_capacity(l);
    let mut s2 = Vec::with_capacity(k);

    for nonce in 0..(l + k) as u16 {
        let mut hasher = Shake256::default();
        hasher.update(sigma);
        hasher.update(&nonce.to_le_bytes());
        let mut reader = hasher.finalize_xof();

        let poly = if eta == 2 {
            sample_eta2(&mut reader)
        } else {
            sample_eta4(&mut reader)
        };

        if (nonce as usize) < l {
            s1.push(poly);
        } else {
            s2.push(poly);
        }
    }

    (s1, s2)
}

/// Sample a polynomial with coefficients in [-2, 2] mod q via rejection.
fn sample_eta2(reader: &mut impl XofReader) -> [u32; 256] {
    let mut poly = [0u32; 256];
    let mut idx = 0;
    let mut buf = [0u8; 1];
    while idx < 256 {
        reader.read(&mut buf);
        let b = buf[0];
        let t0 = (b & 0x0F) as u32;
        let t1 = (b >> 4) as u32;
        // Rejection: need t < 15 to get uniform in {0,1,2,3,4}
        if t0 < 15 && idx < 256 {
            let coeff = t0 % 5; // 0..4
            // Map: 0->0, 1->1, 2->2, 3->q-1 (-1), 4->q-2 (-2)
            poly[idx] = eta_map(coeff, 2);
            idx += 1;
        }
        if t1 < 15 && idx < 256 {
            let coeff = t1 % 5;
            poly[idx] = eta_map(coeff, 2);
            idx += 1;
        }
    }
    poly
}

/// Sample a polynomial with coefficients in [-4, 4] mod q via rejection.
fn sample_eta4(reader: &mut impl XofReader) -> [u32; 256] {
    let mut poly = [0u32; 256];
    let mut idx = 0;
    let mut buf = [0u8; 1];
    while idx < 256 {
        reader.read(&mut buf);
        let b = buf[0];
        let t0 = (b & 0x0F) as u32;
        let t1 = (b >> 4) as u32;
        // For eta=4: need t < 9 to get uniform in {0..8}
        if t0 < 9 && idx < 256 {
            poly[idx] = eta_map(t0, 4);
            idx += 1;
        }
        if t1 < 9 && idx < 256 {
            poly[idx] = eta_map(t1, 4);
            idx += 1;
        }
    }
    poly
}

/// Map a value in [0, 2*eta] to the corresponding field element.
/// 0 -> eta, 1 -> eta-1, ..., eta -> 0, eta+1 -> q-1, ..., 2*eta -> q-eta.
/// That is: result = eta - val (mod q).
#[inline]
fn eta_map(val: u32, eta: u32) -> u32 {
    if val <= eta {
        eta - val
    } else {
        Q - (val - eta)
    }
}

/// Generate masking vector y of length l from rho_prime.
///
/// For each polynomial i: SHAKE-256(rho_prime || (kappa + i) as 2 bytes LE),
/// then sample coefficients in [-(gamma1-1), gamma1].
pub fn expand_mask(rho_prime: &[u8; 64], gamma1: u32, l: usize, kappa: u16) -> Vec<[u32; 256]> {
    let mut y = Vec::with_capacity(l);
    for i in 0..l {
        let nonce = kappa + i as u16;
        let mut hasher = Shake256::default();
        hasher.update(rho_prime);
        hasher.update(&nonce.to_le_bytes());
        let mut reader = hasher.finalize_xof();

        let poly = if gamma1 == (1 << 17) {
            sample_gamma1_17(&mut reader)
        } else {
            sample_gamma1_19(&mut reader)
        };
        y.push(poly);
    }
    y
}

/// Sample coefficients in [-(2^17 - 1), 2^17] using 18-bit chunks.
fn sample_gamma1_17(reader: &mut impl XofReader) -> [u32; 256] {
    let mut poly = [0u32; 256];
    // Read 256 * 18 bits = 576 bytes
    let mut buf = [0u8; 576];
    reader.read(&mut buf);
    for i in 0..256 {
        let bit_offset = i * 18;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;
        let val = ((buf[byte_idx] as u32) >> bit_idx)
            | ((buf[byte_idx + 1] as u32) << (8 - bit_idx))
            | ((buf[byte_idx + 2] as u32) << (16 - bit_idx));
        let val = val & 0x3FFFF; // 18 bits
        // val is in [0, 2^18 - 1]; we interpret as gamma1 - val
        let gamma1 = 1u32 << 17;
        if gamma1 >= val {
            poly[i] = gamma1 - val;
        } else {
            // gamma1 - val < 0, so result = q + gamma1 - val
            poly[i] = Q + gamma1 - val;
        }
    }
    poly
}

/// Sample coefficients in [-(2^19 - 1), 2^19] using 20-bit chunks.
fn sample_gamma1_19(reader: &mut impl XofReader) -> [u32; 256] {
    let mut poly = [0u32; 256];
    // Read 256 * 20 bits = 640 bytes
    let mut buf = [0u8; 640];
    reader.read(&mut buf);
    for i in 0..128 {
        // 2 coefficients per 5 bytes
        let base = i * 5;
        let v0 = (buf[base] as u32)
            | ((buf[base + 1] as u32) << 8)
            | (((buf[base + 2] & 0x0F) as u32) << 16);
        let v1 = ((buf[base + 2] as u32) >> 4)
            | ((buf[base + 3] as u32) << 4)
            | ((buf[base + 4] as u32) << 12);

        let gamma1 = 1u32 << 19;
        poly[2 * i] = coeff_from_halfword(v0 & 0xFFFFF, gamma1);
        poly[2 * i + 1] = coeff_from_halfword(v1 & 0xFFFFF, gamma1);
    }
    poly
}

/// Convert a raw sample value to a coefficient: gamma1 - val (mod q).
#[inline]
fn coeff_from_halfword(val: u32, gamma1: u32) -> u32 {
    if gamma1 >= val {
        gamma1 - val
    } else {
        Q + gamma1 - val
    }
}

/// Generate challenge polynomial c with exactly tau coefficients in {-1, 1}
/// and the rest 0. Uses SHAKE-256(c_tilde) for random bits.
pub fn sample_in_ball(c_tilde: &[u8], tau: usize) -> [u32; 256] {
    let mut hasher = Shake256::default();
    hasher.update(c_tilde);
    let mut reader = hasher.finalize_xof();

    // First read 8 bytes for sign bits
    let mut sign_bytes = [0u8; 8];
    reader.read(&mut sign_bytes);
    let signs = u64::from_le_bytes(sign_bytes);

    let mut c = [0u32; 256];
    let mut sign_idx = 0u32;

    for i in (256 - tau)..256 {
        // Sample j uniform in [0, i]
        let j = loop {
            let mut buf = [0u8; 1];
            reader.read(&mut buf);
            let val = buf[0] as usize;
            if val <= i {
                break val;
            }
        };

        c[i] = c[j];
        if (signs >> sign_idx) & 1 == 1 {
            c[j] = Q - 1; // -1 mod q
        } else {
            c[j] = 1;
        }
        sign_idx += 1;
    }

    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h_deterministic() {
        let data = b"test input";
        let out1 = h(data, 64);
        let out2 = h(data, 64);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 64);
    }

    #[test]
    fn test_expand_a_deterministic() {
        let rho = [0u8; 32];
        let a1 = expand_a(&rho, 4, 4);
        let a2 = expand_a(&rho, 4, 4);
        assert_eq!(a1.len(), 4);
        assert_eq!(a1[0].len(), 4);
        for i in 0..4 {
            for j in 0..4 {
                assert_eq!(a1[i][j], a2[i][j]);
            }
        }
    }

    #[test]
    fn test_expand_a_coefficients_in_range() {
        let rho = [42u8; 32];
        let a = expand_a(&rho, 6, 5);
        for row in &a {
            for poly in row {
                for &c in poly.iter() {
                    assert!(c < Q, "coefficient {} out of range", c);
                }
            }
        }
    }

    #[test]
    fn test_expand_s_lengths() {
        let sigma = [1u8; 64];
        let (s1, s2) = expand_s(&sigma, 2, 4, 4);
        assert_eq!(s1.len(), 4);
        assert_eq!(s2.len(), 4);
    }

    #[test]
    fn test_expand_s_eta2_range() {
        let sigma = [7u8; 64];
        let (s1, s2) = expand_s(&sigma, 2, 4, 4);
        for poly in s1.iter().chain(s2.iter()) {
            for &c in poly.iter() {
                // Should be in {0, 1, 2, q-1, q-2}
                assert!(
                    c <= 2 || c >= Q - 2,
                    "eta=2 coefficient {} out of range",
                    c
                );
            }
        }
    }

    #[test]
    fn test_expand_s_eta4_range() {
        let sigma = [13u8; 64];
        let (s1, s2) = expand_s(&sigma, 4, 6, 5);
        for poly in s1.iter().chain(s2.iter()) {
            for &c in poly.iter() {
                assert!(
                    c <= 4 || c >= Q - 4,
                    "eta=4 coefficient {} out of range",
                    c
                );
            }
        }
    }

    #[test]
    fn test_sample_in_ball_tau39() {
        let c_tilde = [0u8; 32];
        let c = sample_in_ball(&c_tilde, 39);
        let nonzero: usize = c.iter().filter(|&&v| v != 0).count();
        assert_eq!(nonzero, 39);
        for &v in c.iter() {
            assert!(v == 0 || v == 1 || v == Q - 1);
        }
    }

    #[test]
    fn test_sample_in_ball_tau60() {
        let c_tilde = [0xFF; 32];
        let c = sample_in_ball(&c_tilde, 60);
        let nonzero: usize = c.iter().filter(|&&v| v != 0).count();
        assert_eq!(nonzero, 60);
    }

    #[test]
    fn test_expand_mask_gamma1_17() {
        let rho_prime = [3u8; 64];
        let y = expand_mask(&rho_prime, 1 << 17, 4, 0);
        assert_eq!(y.len(), 4);
        let gamma1 = 1u32 << 17;
        for poly in &y {
            for &c in poly.iter() {
                // Should be in [-(gamma1-1), gamma1] mod q
                // i.e., [0, gamma1] union [q-gamma1+1, q-1]
                assert!(c <= gamma1 || c >= Q - gamma1 + 1);
            }
        }
    }

    #[test]
    fn test_expand_mask_gamma1_19() {
        let rho_prime = [5u8; 64];
        let y = expand_mask(&rho_prime, 1 << 19, 5, 0);
        assert_eq!(y.len(), 5);
        let gamma1 = 1u32 << 19;
        for poly in &y {
            for &c in poly.iter() {
                assert!(c <= gamma1 || c >= Q - gamma1 + 1);
            }
        }
    }
}
