//! Number Theoretic Transform for ML-KEM.
//!
//! Implements the NTT and inverse NTT over Z_q[X]/(X^256+1) as specified
//! in FIPS 203, Algorithms 9-12.
//!
//! The NTT uses a negacyclic variant with q = 3329 and primitive 256th
//! root of unity zeta = 17.

use pqc_common::field::{FieldElement, Q};

/// Reverses the 7 least significant bits of `x`.
///
/// Used to compute butterfly indices in the NTT.
/// FIPS 203, used in NTT zeta table construction.
#[inline]
pub const fn bitrev7(x: u8) -> u8 {
    let mut result = 0u8;
    let mut i = 0;
    let mut val = x;
    while i < 7 {
        result = (result << 1) | (val & 1);
        val >>= 1;
        i += 1;
    }
    result
}

/// Modular exponentiation: base^exp mod modulus.
const fn pow_mod(mut base: u32, mut exp: u32, modulus: u32) -> u32 {
    let mut result = 1u32;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        if exp > 0 {
            base = (base * base) % modulus;
        }
    }
    result
}

/// Precomputed zeta table: `ZETAS[i] = 17^BitRev7(i) mod 3329`.
///
/// 17 is a primitive 256th root of unity modulo 3329.
/// FIPS 203, Section 4.4.
pub const ZETAS: [u16; 128] = compute_zetas();

const fn compute_zetas() -> [u16; 128] {
    let mut table = [0u16; 128];
    let mut i = 0u8;
    while (i as usize) < 128 {
        let exp = bitrev7(i) as u32;
        table[i as usize] = pow_mod(17, exp, Q as u32) as u16;
        i += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitrev7() {
        assert_eq!(bitrev7(0), 0);
        assert_eq!(bitrev7(1), 64);
        assert_eq!(bitrev7(2), 32);
        assert_eq!(bitrev7(64), 1);
        assert_eq!(bitrev7(127), 127);
    }

    #[test]
    fn test_zetas_first_entries() {
        // zeta^BitRev7(0) = 17^0 = 1
        assert_eq!(ZETAS[0], 1);
        // zeta^BitRev7(1) = 17^64 mod 3329 = 1729
        assert_eq!(ZETAS[1], 1729);
    }

    #[test]
    fn test_zetas_length() {
        assert_eq!(ZETAS.len(), 128);
    }

    #[test]
    fn test_all_zetas_in_range() {
        for &z in ZETAS.iter() {
            assert!(z < Q, "zeta {} out of range", z);
        }
    }

    #[test]
    fn test_zeta_is_256th_root_of_unity() {
        // 17^256 mod 3329 should equal 1
        assert_eq!(pow_mod(17, 256, Q as u32), 1);
        // 17^128 mod 3329 should equal q-1 (i.e., -1 mod q)
        assert_eq!(pow_mod(17, 128, Q as u32), (Q - 1) as u32);
    }
}
