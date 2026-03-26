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

/// Forward NTT in-place. FIPS 203, Algorithm 9.
///
/// Transforms a polynomial f in Z_q[X]/(X^256+1) into its NTT representation.
/// After this transform, pointwise multiplication in NTT domain corresponds
/// to polynomial multiplication modulo X^256+1.
pub fn ntt(f: &mut [FieldElement; 256]) {
    let mut i = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = FieldElement::new(ZETAS[i]);
            i += 1;
            for j in start..(start + len) {
                let t = zeta * f[j + len];
                f[j + len] = f[j] - t;
                f[j] = f[j] + t;
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Inverse NTT in-place. FIPS 203, Algorithm 10.
///
/// Transforms an NTT representation back to a polynomial in Z_q[X]/(X^256+1).
/// This is the inverse of [`ntt`].
pub fn ntt_inverse(f: &mut [FieldElement; 256]) {
    let mut i = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = FieldElement::new(ZETAS[i]);
            i = i.wrapping_sub(1);
            for j in start..(start + len) {
                let t = f[j];
                f[j] = t + f[j + len];
                f[j + len] = zeta * (f[j + len] - t);
            }
            start += 2 * len;
        }
        len *= 2;
    }
    // Multiply by 128^{-1} mod 3329 = 3303
    let inv128 = FieldElement::new(3303);
    for coeff in f.iter_mut() {
        *coeff = *coeff * inv128;
    }
}

/// Multiply two polynomials in NTT domain. FIPS 203, Algorithm 11.
///
/// Each pair of consecutive coefficients in the NTT domain represents
/// a degree-1 polynomial, and multiplication is performed pairwise
/// using [`base_case_multiply`].
pub fn multiply_ntts(
    f_hat: &[FieldElement; 256],
    g_hat: &[FieldElement; 256],
) -> [FieldElement; 256] {
    let mut h_hat = [FieldElement::ZERO; 256];
    for i in 0..64 {
        let gamma_exp = (2 * bitrev7(i as u8) as u32) + 1;
        let gamma = FieldElement::new(pow_mod(17, gamma_exp, Q as u32) as u16);

        let (c0, c1) = base_case_multiply(
            f_hat[4 * i],
            f_hat[4 * i + 1],
            g_hat[4 * i],
            g_hat[4 * i + 1],
            gamma,
        );
        h_hat[4 * i] = c0;
        h_hat[4 * i + 1] = c1;

        let (c0, c1) = base_case_multiply(
            f_hat[4 * i + 2],
            f_hat[4 * i + 3],
            g_hat[4 * i + 2],
            g_hat[4 * i + 3],
            -gamma,
        );
        h_hat[4 * i + 2] = c0;
        h_hat[4 * i + 3] = c1;
    }
    h_hat
}

/// Base case multiplication for NTT domain. FIPS 203, Algorithm 12.
///
/// Multiplies two degree-1 polynomials (a0 + a1*X) and (b0 + b1*X)
/// modulo (X^2 - gamma).
#[inline]
fn base_case_multiply(
    a0: FieldElement,
    a1: FieldElement,
    b0: FieldElement,
    b1: FieldElement,
    gamma: FieldElement,
) -> (FieldElement, FieldElement) {
    let c0 = a0 * b0 + a1 * b1 * gamma;
    let c1 = a0 * b1 + a1 * b0;
    (c0, c1)
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

    #[test]
    fn test_ntt_roundtrip() {
        let mut f = [FieldElement::ZERO; 256];
        for i in 0..256 {
            f[i] = FieldElement::new(i as u16);
        }
        let original = f;
        ntt(&mut f);
        ntt_inverse(&mut f);
        for i in 0..256 {
            assert_eq!(f[i].value(), original[i].value(), "mismatch at index {i}");
        }
    }

    #[test]
    fn test_ntt_zero_polynomial() {
        let mut f = [FieldElement::ZERO; 256];
        ntt(&mut f);
        for i in 0..256 {
            assert_eq!(f[i].value(), 0, "NTT of zero should be zero at index {i}");
        }
    }

    #[test]
    fn test_ntt_single_coefficient() {
        let mut f = [FieldElement::ZERO; 256];
        f[0] = FieldElement::new(1);
        let original = f;
        ntt(&mut f);
        ntt_inverse(&mut f);
        for i in 0..256 {
            assert_eq!(f[i].value(), original[i].value(), "mismatch at index {i}");
        }
    }

    #[test]
    fn test_ntt_random_roundtrip() {
        // Use a deterministic "random" polynomial
        let mut f = [FieldElement::ZERO; 256];
        for i in 0..256 {
            f[i] = FieldElement::new(((i * 1337 + 42) % 3329) as u16);
        }
        let original = f;
        ntt(&mut f);
        // NTT should change the values
        let mut same = true;
        for i in 0..256 {
            if f[i].value() != original[i].value() {
                same = false;
                break;
            }
        }
        assert!(!same, "NTT should change polynomial coefficients");
        ntt_inverse(&mut f);
        for i in 0..256 {
            assert_eq!(f[i].value(), original[i].value(), "mismatch at index {i}");
        }
    }

    #[test]
    fn test_multiply_ntts_identity() {
        // NTT(1) * NTT(f) should equal NTT(f)
        let mut one = [FieldElement::ZERO; 256];
        one[0] = FieldElement::ONE;
        ntt(&mut one);

        let mut f = [FieldElement::ZERO; 256];
        for i in 0..256 {
            f[i] = FieldElement::new(((i * 7) % 3329) as u16);
        }
        ntt(&mut f);

        let result = multiply_ntts(&f, &one);
        for i in 0..256 {
            assert_eq!(result[i].value(), f[i].value(), "mismatch at {i}");
        }
    }

    #[test]
    fn test_multiply_ntts_commutative() {
        let mut a = [FieldElement::ZERO; 256];
        let mut b = [FieldElement::ZERO; 256];
        for i in 0..256 {
            a[i] = FieldElement::new(((i * 3) % 3329) as u16);
            b[i] = FieldElement::new(((i * 7 + 1) % 3329) as u16);
        }
        ntt(&mut a);
        ntt(&mut b);

        let ab = multiply_ntts(&a, &b);
        let ba = multiply_ntts(&b, &a);
        for i in 0..256 {
            assert_eq!(ab[i].value(), ba[i].value(), "not commutative at {i}");
        }
    }

    #[test]
    fn test_ntt_multiply_zero() {
        let mut f = [FieldElement::ZERO; 256];
        for i in 0..256 {
            f[i] = FieldElement::new(((i * 13) % 3329) as u16);
        }
        ntt(&mut f);
        let zero = [FieldElement::ZERO; 256];
        let result = multiply_ntts(&f, &zero);
        for i in 0..256 {
            assert_eq!(result[i].value(), 0, "f*0 should be 0 at {i}");
        }
    }
}
