//! ML-DSA (FIPS 204) parameter sets.
//!
//! Defines the three standardized security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87.

use crate::field::Q;

/// Common parameters shared by all ML-DSA instances.
pub const N: usize = 256;
/// The modulus.
pub const MODULUS: u32 = Q;
/// Number of dropped bits from t (same for all parameter sets).
pub const D: usize = 13;

/// Trait describing an ML-DSA parameter set.
///
/// Implementors provide the constants that vary between security levels.
pub trait ParamSet {
    /// Number of rows in the matrix A (and length of vectors t, w, etc.).
    const K: usize;
    /// Number of columns in the matrix A (and length of vector s1).
    const L: usize;
    /// Coefficient range for secret vectors s1, s2: coefficients in [-eta, eta].
    const ETA: usize;
    /// Number of ±1 coefficients in the challenge polynomial c.
    const TAU: usize;
    /// Norm bound: beta = tau * eta.
    const BETA: u32;
    /// Coefficient range for y: coefficients in [-(gamma1-1), gamma1].
    const GAMMA1: u32;
    /// Low-order rounding range: divides (q - 1).
    const GAMMA2: u32;
    /// Maximum number of 1s in the hint vector h.
    const OMEGA: usize;
    /// Collision strength in bits (128, 192, or 256).
    const LAMBDA: usize;

    // ---- Derived sizes (in bytes) ----

    /// Number of bits to encode a gamma1-range coefficient in the signature.
    /// `gamma1_bits = 1 + floor(log2(gamma1))`.
    const GAMMA1_BITS: usize;

    /// Number of bits to encode an eta-range coefficient.
    /// For eta = 2: need 3 bits (values 0..4 map to 2, 1, 0, -1, -2).
    /// For eta = 4: need 4 bits (values 0..8).
    const ETA_BITS: usize;

    /// Size of c_tilde in bytes: lambda / 4.
    const C_TILDE_SIZE: usize = Self::LAMBDA / 4;

    /// Public key size in bytes: 32 + 320 * k.
    /// (rho: 32 bytes, t1: k polynomials * 256 coeffs * 10 bits / 8).
    const PK_SIZE: usize = 32 + 320 * Self::K;

    /// Secret key size in bytes.
    /// sk = rho || K || tr || s1_packed || s2_packed || t0_packed
    /// rho: 32, K: 32, tr: 64
    /// s1: l polynomials, each 256 coeffs * eta_bits / 8 bytes
    /// s2: k polynomials, each 256 coeffs * eta_bits / 8 bytes
    /// t0: k polynomials, each 256 coeffs * d bits / 8 bytes
    const SK_SIZE: usize =
        32 + 32 + 64 + 32 * Self::ETA_BITS * (Self::L + Self::K) + 32 * D * Self::K;

    /// Signature size in bytes.
    /// sig = c_tilde || z_packed || h_packed
    /// c_tilde: lambda/4 bytes
    /// z: l polynomials * 256 coeffs * gamma1_bits bits / 8 bytes
    /// h: omega + k bytes (encoded hint)
    const SIG_SIZE: usize =
        Self::C_TILDE_SIZE + Self::L * 32 * Self::GAMMA1_BITS + Self::OMEGA + Self::K;
}

/// ML-DSA-44: NIST security level 2.
pub struct MlDsa44;

impl ParamSet for MlDsa44 {
    const K: usize = 4;
    const L: usize = 4;
    const ETA: usize = 2;
    const TAU: usize = 39;
    const BETA: u32 = 78; // 39 * 2
    const GAMMA1: u32 = 1 << 17; // 2^17 = 131072
    const GAMMA2: u32 = (Q - 1) / 88; // 95232
    const OMEGA: usize = 80;
    const LAMBDA: usize = 128;
    const GAMMA1_BITS: usize = 18; // 1 + 17
    const ETA_BITS: usize = 3; // ceil(log2(2*2 + 1)) = 3
}

/// ML-DSA-65: NIST security level 3.
pub struct MlDsa65;

impl ParamSet for MlDsa65 {
    const K: usize = 6;
    const L: usize = 5;
    const ETA: usize = 4;
    const TAU: usize = 49;
    const BETA: u32 = 196; // 49 * 4
    const GAMMA1: u32 = 1 << 19; // 2^19 = 524288
    const GAMMA2: u32 = (Q - 1) / 32; // 261888
    const OMEGA: usize = 55;
    const LAMBDA: usize = 192;
    const GAMMA1_BITS: usize = 20; // 1 + 19
    const ETA_BITS: usize = 4; // ceil(log2(2*4 + 1)) = 4
}

/// ML-DSA-87: NIST security level 5.
pub struct MlDsa87;

impl ParamSet for MlDsa87 {
    const K: usize = 8;
    const L: usize = 7;
    const ETA: usize = 2;
    const TAU: usize = 60;
    const BETA: u32 = 120; // 60 * 2
    const GAMMA1: u32 = 1 << 19; // 2^19 = 524288
    const GAMMA2: u32 = (Q - 1) / 32; // 261888
    const OMEGA: usize = 75;
    const LAMBDA: usize = 256;
    const GAMMA1_BITS: usize = 20; // 1 + 19
    const ETA_BITS: usize = 3; // ceil(log2(2*2 + 1)) = 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_constants() {
        assert_eq!(N, 256);
        assert_eq!(MODULUS, 8380417);
        assert_eq!(D, 13);
    }

    #[test]
    fn test_beta_equals_tau_times_eta() {
        assert_eq!(MlDsa44::BETA, (MlDsa44::TAU as u32) * (MlDsa44::ETA as u32));
        assert_eq!(MlDsa65::BETA, (MlDsa65::TAU as u32) * (MlDsa65::ETA as u32));
        assert_eq!(MlDsa87::BETA, (MlDsa87::TAU as u32) * (MlDsa87::ETA as u32));
    }

    #[test]
    fn test_gamma2_divides_q_minus_1() {
        assert_eq!((Q - 1) % MlDsa44::GAMMA2, 0);
        assert_eq!((Q - 1) % MlDsa65::GAMMA2, 0);
        assert_eq!((Q - 1) % MlDsa87::GAMMA2, 0);
    }

    #[test]
    fn test_gamma2_values() {
        assert_eq!(MlDsa44::GAMMA2, (Q - 1) / 88);
        assert_eq!(MlDsa65::GAMMA2, (Q - 1) / 32);
        assert_eq!(MlDsa87::GAMMA2, (Q - 1) / 32);
    }

    #[test]
    fn test_pk_sizes() {
        // pk = rho(32) + t1_packed(k * 320)
        assert_eq!(MlDsa44::PK_SIZE, 32 + 320 * 4); // 1312
        assert_eq!(MlDsa65::PK_SIZE, 32 + 320 * 6); // 1952
        assert_eq!(MlDsa87::PK_SIZE, 32 + 320 * 8); // 2592
    }

    #[test]
    fn test_pk_size_values() {
        assert_eq!(MlDsa44::PK_SIZE, 1312);
        assert_eq!(MlDsa65::PK_SIZE, 1952);
        assert_eq!(MlDsa87::PK_SIZE, 2592);
    }

    #[test]
    fn test_sk_sizes() {
        // ML-DSA-44: 32+32+64 + 32*3*(4+4) + 32*13*4 = 128 + 768 + 1664 = 2560
        assert_eq!(MlDsa44::SK_SIZE, 2560);
        // ML-DSA-65: 32+32+64 + 32*4*(5+6) + 32*13*6 = 128 + 1408 + 2496 = 4032
        assert_eq!(MlDsa65::SK_SIZE, 4032);
        // ML-DSA-87: 32+32+64 + 32*3*(7+8) + 32*13*8 = 128 + 1440 + 3328 = 4896
        assert_eq!(MlDsa87::SK_SIZE, 4896);
    }

    #[test]
    fn test_sig_sizes() {
        // ML-DSA-44: lambda/4=32, 32 + 4*32*18 + 80 + 4 = 32 + 2304 + 84 = 2420
        assert_eq!(MlDsa44::SIG_SIZE, 2420);
        // ML-DSA-65: lambda/4=48, 48 + 5*32*20 + 55 + 6 = 48 + 3200 + 61 = 3309
        assert_eq!(MlDsa65::SIG_SIZE, 3309);
        // ML-DSA-87: lambda/4=64, 64 + 7*32*20 + 75 + 8 = 64 + 4480 + 83 = 4627
        assert_eq!(MlDsa87::SIG_SIZE, 4627);
    }
}
