//! HQC (Hamming Quasi-Cyclic) Key Encapsulation Mechanism.
//!
//! HQC is a code-based KEM selected by NIST for post-quantum cryptography
//! standardization. It combines a quasi-cyclic code over GF(2), a tensor
//! product code (Reed-Muller x Reed-Solomon) for error correction, and a
//! Fujisaki-Okeyama transform for CCA security.
//!
//! Three security levels are supported:
//! - HQC-128: NIST security level 1 (128-bit)
//! - HQC-192: NIST security level 3 (192-bit)
//! - HQC-256: NIST security level 5 (256-bit)
//!
//! # Example
//!
//! ```ignore
//! use hqc::{HQC128, key_gen, encaps, decaps};
//!
//! let (pk, sk) = key_gen(&HQC128, &mut rng);
//! let (ct, ss1) = encaps(&pk, &HQC128, &mut rng);
//! let ss2 = decaps(&sk, &ct, &HQC128);
//! assert_eq!(ss1, ss2);
//! ```

pub mod gf2;
pub mod gf256;
mod kem;
pub mod params;
pub mod rm;
pub mod rs;
pub mod tensor;

pub use params::{all_params, Params, HQC128, HQC192, HQC256};

use rand_core::CryptoRngCore;

/// Generates an HQC key pair for the given parameter set.
/// Returns (public_key, secret_key).
pub fn key_gen(p: &Params, rng: &mut impl CryptoRngCore) -> (Vec<u8>, Vec<u8>) {
    kem::key_gen(p, rng)
}

/// Encapsulates a shared secret using the given public key.
/// Returns (ciphertext, shared_secret).
///
/// # Panics
///
/// Panics if `pk.len() != p.pk_size`.
pub fn encaps(pk: &[u8], p: &Params, rng: &mut impl CryptoRngCore) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(pk.len(), p.pk_size, "hqc: invalid public key size");
    kem::encaps(pk, p, rng)
}

/// Decapsulates a shared secret from a ciphertext using the secret key.
/// Returns the shared secret.
///
/// # Panics
///
/// Panics if `sk.len() != p.sk_size` or `ct.len() != p.ct_size`.
pub fn decaps(sk: &[u8], ct: &[u8], p: &Params) -> Vec<u8> {
    assert_eq!(sk.len(), p.sk_size, "hqc: invalid secret key size");
    assert_eq!(ct.len(), p.ct_size, "hqc: invalid ciphertext size");
    kem::decaps(sk, ct, p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_kem_roundtrip_all_params() {
        for p in all_params() {
            let (pk, sk) = key_gen(p, &mut OsRng);
            assert_eq!(pk.len(), p.pk_size, "{}: pk size mismatch", p.name);
            assert_eq!(sk.len(), p.sk_size, "{}: sk size mismatch", p.name);

            let (ct, ss1) = encaps(&pk, p, &mut OsRng);
            assert_eq!(ct.len(), p.ct_size, "{}: ct size mismatch", p.name);
            assert_eq!(ss1.len(), p.ss_size, "{}: ss size mismatch", p.name);

            let ss2 = decaps(&sk, &ct, p);
            assert_eq!(ss1, ss2, "{}: shared secrets do not match", p.name);
        }
    }

    #[test]
    fn test_kem_bad_ciphertext_rejection() {
        let p = &HQC128;
        let (pk, sk) = key_gen(p, &mut OsRng);
        let (mut ct, ss1) = encaps(&pk, p, &mut OsRng);

        // Corrupt ciphertext
        ct[0] ^= 0xFF;
        ct[1] ^= 0xFF;

        let ss2 = decaps(&sk, &ct, p);
        assert_ne!(ss1, ss2, "shared secrets should differ with corrupted ciphertext");
    }

    #[test]
    fn test_kem_multiple_roundtrips() {
        for p in all_params() {
            for i in 0..5 {
                let (pk, sk) = key_gen(p, &mut OsRng);
                let (ct, ss1) = encaps(&pk, p, &mut OsRng);
                let ss2 = decaps(&sk, &ct, p);
                assert_eq!(
                    ss1, ss2,
                    "{}: trial {}: shared secrets do not match",
                    p.name, i
                );
            }
        }
    }
}
