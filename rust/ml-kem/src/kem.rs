//! ML-KEM top-level key encapsulation mechanism.
//!
//! FIPS 203, Algorithms 16 (KeyGen), 17 (Encaps), 18 (Decaps).
//!
//! Wraps the internal K-PKE scheme with the Fujisaki-Okamoto transform
//! to achieve IND-CCA2 security with implicit rejection.

extern crate alloc;
use alloc::vec::Vec;
use subtle::ConstantTimeEq;
use rand_core::{CryptoRng, RngCore};
use crate::kpke::{kpke_keygen, kpke_encrypt, kpke_decrypt};
use crate::hash::{g, h, j};
use crate::params::ParameterSet;

/// ML-KEM.KeyGen — FIPS 203, Algorithm 16.
///
/// Generates an (encapsulation_key, decapsulation_key) pair.
/// Randomness is sourced from the provided CSPRNG.
pub fn keygen<P: ParameterSet>(rng: &mut (impl CryptoRng + RngCore)) -> (Vec<u8>, Vec<u8>) {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    rng.fill_bytes(&mut d);
    rng.fill_bytes(&mut z);
    keygen_internal::<P>(&d, &z)
}

/// Deterministic key generation from seeds (for testing/KAT).
pub fn keygen_internal<P: ParameterSet>(d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (ek_pke, dk_pke) = kpke_keygen::<P>(d);
    let ek = ek_pke;
    let h_ek = h(&ek);

    // dk = dk_pke || ek || H(ek) || z
    let mut dk = Vec::with_capacity(P::DK_SIZE);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(z);

    (ek.clone(), dk)
}

/// ML-KEM.Encaps — FIPS 203, Algorithm 17.
///
/// Produces a (shared_secret, ciphertext) pair from an encapsulation key.
/// The shared secret is 32 bytes. Randomness is sourced from the provided CSPRNG.
pub fn encapsulate<P: ParameterSet>(
    ek: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> ([u8; 32], Vec<u8>) {
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    encapsulate_internal::<P>(ek, &m)
}

/// Deterministic encapsulation from seed (for testing/KAT).
pub fn encapsulate_internal<P: ParameterSet>(
    ek: &[u8],
    m: &[u8; 32],
) -> ([u8; 32], Vec<u8>) {
    // (K, r) = G(m || H(ek))
    let h_ek = h(ek);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&h_ek);
    let (k, r) = g(&g_input);

    let ct = kpke_encrypt::<P>(ek, m, &r);
    (k, ct)
}

/// ML-KEM.Decaps — FIPS 203, Algorithm 18.
///
/// Recovers the shared secret from a ciphertext and decapsulation key.
/// Returns a 32-byte shared secret.
///
/// # Implicit Rejection
///
/// If the ciphertext is invalid (tampered or malformed), the function
/// returns a pseudorandom value J(z || c) instead of an error.
/// This comparison is constant-time to prevent timing side-channels.
pub fn decapsulate<P: ParameterSet>(dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let dk_pke_len = 384 * P::K;
    let ek_len = 384 * P::K + 32;

    // Parse dk into components
    let dk_pke = &dk[..dk_pke_len];
    let ek_pke = &dk[dk_pke_len..dk_pke_len + ek_len];
    let h_ek = &dk[dk_pke_len + ek_len..dk_pke_len + ek_len + 32];
    let z = &dk[dk_pke_len + ek_len + 32..dk_pke_len + ek_len + 64];

    // Decrypt to recover m'
    let m_prime = kpke_decrypt::<P>(dk_pke, ct);

    // (K', r') = G(m' || h)
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(h_ek);
    let (k_prime, r_prime) = g(&g_input);

    // Implicit rejection key: K_bar = J(z || c)
    let k_bar = j(z, ct);

    // Re-encrypt and compare (constant-time)
    let ct_prime = kpke_encrypt::<P>(ek_pke, &m_prime, &r_prime);
    let ct_eq: subtle::Choice = ct.ct_eq(&ct_prime);

    // Select K' if ct == ct', else K_bar (constant-time)
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = u8::conditional_select(&k_bar[i], &k_prime[i], ct_eq);
    }
    result
}

use subtle::ConditionallySelectable;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlKem512, MlKem768, MlKem1024};
    use rand::rngs::OsRng;

    #[test]
    fn test_kem_768_roundtrip() {
        let (ek, dk) = keygen::<MlKem768>(&mut OsRng);
        assert_eq!(ek.len(), MlKem768::EK_SIZE);
        assert_eq!(dk.len(), MlKem768::DK_SIZE);
        let (ss1, ct) = encapsulate::<MlKem768>(&ek, &mut OsRng);
        assert_eq!(ct.len(), MlKem768::CT_SIZE);
        assert_eq!(ss1.len(), 32);
        let ss2 = decapsulate::<MlKem768>(&dk, &ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_kem_512_roundtrip() {
        let (ek, dk) = keygen::<MlKem512>(&mut OsRng);
        assert_eq!(ek.len(), MlKem512::EK_SIZE);
        assert_eq!(dk.len(), MlKem512::DK_SIZE);
        let (ss1, ct) = encapsulate::<MlKem512>(&ek, &mut OsRng);
        assert_eq!(ct.len(), MlKem512::CT_SIZE);
        let ss2 = decapsulate::<MlKem512>(&dk, &ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_kem_1024_roundtrip() {
        let (ek, dk) = keygen::<MlKem1024>(&mut OsRng);
        assert_eq!(ek.len(), MlKem1024::EK_SIZE);
        assert_eq!(dk.len(), MlKem1024::DK_SIZE);
        let (ss1, ct) = encapsulate::<MlKem1024>(&ek, &mut OsRng);
        assert_eq!(ct.len(), MlKem1024::CT_SIZE);
        let ss2 = decapsulate::<MlKem1024>(&dk, &ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_kem_768_implicit_rejection() {
        let (ek, dk) = keygen::<MlKem768>(&mut OsRng);
        let (ss, ct) = encapsulate::<MlKem768>(&ek, &mut OsRng);

        // Tamper with ciphertext
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0xFF;
        let ss_bad = decapsulate::<MlKem768>(&dk, &bad_ct);

        // Should NOT return the real shared secret
        assert_ne!(ss, ss_bad);
        // Should still return 32 bytes
        assert_eq!(ss_bad.len(), 32);
    }

    #[test]
    fn test_kem_deterministic_keygen() {
        let d = [42u8; 32];
        let z = [7u8; 32];
        let (ek1, dk1) = keygen_internal::<MlKem768>(&d, &z);
        let (ek2, dk2) = keygen_internal::<MlKem768>(&d, &z);
        assert_eq!(ek1, ek2);
        assert_eq!(dk1, dk2);
    }

    #[test]
    fn test_kem_deterministic_encaps() {
        let d = [42u8; 32];
        let z = [7u8; 32];
        let (ek, dk) = keygen_internal::<MlKem768>(&d, &z);
        let m = [99u8; 32];
        let (ss1, ct1) = encapsulate_internal::<MlKem768>(&ek, &m);
        let (ss2, ct2) = encapsulate_internal::<MlKem768>(&ek, &m);
        assert_eq!(ss1, ss2);
        assert_eq!(ct1, ct2);

        let ss3 = decapsulate::<MlKem768>(&dk, &ct1);
        assert_eq!(ss1, ss3);
    }

    #[test]
    fn test_kem_different_keys_different_secrets() {
        let (ek1, _) = keygen::<MlKem768>(&mut OsRng);
        let (ek2, _) = keygen::<MlKem768>(&mut OsRng);
        let (ss1, _) = encapsulate::<MlKem768>(&ek1, &mut OsRng);
        let (ss2, _) = encapsulate::<MlKem768>(&ek2, &mut OsRng);
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_kem_multiple_roundtrips() {
        let (ek, dk) = keygen::<MlKem768>(&mut OsRng);
        for _ in 0..10 {
            let (ss1, ct) = encapsulate::<MlKem768>(&ek, &mut OsRng);
            let ss2 = decapsulate::<MlKem768>(&dk, &ct);
            assert_eq!(ss1, ss2);
        }
    }
}
