//! Hash function instantiations for ML-KEM.
//!
//! FIPS 203, Section 4.1:
//! - G: SHA3-512 → two 32-byte outputs
//! - H: SHA3-256 → one 32-byte output
//! - J: SHAKE-256 → one 32-byte output (implicit rejection PRF)

use sha3::{Sha3_256, Sha3_512, Shake256};
use sha3::digest::{Digest, Update, ExtendableOutput, XofReader};

/// G(input) = SHA3-512(input), split into two 32-byte halves.
///
/// Used in K-PKE.KeyGen to derive (rho, sigma) and in Encaps to derive (K, r).
pub fn g(input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hash = Sha3_512::digest(input);
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first.copy_from_slice(&hash[..32]);
    second.copy_from_slice(&hash[32..]);
    (first, second)
}

/// H(input) = SHA3-256(input).
///
/// Used to hash the encapsulation key for storage in the decapsulation key.
pub fn h(input: &[u8]) -> [u8; 32] {
    let hash = Sha3_256::digest(input);
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash);
    output
}

/// J(input) = first 32 bytes of SHAKE-256(input).
///
/// Used for implicit rejection in Decaps: J(z || c) produces a
/// pseudorandom shared secret when decapsulation detects tampering.
pub fn j(input: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 32];
    reader.read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g_output_length() {
        let (a, b) = g(b"test input");
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
    }

    #[test]
    fn test_g_deterministic() {
        let (a1, b1) = g(b"hello");
        let (a2, b2) = g(b"hello");
        assert_eq!(a1, a2);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_g_different_inputs() {
        let (a1, _) = g(b"hello");
        let (a2, _) = g(b"world");
        assert_ne!(a1, a2);
    }

    #[test]
    fn test_h_deterministic() {
        let a = h(b"test");
        let b = h(b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn test_j_deterministic() {
        let a = j(b"test");
        let b = j(b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn test_g_h_j_different() {
        // G, H, J should produce different outputs for the same input
        // (different hash functions)
        let (g_out, _) = g(b"same input");
        let h_out = h(b"same input");
        let j_out = j(b"same input");
        assert_ne!(g_out, h_out);
        assert_ne!(h_out, j_out);
    }
}
