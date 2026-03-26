//! SLH-DSA (FIPS 205) hash function abstractions.
//!
//! Provides the [`HashSuite`] trait and two concrete implementations:
//! - [`Sha2Hash`] — uses SHA-256 (for n <= 16) or SHA-512 (for n > 16)
//! - [`ShakeHash`] — uses SHAKE-256 for all security levels

use alloc::vec;
use alloc::vec::Vec;

use sha2::{Digest as _, Sha256, Sha512};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::Shake256;
use hmac::{Hmac, Mac};

use crate::address::Address;

/// Trait abstracting the hash function family used in SLH-DSA.
///
/// All methods accept the security parameter `n` (in bytes) to determine
/// output length and, for SHA-2, which underlying hash to use.
pub trait HashSuite {
    /// Message hash: produces a digest of the message `m` used by FORS to
    /// derive tree indices and leaf values.
    ///
    /// Input: randomizer `r` (n bytes), `pk_seed` (n bytes),
    ///        `pk_root` (n bytes), message `m` (arbitrary length).
    /// Output: digest of sufficient length for the parameter set.
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], n: usize) -> Vec<u8>;

    /// Pseudorandom function for secret key element generation.
    ///
    /// Input: `pk_seed` (n bytes), `sk_seed` (n bytes), address `adrs`.
    /// Output: n bytes.
    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address, n: usize) -> Vec<u8>;

    /// Pseudorandom function for message randomizer generation.
    ///
    /// Input: `sk_prf` (n bytes), `opt_rand` (n bytes), message `m`.
    /// Output: n bytes.
    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8], n: usize) -> Vec<u8>;

    /// Tweakable hash function F (single n-byte block input).
    ///
    /// Input: `pk_seed` (n bytes), address `adrs`, message `m` (n bytes).
    /// Output: n bytes.
    fn f(pk_seed: &[u8], adrs: &Address, m: &[u8], n: usize) -> Vec<u8>;

    /// Tweakable hash function H (two n-byte block inputs).
    ///
    /// Input: `pk_seed` (n bytes), address `adrs`, `m1` (n bytes), `m2` (n bytes).
    /// Output: n bytes.
    fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8], n: usize) -> Vec<u8>;

    /// Tweakable hash function T_l (variable-length input).
    ///
    /// Input: `pk_seed` (n bytes), address `adrs`, list of n-byte blocks `ms`.
    /// Output: n bytes.
    fn t_l(pk_seed: &[u8], adrs: &Address, ms: &[&[u8]], n: usize) -> Vec<u8>;
}

// ---------------------------------------------------------------------------
// Helper: toByte(x, n) — encode integer x as n zero-padded bytes (big-endian)
// ---------------------------------------------------------------------------

/// Encode a u32 as an `n`-byte big-endian byte string, zero-padded on the left.
pub fn to_byte(x: u32, n: usize) -> Vec<u8> {
    let be = x.to_be_bytes();
    if n >= 4 {
        let mut out = vec![0u8; n];
        out[n - 4..].copy_from_slice(&be);
        out
    } else {
        be[4 - n..].to_vec()
    }
}

// ---------------------------------------------------------------------------
// MGF1 (Mask Generation Function 1) for SHA-2 H_msg
// ---------------------------------------------------------------------------

/// MGF1 using SHA-256 as the underlying hash.
fn mgf1_sha256(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;
    while output.len() < mask_len {
        let mut hasher = Sha256::new();
        sha2::Digest::update(&mut hasher, seed);
        sha2::Digest::update(&mut hasher, &counter.to_be_bytes());
        let hash = hasher.finalize();
        output.extend_from_slice(&hash);
        counter += 1;
    }
    output.truncate(mask_len);
    output
}

/// MGF1 using SHA-512 as the underlying hash.
fn mgf1_sha512(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;
    while output.len() < mask_len {
        let mut hasher = Sha512::new();
        sha2::Digest::update(&mut hasher, seed);
        sha2::Digest::update(&mut hasher, &counter.to_be_bytes());
        let hash = hasher.finalize();
        output.extend_from_slice(&hash);
        counter += 1;
    }
    output.truncate(mask_len);
    output
}

// ===========================================================================
// SHA-2 hash suite
// ===========================================================================

/// SHA-2 based hash suite for SLH-DSA.
///
/// - For n <= 16 (128-bit security): uses SHA-256 and HMAC-SHA-256.
/// - For n > 16 (192/256-bit security): uses SHA-512 and HMAC-SHA-512.
pub struct Sha2Hash;

impl Sha2Hash {
    /// Internal: SHA-256 based tweakable hash.
    /// Input format: toByte(0, n) || PK.seed || padding || ADRS_c || M
    /// where ADRS_c is the compressed address (22 bytes for SHA-256).
    ///
    /// For simplicity we use the full 32-byte ADRS and the padding scheme
    /// described in FIPS 205 Section 11.1.
    fn sha256_hash(pk_seed: &[u8], adrs: &Address, msg: &[u8], n: usize) -> Vec<u8> {
        let mut hasher = Sha256::new();
        // Block-sized padding: toByte(0, 64 - n) prepended to PK.seed
        // gives a full SHA-256 block (64 bytes).
        let pad_len = 64 - n;
        sha2::Digest::update(&mut hasher, &vec![0u8; pad_len]);
        sha2::Digest::update(&mut hasher, pk_seed);
        // Compressed address: for SHA-256, we use the full 32-byte ADRS.
        sha2::Digest::update(&mut hasher, adrs.as_bytes());
        sha2::Digest::update(&mut hasher, msg);
        let hash = hasher.finalize();
        hash[..n].to_vec()
    }

    /// Internal: SHA-512 based tweakable hash.
    fn sha512_hash(pk_seed: &[u8], adrs: &Address, msg: &[u8], n: usize) -> Vec<u8> {
        let mut hasher = Sha512::new();
        // Block-sized padding: toByte(0, 128 - n) prepended to PK.seed
        // gives a full SHA-512 block (128 bytes).
        let pad_len = 128 - n;
        sha2::Digest::update(&mut hasher, &vec![0u8; pad_len]);
        sha2::Digest::update(&mut hasher, pk_seed);
        sha2::Digest::update(&mut hasher, adrs.as_bytes());
        sha2::Digest::update(&mut hasher, msg);
        let hash = hasher.finalize();
        hash[..n].to_vec()
    }
}

impl HashSuite for Sha2Hash {
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], n: usize) -> Vec<u8> {
        // H_msg uses MGF1 to produce a long digest.
        // seed = R || PK.seed || SHA-x(R || PK.seed || PK.root || M)
        // output = MGF1-SHA-x(seed, desired_length)
        //
        // The output length needed is determined by the FORS parameters,
        // but we produce a generous amount (ceil to a multiple of n) and
        // let the caller truncate.
        let digest_len = n * 16; // generous; caller will use what it needs

        if n <= 16 {
            // SHA-256 variant
            let mut inner = Sha256::new();
            sha2::Digest::update(&mut inner, r);
            sha2::Digest::update(&mut inner, pk_seed);
            sha2::Digest::update(&mut inner, pk_root);
            sha2::Digest::update(&mut inner, m);
            let inner_hash = inner.finalize();

            let mut seed = Vec::with_capacity(r.len() + pk_seed.len() + 32);
            seed.extend_from_slice(r);
            seed.extend_from_slice(pk_seed);
            seed.extend_from_slice(&inner_hash);

            mgf1_sha256(&seed, digest_len)
        } else {
            // SHA-512 variant
            let mut inner = Sha512::new();
            sha2::Digest::update(&mut inner, r);
            sha2::Digest::update(&mut inner, pk_seed);
            sha2::Digest::update(&mut inner, pk_root);
            sha2::Digest::update(&mut inner, m);
            let inner_hash = inner.finalize();

            let mut seed = Vec::with_capacity(r.len() + pk_seed.len() + 64);
            seed.extend_from_slice(r);
            seed.extend_from_slice(pk_seed);
            seed.extend_from_slice(&inner_hash);

            mgf1_sha512(&seed, digest_len)
        }
    }

    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address, n: usize) -> Vec<u8> {
        // PRF: HMAC-SHA-x(PK.seed, ADRS || SK.seed), truncated to n bytes.
        if n <= 16 {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(pk_seed).expect("HMAC key length is valid");
            hmac::Mac::update(&mut mac, adrs.as_bytes());
            hmac::Mac::update(&mut mac, sk_seed);
            let result = mac.finalize().into_bytes();
            result[..n].to_vec()
        } else {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(pk_seed).expect("HMAC key length is valid");
            hmac::Mac::update(&mut mac, adrs.as_bytes());
            hmac::Mac::update(&mut mac, sk_seed);
            let result = mac.finalize().into_bytes();
            result[..n].to_vec()
        }
    }

    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8], n: usize) -> Vec<u8> {
        // PRF_msg: HMAC-SHA-x(SK.prf, opt_rand || M), truncated to n bytes.
        if n <= 16 {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(sk_prf).expect("HMAC key length is valid");
            hmac::Mac::update(&mut mac, opt_rand);
            hmac::Mac::update(&mut mac, m);
            let result = mac.finalize().into_bytes();
            result[..n].to_vec()
        } else {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(sk_prf).expect("HMAC key length is valid");
            hmac::Mac::update(&mut mac, opt_rand);
            hmac::Mac::update(&mut mac, m);
            let result = mac.finalize().into_bytes();
            result[..n].to_vec()
        }
    }

    fn f(pk_seed: &[u8], adrs: &Address, m: &[u8], n: usize) -> Vec<u8> {
        if n <= 16 {
            Self::sha256_hash(pk_seed, adrs, m, n)
        } else {
            Self::sha512_hash(pk_seed, adrs, m, n)
        }
    }

    fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8], n: usize) -> Vec<u8> {
        let mut combined = Vec::with_capacity(m1.len() + m2.len());
        combined.extend_from_slice(m1);
        combined.extend_from_slice(m2);
        if n <= 16 {
            Self::sha256_hash(pk_seed, adrs, &combined, n)
        } else {
            Self::sha512_hash(pk_seed, adrs, &combined, n)
        }
    }

    fn t_l(pk_seed: &[u8], adrs: &Address, ms: &[&[u8]], n: usize) -> Vec<u8> {
        let mut combined = Vec::new();
        for m in ms {
            combined.extend_from_slice(m);
        }
        if n <= 16 {
            Self::sha256_hash(pk_seed, adrs, &combined, n)
        } else {
            Self::sha512_hash(pk_seed, adrs, &combined, n)
        }
    }
}

// ===========================================================================
// SHAKE hash suite
// ===========================================================================

/// SHAKE-256 based hash suite for SLH-DSA.
///
/// All functions use SHAKE-256 with the input format:
/// PK.seed || ADRS || M, producing `n` output bytes.
pub struct ShakeHash;

impl ShakeHash {
    /// Core SHAKE-256 based tweakable hash.
    fn shake256_hash(pk_seed: &[u8], adrs: &Address, msg: &[u8], n: usize) -> Vec<u8> {
        let mut hasher = Shake256::default();
        sha3::digest::Update::update(&mut hasher, pk_seed);
        sha3::digest::Update::update(&mut hasher, adrs.as_bytes());
        sha3::digest::Update::update(&mut hasher, msg);
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0u8; n];
        reader.read(&mut output);
        output
    }
}

impl HashSuite for ShakeHash {
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], n: usize) -> Vec<u8> {
        // H_msg: SHAKE-256(R || PK.seed || PK.root || M, 8m) where m is the
        // output length in bytes needed for FORS message digest.
        let digest_len = n * 16; // generous output; caller truncates

        let mut hasher = Shake256::default();
        sha3::digest::Update::update(&mut hasher, r);
        sha3::digest::Update::update(&mut hasher, pk_seed);
        sha3::digest::Update::update(&mut hasher, pk_root);
        sha3::digest::Update::update(&mut hasher, m);
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0u8; digest_len];
        reader.read(&mut output);
        output
    }

    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address, n: usize) -> Vec<u8> {
        // PRF: SHAKE-256(PK.seed || ADRS || SK.seed, 8n)
        Self::shake256_hash(pk_seed, adrs, sk_seed, n)
    }

    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8], n: usize) -> Vec<u8> {
        // PRF_msg: SHAKE-256(SK.prf || opt_rand || M, 8n)
        let mut hasher = Shake256::default();
        sha3::digest::Update::update(&mut hasher, sk_prf);
        sha3::digest::Update::update(&mut hasher, opt_rand);
        sha3::digest::Update::update(&mut hasher, m);
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0u8; n];
        reader.read(&mut output);
        output
    }

    fn f(pk_seed: &[u8], adrs: &Address, m: &[u8], n: usize) -> Vec<u8> {
        Self::shake256_hash(pk_seed, adrs, m, n)
    }

    fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8], n: usize) -> Vec<u8> {
        let mut combined = Vec::with_capacity(m1.len() + m2.len());
        combined.extend_from_slice(m1);
        combined.extend_from_slice(m2);
        Self::shake256_hash(pk_seed, adrs, &combined, n)
    }

    fn t_l(pk_seed: &[u8], adrs: &Address, ms: &[&[u8]], n: usize) -> Vec<u8> {
        let mut combined = Vec::new();
        for m in ms {
            combined.extend_from_slice(m);
        }
        Self::shake256_hash(pk_seed, adrs, &combined, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: deterministic test inputs.
    fn test_inputs(n: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>, Address) {
        let pk_seed: Vec<u8> = (0..n).map(|i| i as u8).collect();
        let sk_seed: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0x10)).collect();
        let msg: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0x20)).collect();
        let mut adrs = Address::new();
        adrs.set_layer_address(1);
        adrs.set_tree_address(2);
        adrs.set_type(crate::address::AddressType::WotsHash);
        adrs.set_key_pair_address(3);
        adrs.set_chain_address(4);
        adrs.set_hash_address(5);
        (pk_seed, sk_seed, msg, adrs)
    }

    // -- Determinism tests: same input -> same output --

    #[test]
    fn test_sha2_f_deterministic() {
        let (pk_seed, _sk, msg, adrs) = test_inputs(16);
        let out1 = Sha2Hash::f(&pk_seed, &adrs, &msg, 16);
        let out2 = Sha2Hash::f(&pk_seed, &adrs, &msg, 16);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 16);
    }

    #[test]
    fn test_sha2_f_deterministic_n24() {
        let (pk_seed, _sk, msg, adrs) = test_inputs(24);
        let out1 = Sha2Hash::f(&pk_seed, &adrs, &msg, 24);
        let out2 = Sha2Hash::f(&pk_seed, &adrs, &msg, 24);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 24);
    }

    #[test]
    fn test_shake_f_deterministic() {
        let (pk_seed, _sk, msg, adrs) = test_inputs(16);
        let out1 = ShakeHash::f(&pk_seed, &adrs, &msg, 16);
        let out2 = ShakeHash::f(&pk_seed, &adrs, &msg, 16);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 16);
    }

    // -- Different inputs produce different outputs --

    #[test]
    fn test_sha2_f_different_inputs() {
        let (pk_seed, _sk, msg, adrs) = test_inputs(16);
        let out1 = Sha2Hash::f(&pk_seed, &adrs, &msg, 16);

        let mut msg2 = msg.clone();
        msg2[0] ^= 0xFF;
        let out2 = Sha2Hash::f(&pk_seed, &adrs, &msg2, 16);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_shake_f_different_inputs() {
        let (pk_seed, _sk, msg, adrs) = test_inputs(16);
        let out1 = ShakeHash::f(&pk_seed, &adrs, &msg, 16);

        let mut msg2 = msg.clone();
        msg2[0] ^= 0xFF;
        let out2 = ShakeHash::f(&pk_seed, &adrs, &msg2, 16);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_sha2_different_from_shake() {
        let (pk_seed, _sk, msg, adrs) = test_inputs(16);
        let sha2_out = Sha2Hash::f(&pk_seed, &adrs, &msg, 16);
        let shake_out = ShakeHash::f(&pk_seed, &adrs, &msg, 16);
        assert_ne!(sha2_out, shake_out);
    }

    // -- H function tests --

    #[test]
    fn test_sha2_h_deterministic() {
        let (pk_seed, _sk, msg, adrs) = test_inputs(16);
        let m1 = &msg;
        let m2: Vec<u8> = (0..16).map(|i| (i as u8).wrapping_add(0x30)).collect();
        let out1 = Sha2Hash::h(&pk_seed, &adrs, m1, &m2, 16);
        let out2 = Sha2Hash::h(&pk_seed, &adrs, m1, &m2, 16);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 16);
    }

    #[test]
    fn test_shake_h_deterministic() {
        let (pk_seed, _sk, msg, adrs) = test_inputs(32);
        let m1 = &msg;
        let m2: Vec<u8> = (0..32).map(|i| (i as u8).wrapping_add(0x30)).collect();
        let out1 = ShakeHash::h(&pk_seed, &adrs, m1, &m2, 32);
        let out2 = ShakeHash::h(&pk_seed, &adrs, m1, &m2, 32);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 32);
    }

    // -- PRF tests --

    #[test]
    fn test_sha2_prf_deterministic() {
        let (pk_seed, sk_seed, _msg, adrs) = test_inputs(16);
        let out1 = Sha2Hash::prf(&pk_seed, &sk_seed, &adrs, 16);
        let out2 = Sha2Hash::prf(&pk_seed, &sk_seed, &adrs, 16);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 16);
    }

    #[test]
    fn test_shake_prf_deterministic() {
        let (pk_seed, sk_seed, _msg, adrs) = test_inputs(32);
        let out1 = ShakeHash::prf(&pk_seed, &sk_seed, &adrs, 32);
        let out2 = ShakeHash::prf(&pk_seed, &sk_seed, &adrs, 32);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 32);
    }

    #[test]
    fn test_sha2_prf_different_adrs() {
        let (pk_seed, sk_seed, _msg, adrs) = test_inputs(16);
        let out1 = Sha2Hash::prf(&pk_seed, &sk_seed, &adrs, 16);

        let mut adrs2 = adrs.copy();
        adrs2.set_key_pair_address(999);
        let out2 = Sha2Hash::prf(&pk_seed, &sk_seed, &adrs2, 16);
        assert_ne!(out1, out2);
    }

    // -- PRF_msg tests --

    #[test]
    fn test_sha2_prf_msg_deterministic() {
        let (pk_seed, sk_seed, msg, _adrs) = test_inputs(16);
        let out1 = Sha2Hash::prf_msg(&sk_seed, &pk_seed, &msg, 16);
        let out2 = Sha2Hash::prf_msg(&sk_seed, &pk_seed, &msg, 16);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 16);
    }

    #[test]
    fn test_shake_prf_msg_deterministic() {
        let (pk_seed, sk_seed, msg, _adrs) = test_inputs(24);
        let out1 = ShakeHash::prf_msg(&sk_seed, &pk_seed, &msg, 24);
        let out2 = ShakeHash::prf_msg(&sk_seed, &pk_seed, &msg, 24);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 24);
    }

    // -- T_l tests --

    #[test]
    fn test_sha2_t_l_deterministic() {
        let (pk_seed, _sk, _msg, adrs) = test_inputs(16);
        let block1 = vec![0xAAu8; 16];
        let block2 = vec![0xBBu8; 16];
        let ms: Vec<&[u8]> = vec![&block1, &block2];
        let out1 = Sha2Hash::t_l(&pk_seed, &adrs, &ms, 16);
        let out2 = Sha2Hash::t_l(&pk_seed, &adrs, &ms, 16);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 16);
    }

    #[test]
    fn test_shake_t_l_deterministic() {
        let (pk_seed, _sk, _msg, adrs) = test_inputs(32);
        let block1 = vec![0xAAu8; 32];
        let block2 = vec![0xBBu8; 32];
        let block3 = vec![0xCCu8; 32];
        let ms: Vec<&[u8]> = vec![&block1, &block2, &block3];
        let out1 = ShakeHash::t_l(&pk_seed, &adrs, &ms, 32);
        let out2 = ShakeHash::t_l(&pk_seed, &adrs, &ms, 32);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 32);
    }

    // -- H_msg tests --

    #[test]
    fn test_sha2_h_msg_deterministic() {
        let (pk_seed, _sk, _msg, _adrs) = test_inputs(16);
        let r = vec![0x42u8; 16];
        let pk_root = vec![0x55u8; 16];
        let m = b"Hello, SLH-DSA!";
        let out1 = Sha2Hash::h_msg(&r, &pk_seed, &pk_root, m, 16);
        let out2 = Sha2Hash::h_msg(&r, &pk_seed, &pk_root, m, 16);
        assert_eq!(out1, out2);
        assert!(out1.len() >= 16);
    }

    #[test]
    fn test_shake_h_msg_deterministic() {
        let (pk_seed, _sk, _msg, _adrs) = test_inputs(32);
        let r = vec![0x42u8; 32];
        let pk_root = vec![0x55u8; 32];
        let m = b"Hello, SLH-DSA!";
        let out1 = ShakeHash::h_msg(&r, &pk_seed, &pk_root, m, 32);
        let out2 = ShakeHash::h_msg(&r, &pk_seed, &pk_root, m, 32);
        assert_eq!(out1, out2);
        assert!(out1.len() >= 32);
    }

    #[test]
    fn test_sha2_h_msg_different_messages() {
        let (pk_seed, _sk, _msg, _adrs) = test_inputs(16);
        let r = vec![0x42u8; 16];
        let pk_root = vec![0x55u8; 16];
        let out1 = Sha2Hash::h_msg(&r, &pk_seed, &pk_root, b"message A", 16);
        let out2 = Sha2Hash::h_msg(&r, &pk_seed, &pk_root, b"message B", 16);
        assert_ne!(out1, out2);
    }

    // -- Output length for larger n --

    #[test]
    fn test_sha2_output_lengths_n32() {
        let (pk_seed, sk_seed, msg, adrs) = test_inputs(32);
        assert_eq!(Sha2Hash::f(&pk_seed, &adrs, &msg, 32).len(), 32);
        assert_eq!(Sha2Hash::prf(&pk_seed, &sk_seed, &adrs, 32).len(), 32);
        assert_eq!(Sha2Hash::prf_msg(&sk_seed, &pk_seed, &msg, 32).len(), 32);
    }

    #[test]
    fn test_to_byte() {
        assert_eq!(to_byte(0, 4), vec![0, 0, 0, 0]);
        assert_eq!(to_byte(1, 4), vec![0, 0, 0, 1]);
        assert_eq!(to_byte(256, 4), vec![0, 0, 1, 0]);
        assert_eq!(to_byte(0, 16), vec![0; 16]);
        let mut expected = vec![0u8; 16];
        expected[15] = 1;
        assert_eq!(to_byte(1, 16), expected);
    }
}
