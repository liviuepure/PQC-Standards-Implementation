//! Integration tests for SLH-DSA (FIPS 205).

use rand::rngs::StdRng;
use rand::SeedableRng;

use slh_dsa::address::{Address, AddressType};
use slh_dsa::hash::{ShakeHash, Sha2Hash};
use slh_dsa::params::*;
use slh_dsa::wots;
use slh_dsa::xmss;
use slh_dsa::fors;
use slh_dsa::slhdsa;

// ======================================================================
// WOTS+ tests
// ======================================================================

#[test]
fn test_wots_sign_verify_shake_128f() {
    let n = Shake_128f::N;
    let len = Shake_128f::LEN;
    let len1 = Shake_128f::LEN1;
    let len2 = Shake_128f::LEN2;

    let sk_seed: Vec<u8> = (0..n).map(|i| i as u8).collect();
    let pk_seed: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0x10)).collect();
    let msg: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0x20)).collect();

    let mut adrs = Address::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(0);
    adrs.set_type(AddressType::WotsHash);
    adrs.set_key_pair_address(0);

    // Generate public key directly
    let pk = wots::wots_pkgen::<ShakeHash>(&sk_seed, &pk_seed, &mut adrs, n, len);

    // Reset address for signing
    adrs.set_type(AddressType::WotsHash);
    adrs.set_key_pair_address(0);

    // Sign
    let sig = wots::wots_sign::<ShakeHash>(&msg, &sk_seed, &pk_seed, &mut adrs, n, len, len1, len2);
    assert_eq!(sig.len(), len * n);

    // Recover public key from signature
    adrs.set_type(AddressType::WotsHash);
    adrs.set_key_pair_address(0);
    let pk_recovered = wots::wots_pk_from_sig::<ShakeHash>(&sig, &msg, &pk_seed, &mut adrs, n, len, len1, len2);

    assert_eq!(pk, pk_recovered, "WOTS+ pk_from_sig should match pkgen");
}

#[test]
fn test_wots_sign_verify_sha2_128f() {
    let n = Sha2_128f::N;
    let len = Sha2_128f::LEN;
    let len1 = Sha2_128f::LEN1;
    let len2 = Sha2_128f::LEN2;

    let sk_seed: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0x30)).collect();
    let pk_seed: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0x40)).collect();
    let msg: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0x50)).collect();

    let mut adrs = Address::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(0);
    adrs.set_type(AddressType::WotsHash);
    adrs.set_key_pair_address(0);

    let pk = wots::wots_pkgen::<Sha2Hash>(&sk_seed, &pk_seed, &mut adrs, n, len);

    adrs.set_type(AddressType::WotsHash);
    adrs.set_key_pair_address(0);
    let sig = wots::wots_sign::<Sha2Hash>(&msg, &sk_seed, &pk_seed, &mut adrs, n, len, len1, len2);

    adrs.set_type(AddressType::WotsHash);
    adrs.set_key_pair_address(0);
    let pk_recovered = wots::wots_pk_from_sig::<Sha2Hash>(&sig, &msg, &pk_seed, &mut adrs, n, len, len1, len2);

    assert_eq!(pk, pk_recovered, "SHA2 WOTS+ pk_from_sig should match pkgen");
}

// ======================================================================
// XMSS tests
// ======================================================================

#[test]
fn test_xmss_sign_verify_shake_128f() {
    // SHAKE-128f: hp=3, so XMSS tree has 8 leaves
    let n = Shake_128f::N;
    let hp = Shake_128f::HP as u32;
    let len = Shake_128f::LEN;

    let sk_seed: Vec<u8> = (0..n).map(|i| i as u8).collect();
    let pk_seed: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0x10)).collect();
    let msg: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0x20)).collect();

    // Compute tree root
    let mut adrs = Address::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(0);
    let root = xmss::xmss_node::<ShakeHash>(&sk_seed, 0, hp, &pk_seed, &mut adrs, n, len);

    // Sign at leaf index 3
    let idx = 3u32;
    adrs.set_layer_address(0);
    adrs.set_tree_address(0);
    let sig = xmss::xmss_sign::<ShakeHash>(&msg, &sk_seed, idx, &pk_seed, &mut adrs, n, hp, len);
    assert_eq!(sig.len(), (len + hp as usize) * n);

    // Recover root
    adrs.set_layer_address(0);
    adrs.set_tree_address(0);
    let recovered = xmss::xmss_pk_from_sig::<ShakeHash>(idx, &sig, &msg, &pk_seed, &mut adrs, n, hp, len);

    assert_eq!(root, recovered, "XMSS recovered root should match computed root");
}

// ======================================================================
// FORS tests
// ======================================================================

#[test]
fn test_fors_sign_verify_shake_128f() {
    let n = Shake_128f::N;
    let k = Shake_128f::K;
    let a = Shake_128f::A;

    let sk_seed: Vec<u8> = (0..n).map(|i| i as u8).collect();
    let pk_seed: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0x10)).collect();

    // md needs ceil(k*a/8) bytes
    let md_len = (k * a + 7) / 8;
    let md: Vec<u8> = (0..md_len).map(|i| (i as u8).wrapping_add(0x30)).collect();

    let mut adrs = Address::new();
    adrs.set_tree_address(0);
    adrs.set_type(AddressType::ForsTree);
    adrs.set_key_pair_address(0);

    let sig_fors = fors::fors_sign::<ShakeHash>(&md, &sk_seed, &pk_seed, &mut adrs, n, k, a);
    assert_eq!(sig_fors.len(), k * (1 + a) * n);

    // Recover FORS pk
    adrs.set_tree_address(0);
    adrs.set_type(AddressType::ForsTree);
    adrs.set_key_pair_address(0);
    let pk1 = fors::fors_pk_from_sig::<ShakeHash>(&sig_fors, &md, &pk_seed, &mut adrs, n, k, a);

    // Sign again and recover — should be identical
    adrs.set_tree_address(0);
    adrs.set_type(AddressType::ForsTree);
    adrs.set_key_pair_address(0);
    let sig_fors2 = fors::fors_sign::<ShakeHash>(&md, &sk_seed, &pk_seed, &mut adrs, n, k, a);

    adrs.set_tree_address(0);
    adrs.set_type(AddressType::ForsTree);
    adrs.set_key_pair_address(0);
    let pk2 = fors::fors_pk_from_sig::<ShakeHash>(&sig_fors2, &md, &pk_seed, &mut adrs, n, k, a);

    assert_eq!(pk1, pk2, "FORS pk should be deterministic");
}

// ======================================================================
// Full SLH-DSA roundtrip tests
// ======================================================================

#[test]
fn test_slhdsa_shake_128f_roundtrip() {
    let mut rng = StdRng::seed_from_u64(42);
    let (sk, pk) = slhdsa::keygen::<Shake_128f, ShakeHash>(&mut rng);

    assert_eq!(sk.len(), Shake_128f::SK_SIZE);
    assert_eq!(pk.len(), Shake_128f::PK_SIZE);

    let msg = b"Hello, SLH-DSA SHAKE-128f!";
    let sig = slhdsa::sign::<Shake_128f, ShakeHash>(&sk, msg);
    assert_eq!(sig.len(), Shake_128f::SIG_SIZE);

    let valid = slhdsa::verify::<Shake_128f, ShakeHash>(&pk, msg, &sig);
    assert!(valid, "Signature should verify for SHAKE-128f");
}

#[test]
fn test_slhdsa_sha2_128f_roundtrip() {
    let mut rng = StdRng::seed_from_u64(99);
    let (sk, pk) = slhdsa::keygen::<Sha2_128f, Sha2Hash>(&mut rng);

    assert_eq!(sk.len(), Sha2_128f::SK_SIZE);
    assert_eq!(pk.len(), Sha2_128f::PK_SIZE);

    let msg = b"Hello, SLH-DSA SHA2-128f!";
    let sig = slhdsa::sign::<Sha2_128f, Sha2Hash>(&sk, msg);
    assert_eq!(sig.len(), Sha2_128f::SIG_SIZE);

    let valid = slhdsa::verify::<Sha2_128f, Sha2Hash>(&pk, msg, &sig);
    assert!(valid, "Signature should verify for SHA2-128f");
}

#[test]
fn test_slhdsa_reject_tampered_sig() {
    let mut rng = StdRng::seed_from_u64(123);
    let (sk, pk) = slhdsa::keygen::<Shake_128f, ShakeHash>(&mut rng);

    let msg = b"Tamper test message";
    let mut sig = slhdsa::sign::<Shake_128f, ShakeHash>(&sk, msg);

    // Flip a byte in the middle of the signature
    let mid = sig.len() / 2;
    sig[mid] ^= 0xFF;

    let valid = slhdsa::verify::<Shake_128f, ShakeHash>(&pk, msg, &sig);
    assert!(!valid, "Tampered signature should not verify");
}

#[test]
fn test_slhdsa_reject_tampered_msg() {
    let mut rng = StdRng::seed_from_u64(456);
    let (sk, pk) = slhdsa::keygen::<Shake_128f, ShakeHash>(&mut rng);

    let msg = b"Original message";
    let sig = slhdsa::sign::<Shake_128f, ShakeHash>(&sk, msg);

    let tampered_msg = b"Tampered message";
    let valid = slhdsa::verify::<Shake_128f, ShakeHash>(&pk, tampered_msg, &sig);
    assert!(!valid, "Signature should not verify for tampered message");
}

#[test]
fn test_slhdsa_reject_wrong_pk() {
    let mut rng = StdRng::seed_from_u64(789);
    let (sk, _pk) = slhdsa::keygen::<Shake_128f, ShakeHash>(&mut rng);
    let (_sk2, pk2) = slhdsa::keygen::<Shake_128f, ShakeHash>(&mut rng);

    let msg = b"Wrong key test";
    let sig = slhdsa::sign::<Shake_128f, ShakeHash>(&sk, msg);

    let valid = slhdsa::verify::<Shake_128f, ShakeHash>(&pk2, msg, &sig);
    assert!(!valid, "Signature should not verify under wrong public key");
}

#[test]
fn test_slhdsa_signature_sizes() {
    // Verify signature sizes match FIPS 205 Table 1
    assert_eq!(Shake_128f::SIG_SIZE, 17_088);
    assert_eq!(Sha2_128f::SIG_SIZE, 17_088);
    assert_eq!(Shake_128s::SIG_SIZE, 7_856);
    assert_eq!(Sha2_128s::SIG_SIZE, 7_856);
}

#[test]
fn test_slhdsa_reject_wrong_sig_length() {
    let mut rng = StdRng::seed_from_u64(101);
    let (_sk, pk) = slhdsa::keygen::<Shake_128f, ShakeHash>(&mut rng);

    let msg = b"Length test";
    let short_sig = vec![0u8; 100];
    let valid = slhdsa::verify::<Shake_128f, ShakeHash>(&pk, msg, &short_sig);
    assert!(!valid, "Too-short signature should not verify");
}

#[test]
fn test_slhdsa_empty_message() {
    let mut rng = StdRng::seed_from_u64(202);
    let (sk, pk) = slhdsa::keygen::<Shake_128f, ShakeHash>(&mut rng);

    let msg = b"";
    let sig = slhdsa::sign::<Shake_128f, ShakeHash>(&sk, msg);
    let valid = slhdsa::verify::<Shake_128f, ShakeHash>(&pk, msg, &sig);
    assert!(valid, "Empty message should still verify");
}
