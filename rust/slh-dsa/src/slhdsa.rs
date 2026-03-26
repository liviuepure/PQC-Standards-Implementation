//! SLH-DSA top-level API (FIPS 205, Algorithms 17-19).
//!
//! Provides key generation, signing, and verification for the Stateless
//! Hash-Based Digital Signature Algorithm.

use alloc::vec;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};

use crate::address::{Address, AddressType};
use crate::fors;
use crate::hash::HashSuite;
use crate::hypertree;
use crate::params::ParamSet;
use crate::utils::to_int;
use crate::xmss;

/// SLH-DSA key generation (Algorithm 17).
///
/// Returns (secret_key, public_key) where:
/// - SK = SK.seed || SK.prf || PK.seed || PK.root (4*n bytes)
/// - PK = PK.seed || PK.root (2*n bytes)
pub fn keygen<P: ParamSet, H: HashSuite>(
    rng: &mut (impl CryptoRng + RngCore),
) -> (Vec<u8>, Vec<u8>) {
    let n = P::N;

    // Generate random seeds
    let mut sk_seed = vec![0u8; n];
    let mut sk_prf = vec![0u8; n];
    let mut pk_seed = vec![0u8; n];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut sk_prf);
    rng.fill_bytes(&mut pk_seed);

    // Compute the top-level XMSS tree root (hypertree root)
    let mut adrs = Address::new();
    adrs.set_layer_address((P::D - 1) as u32);
    adrs.set_tree_address(0);
    let pk_root = xmss::xmss_node::<H>(
        &sk_seed, 0, P::HP as u32, &pk_seed, &mut adrs, n, P::LEN,
    );

    // Assemble keys
    let mut sk = Vec::with_capacity(4 * n);
    sk.extend_from_slice(&sk_seed);
    sk.extend_from_slice(&sk_prf);
    sk.extend_from_slice(&pk_seed);
    sk.extend_from_slice(&pk_root);

    let mut pk = Vec::with_capacity(2 * n);
    pk.extend_from_slice(&pk_seed);
    pk.extend_from_slice(&pk_root);

    (sk, pk)
}

/// SLH-DSA signature generation (Algorithm 18).
///
/// Signs message `msg` using secret key `sk`. Returns the signature:
/// R || SIG_FORS || SIG_HT
pub fn sign<P: ParamSet, H: HashSuite>(sk: &[u8], msg: &[u8]) -> Vec<u8> {
    let n = P::N;

    // Parse secret key
    let sk_seed = &sk[..n];
    let sk_prf = &sk[n..2 * n];
    let pk_seed = &sk[2 * n..3 * n];
    let pk_root = &sk[3 * n..4 * n];

    // Generate randomizer R
    // opt_rand = PK.seed (deterministic variant; could be random)
    let opt_rand = pk_seed;
    let r = H::prf_msg(sk_prf, opt_rand, msg, n);

    // Compute message digest
    let digest = H::h_msg(&r, pk_seed, pk_root, msg, n);

    // Parse digest into (md, idx_tree, idx_leaf)
    let md_len = (P::K * P::A + 7) / 8;
    let tree_bits = P::H - P::HP; // bits for idx_tree (= h - hp)
    let tree_bytes = (tree_bits + 7) / 8;
    let leaf_bits = P::HP;
    let leaf_bytes = (leaf_bits + 7) / 8;

    let md = &digest[..md_len];
    let idx_tree_bytes = &digest[md_len..md_len + tree_bytes];
    let idx_leaf_bytes = &digest[md_len + tree_bytes..md_len + tree_bytes + leaf_bytes];

    let idx_tree = to_int(idx_tree_bytes) & ((1u64 << tree_bits) - 1);
    let idx_leaf = (to_int(idx_leaf_bytes) & ((1u64 << leaf_bits) - 1)) as u32;

    // FORS signature
    let mut adrs = Address::new();
    adrs.set_tree_address(idx_tree);
    adrs.set_type(AddressType::ForsTree);
    adrs.set_key_pair_address(idx_leaf);

    let sig_fors = fors::fors_sign::<H>(md, sk_seed, pk_seed, &mut adrs, n, P::K, P::A);

    // Compute FORS public key
    let fors_pk = fors::fors_pk_from_sig::<H>(&sig_fors, md, pk_seed, &mut adrs, n, P::K, P::A);

    // Hypertree signature on FORS public key
    let sig_ht = hypertree::ht_sign::<H>(
        &fors_pk, sk_seed, pk_seed, idx_tree, idx_leaf,
        n, P::D, P::HP as u32, P::LEN,
    );

    // Assemble signature: R || SIG_FORS || SIG_HT
    let mut sig = Vec::with_capacity(P::SIG_SIZE);
    sig.extend_from_slice(&r);
    sig.extend_from_slice(&sig_fors);
    sig.extend_from_slice(&sig_ht);
    sig
}

/// SLH-DSA signature verification (Algorithm 19).
///
/// Verifies that `sig` is a valid signature of `msg` under public key `pk`.
pub fn verify<P: ParamSet, H: HashSuite>(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let n = P::N;

    if sig.len() != P::SIG_SIZE {
        return false;
    }
    if pk.len() != P::PK_SIZE {
        return false;
    }

    // Parse public key
    let pk_seed = &pk[..n];
    let pk_root = &pk[n..2 * n];

    // Parse signature
    let r = &sig[..n];
    let fors_sig_len = P::K * (1 + P::A) * n;
    let sig_fors = &sig[n..n + fors_sig_len];
    let sig_ht = &sig[n + fors_sig_len..];

    // Recompute message digest
    let digest = H::h_msg(r, pk_seed, pk_root, msg, n);

    let md_len = (P::K * P::A + 7) / 8;
    let tree_bits = P::H - P::HP;
    let tree_bytes = (tree_bits + 7) / 8;
    let leaf_bits = P::HP;
    let leaf_bytes = (leaf_bits + 7) / 8;

    let md = &digest[..md_len];
    let idx_tree_bytes = &digest[md_len..md_len + tree_bytes];
    let idx_leaf_bytes = &digest[md_len + tree_bytes..md_len + tree_bytes + leaf_bytes];

    let idx_tree = to_int(idx_tree_bytes) & ((1u64 << tree_bits) - 1);
    let idx_leaf = (to_int(idx_leaf_bytes) & ((1u64 << leaf_bits) - 1)) as u32;

    // Recover FORS public key from signature
    let mut adrs = Address::new();
    adrs.set_tree_address(idx_tree);
    adrs.set_type(AddressType::ForsTree);
    adrs.set_key_pair_address(idx_leaf);

    let fors_pk =
        fors::fors_pk_from_sig::<H>(sig_fors, md, pk_seed, &mut adrs, n, P::K, P::A);

    // Verify hypertree signature on FORS public key
    hypertree::ht_verify::<H>(
        &fors_pk, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root,
        n, P::D, P::HP as u32, P::LEN,
    )
}
