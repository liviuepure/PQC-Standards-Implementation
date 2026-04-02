/// HQC KEM: Key Generation, Encapsulation, Decapsulation.
///
/// Implements the Fujisaki-Okeyama transform for CCA security on top of
/// the HQC PKE scheme.

use rand_core::CryptoRngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::gf2::*;
use crate::params::*;
use crate::tensor::*;

/// SHAKE256-based seed expander.
struct SeedExpander {
    reader: sha3::Shake256Reader,
}

impl SeedExpander {
    fn new(seed: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        SeedExpander {
            reader: hasher.finalize_xof(),
        }
    }

    fn read(&mut self, buf: &mut [u8]) {
        self.reader.read(buf);
    }
}

/// Generates a random vector of n bits using the seed expander.
fn vect_set_random(se: &mut SeedExpander, n: usize) -> Vec<u64> {
    let n_words = (n + 63) / 64;
    let n_bytes = n_words * 8;
    let mut buf = vec![0u8; n_bytes];
    se.read(&mut buf);
    let mut v = vect_from_bytes(&buf, n_words);
    let rem = n % 64;
    if rem != 0 {
        v[n_words - 1] &= (1u64 << rem) - 1;
    }
    v
}

/// Generates a random vector of n bits with exactly `weight` bits set,
/// using rejection sampling from the seed expander.
fn vect_set_random_fixed_weight(se: &mut SeedExpander, n: usize, weight: usize) -> Vec<u64> {
    let n_words = (n + 63) / 64;
    let mut v = vec![0u64; n_words];
    let mut positions: Vec<u32> = Vec::with_capacity(weight);
    let mut buf = [0u8; 4];

    for _ in 0..weight {
        loop {
            se.read(&mut buf);
            let pos = u32::from_le_bytes(buf) % (n as u32);

            // Rejection sampling for duplicates
            if !positions.contains(&pos) {
                positions.push(pos);
                break;
            }
        }
    }

    for &pos in &positions {
        vect_set_bit(&mut v, pos as usize);
    }

    v
}

/// Computes d = SHAKE256(H_domain || m), producing 64 bytes.
fn compute_d(m: &[u8]) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(&[HF_CT_DOMAIN]);
    h.update(m);
    let mut d = vec![0u8; SHARED_SECRET_BYTES];
    h.finalize_xof().read(&mut d);
    d
}

/// Computes theta = SHAKE256(G_domain || m || pk || d).
fn compute_theta(m: &[u8], pk: &[u8], d: &[u8], _p: &Params) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(&[GF_CT_DOMAIN]);
    h.update(m);
    h.update(pk);
    h.update(d);
    let mut theta = vec![0u8; SEED_BYTES];
    h.finalize_xof().read(&mut theta);
    theta
}

/// Computes ss = SHAKE256(K_domain || m || u_bytes || v_bytes).
fn compute_ss(m: &[u8], u: &[u64], v: &[u64], p: &Params) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(&[KF_CT_DOMAIN]);
    h.update(m);
    h.update(&vect_to_bytes(u, p.vec_n_size_bytes));
    h.update(&vect_to_bytes(v, p.vec_n1n2_size_bytes));
    let mut ss = vec![0u8; SHARED_SECRET_BYTES];
    h.finalize_xof().read(&mut ss);
    ss
}

/// PKE Encrypt: returns (u, v).
fn pke_encrypt(m: &[u8], theta: &[u8], pk: &[u8], p: &Params) -> (Vec<u64>, Vec<u64>) {
    // Parse public key
    let pk_seed = &pk[..SEED_BYTES];
    let s = vect_from_bytes(&pk[SEED_BYTES..], p.vec_n_size64);

    // Generate h from pk_seed
    let mut pk_expander = SeedExpander::new(pk_seed);
    let h = vect_set_random(&mut pk_expander, p.n);

    // Generate r1, r2, e from theta
    let mut theta_expander = SeedExpander::new(theta);
    let r1 = vect_set_random_fixed_weight(&mut theta_expander, p.n, p.wr);
    let r2 = vect_set_random_fixed_weight(&mut theta_expander, p.n, p.wr);
    let e = vect_set_random_fixed_weight(&mut theta_expander, p.n, p.we);

    // u = r1 + h * r2 mod (x^n - 1)
    let hr2 = vect_mul(&h, &r2, p.n);
    let u = vect_add(&hr2, &r1);
    let u = vect_resize(&u, p.n);

    // v = encode(m) + s * r2 + e (in GF(2)^{n1*n2})
    let encoded = tensor_encode(m, p);

    // s * r2 in the ring, then truncate to n1*n2 bits
    let sr2 = vect_mul(&s, &r2, p.n);
    let mut sr2_trunc = vec![0u64; p.vec_n1n2_size64];
    let copy_len = sr2.len().min(p.vec_n1n2_size64);
    sr2_trunc[..copy_len].copy_from_slice(&sr2[..copy_len]);
    if p.n1n2 % 64 != 0 && p.vec_n1n2_size64 > 0 {
        sr2_trunc[p.vec_n1n2_size64 - 1] &= (1u64 << (p.n1n2 % 64)) - 1;
    }

    // Resize e to n1*n2
    let mut e_resized = vec![0u64; p.vec_n1n2_size64];
    let copy_len = e.len().min(p.vec_n1n2_size64);
    e_resized[..copy_len].copy_from_slice(&e[..copy_len]);
    if p.n1n2 % 64 != 0 && p.vec_n1n2_size64 > 0 {
        e_resized[p.vec_n1n2_size64 - 1] &= (1u64 << (p.n1n2 % 64)) - 1;
    }

    let v = vect_add(&encoded, &sr2_trunc);
    let v = vect_add(&v, &e_resized);
    let v = vect_resize(&v, p.n1n2);

    (u, v)
}

/// Generates an HQC key pair.
/// Returns (public_key, secret_key).
pub fn key_gen(p: &Params, rng: &mut impl CryptoRngCore) -> (Vec<u8>, Vec<u8>) {
    // Generate random seeds
    let mut sk_seed = vec![0u8; SEED_BYTES];
    rng.fill_bytes(&mut sk_seed);
    let mut pk_seed = vec![0u8; SEED_BYTES];
    rng.fill_bytes(&mut pk_seed);

    // Generate secret vectors x, y from sk_seed
    let mut sk_expander = SeedExpander::new(&sk_seed);
    let x = vect_set_random_fixed_weight(&mut sk_expander, p.n, p.w);
    let y = vect_set_random_fixed_weight(&mut sk_expander, p.n, p.w);

    // Generate random vector h from pk_seed
    let mut pk_expander = SeedExpander::new(&pk_seed);
    let h = vect_set_random(&mut pk_expander, p.n);

    // Compute s = x + h * y mod (x^n - 1)
    let hy = vect_mul(&h, &y, p.n);
    let s = vect_add(&hy, &x);
    let s = vect_resize(&s, p.n);

    // Serialize public key: [pk_seed (40 bytes)] [s (VecNSizeBytes bytes)]
    let mut pk = vec![0u8; p.pk_size];
    pk[..SEED_BYTES].copy_from_slice(&pk_seed);
    let s_bytes = vect_to_bytes(&s, p.vec_n_size_bytes);
    pk[SEED_BYTES..SEED_BYTES + s_bytes.len()].copy_from_slice(&s_bytes);

    // Serialize secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
    let mut sk = vec![0u8; p.sk_size];
    sk[..SEED_BYTES].copy_from_slice(&sk_seed);
    sk[SEED_BYTES..SEED_BYTES + pk.len()].copy_from_slice(&pk);

    (pk, sk)
}

/// Encapsulates a shared secret using the public key.
/// Returns (ciphertext, shared_secret).
pub fn encaps(pk: &[u8], p: &Params, rng: &mut impl CryptoRngCore) -> (Vec<u8>, Vec<u8>) {
    // Generate random message m
    let mut m = vec![0u8; p.vec_k_size_bytes];
    rng.fill_bytes(&mut m);

    // Compute d = H(m)
    let d = compute_d(&m);

    // Compute theta
    let theta = compute_theta(&m, pk, &d, p);

    // PKE Encrypt
    let (u, v) = pke_encrypt(&m, &theta, pk, p);

    // Compute shared secret
    let ss = compute_ss(&m, &u, &v, p);

    // Serialize ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
    let mut ct = vec![0u8; p.ct_size];
    let u_bytes = vect_to_bytes(&u, p.vec_n_size_bytes);
    let v_bytes = vect_to_bytes(&v, p.vec_n1n2_size_bytes);
    ct[..p.vec_n_size_bytes].copy_from_slice(&u_bytes);
    ct[p.vec_n_size_bytes..p.vec_n_size_bytes + p.vec_n1n2_size_bytes].copy_from_slice(&v_bytes);
    ct[p.vec_n_size_bytes + p.vec_n1n2_size_bytes..].copy_from_slice(&d);

    (ct, ss)
}

/// Decapsulates a shared secret from a ciphertext using the secret key.
pub fn decaps(sk: &[u8], ct: &[u8], p: &Params) -> Vec<u8> {
    // Parse secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
    let sk_seed = &sk[..SEED_BYTES];
    let pk = &sk[SEED_BYTES..];

    // Parse ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
    let u = vect_from_bytes(&ct[..p.vec_n_size_bytes], p.vec_n_size64);
    let v = vect_from_bytes(
        &ct[p.vec_n_size_bytes..p.vec_n_size_bytes + p.vec_n1n2_size_bytes],
        p.vec_n1n2_size64,
    );
    let d = &ct[p.vec_n_size_bytes + p.vec_n1n2_size_bytes..];

    // Regenerate secret vectors x, y and sigma from sk_seed
    let mut sk_expander = SeedExpander::new(sk_seed);
    let _x = vect_set_random_fixed_weight(&mut sk_expander, p.n, p.w); // x not needed for decrypt
    let y = vect_set_random_fixed_weight(&mut sk_expander, p.n, p.w);
    // Generate sigma (rejection secret)
    let mut sigma = vec![0u8; p.vec_k_size_bytes];
    sk_expander.read(&mut sigma);

    // Compute v - u * y (= v XOR u*y since GF(2))
    let uy = vect_mul(&u, &y, p.n);

    // Truncate uy to n1*n2 bits
    let mut uy_trunc = vec![0u64; p.vec_n1n2_size64];
    let copy_len = uy.len().min(p.vec_n1n2_size64);
    uy_trunc[..copy_len].copy_from_slice(&uy[..copy_len]);
    if p.n1n2 % 64 != 0 && p.vec_n1n2_size64 > 0 {
        uy_trunc[p.vec_n1n2_size64 - 1] &= (1u64 << (p.n1n2 % 64)) - 1;
    }

    let v_minus_uy = vect_add(&v, &uy_trunc);

    // Decode using tensor product code
    let (m_prime, ok) = tensor_decode(&v_minus_uy, p);

    let m_prime = if ok { m_prime } else { sigma.clone() };

    // Re-encrypt to verify
    let theta_prime = compute_theta(&m_prime, pk, d, p);
    let (u2, v2) = pke_encrypt(&m_prime, &theta_prime, pk, p);

    // Constant-time comparison
    let u2_trunc = vect_resize(&u2, p.n);
    let u_orig = vect_resize(&u, p.n);
    let u_match = vect_equal(&u2_trunc, &u_orig);

    let v2_trunc = vect_resize(&v2, p.n1n2);
    let v_orig = vect_resize(&v, p.n1n2);
    let v_match = vect_equal(&v2_trunc, &v_orig);

    let matched = u_match & v_match;

    // Constant-time selection of message or sigma
    let mask_ok = 0u8.wrapping_sub(matched as u8); // 0xFF if match, 0x00 otherwise
    let mask_fail = 0u8.wrapping_sub((1 - matched) as u8); // 0x00 if match, 0xFF otherwise
    let mut mc = vec![0u8; p.vec_k_size_bytes];
    for i in 0..p.vec_k_size_bytes {
        mc[i] = (m_prime[i] & mask_ok) | (sigma[i] & mask_fail);
    }

    // Compute shared secret
    compute_ss(&mc, &u, &v, p)
}
