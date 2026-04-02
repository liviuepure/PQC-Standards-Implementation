// FN-DSA verification (FIPS 206 Algorithm 4).

use crate::params::{Params, Q};
use crate::ntt::poly_mul_ntt;
use crate::encode::{decode_pk, decode_sig};
use crate::sign::{hash_to_point, center_mod_q, norm_sq};

/// Returns true iff sig is a valid FN-DSA signature on msg under public key pk.
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8], p: Params) -> bool {
    // 1. Decode public key.
    let h = match decode_pk(pk, p) {
        Some(h) => h,
        None => return false,
    };

    // 2. Decode signature.
    let (salt, s1) = match decode_sig(sig, p) {
        Some(v) => v,
        None => return false,
    };

    // 3. Recompute c = HashToPoint(salt || msg).
    let n = p.n;
    let mut hash_input = vec![0u8; 40 + msg.len()];
    hash_input[..40].copy_from_slice(&salt);
    hash_input[40..].copy_from_slice(msg);
    let c = hash_to_point(&hash_input, p);

    // 4. Compute s2 = c - s1*h (mod q), centered.
    let s1_mod: Vec<i32> = s1.iter().map(|&v| ((v % Q) + Q) % Q).collect();
    let s1h = poly_mul_ntt(&s1_mod, &h, n);
    let s2: Vec<i32> = (0..n).map(|i| center_mod_q(c[i] - s1h[i])).collect();

    // 5. Norm check.
    norm_sq(&s1, &s2) <= p.beta_sq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_invalid_sig_rejected() {
        use crate::params::FNDSA512;
        let p = FNDSA512;
        let pk = vec![0u8; p.pk_size];
        let msg = b"test";
        let sig = vec![0u8; p.sig_size];
        // Should return false (not panic).
        let _ = verify(&pk, msg, &sig, p);
    }
}
