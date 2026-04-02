// FN-DSA signing (FIPS 206).

use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};
use rand_core::RngCore;

use crate::params::{Params, Q};
use crate::ntt::{ntt, intt, poly_mul_ntt, pow_mod_q};
use crate::fft::{int32s_to_fft, round_fft_to_int32s, Complex64};
use crate::encode::{decode_sk, encode_sig};
use crate::FnDsaError;

/// Hashes msg (salt || message) to a polynomial c ∈ Z_q[x]/(x^n+1).
/// Uses SHAKE256 with rejection sampling.
pub fn hash_to_point(msg: &[u8], p: Params) -> Vec<i32> {
    let n = p.n;
    let mut out = vec![0i32; n];
    let mut hasher = Shake256::default();
    hasher.update(msg);
    let mut reader = hasher.finalize_xof();

    let mut count = 0;
    let mut buf = [0u8; 2];
    while count < n {
        reader.read(&mut buf);
        let v = (buf[0] as u16 | (buf[1] as u16) << 8) as i32;
        if v < 5 * Q {
            out[count] = v % Q;
            count += 1;
        }
    }
    out
}

/// Centers v mod Q into (-Q/2, Q/2].
pub fn center_mod_q(v: i32) -> i32 {
    let v = ((v % Q) + Q) % Q;
    if v > Q / 2 { v - Q } else { v }
}

/// Computes the squared Euclidean norm of two slices.
pub fn norm_sq(s1: &[i32], s2: &[i32]) -> i64 {
    let n1: i64 = s1.iter().map(|&v| i64::from(v) * i64::from(v)).sum();
    let n2: i64 = s2.iter().map(|&v| i64::from(v) * i64::from(v)).sum();
    n1 + n2
}

/// Recovers G from (f, g, F) via NTRU equation fG - gF = Q, mod q.
pub fn recover_g(f: &[i32], g: &[i32], cap_f: &[i32], n: usize) -> Option<Vec<i32>> {
    let g_mod: Vec<i32> = g.iter().map(|&v| ((v % Q) + Q) % Q).collect();
    let f_mod_q: Vec<i32> = cap_f.iter().map(|&v| ((v % Q) + Q) % Q).collect();
    let gf = poly_mul_ntt(&g_mod, &f_mod_q, n);

    let f_mod: Vec<i32> = f.iter().map(|&v| ((v % Q) + Q) % Q).collect();
    let mut f_ntt = f_mod.clone();
    ntt(&mut f_ntt, n);
    if f_ntt.iter().any(|&v| v == 0) {
        return None;
    }
    let mut f_inv_ntt: Vec<i32> = f_ntt.iter().map(|&v| pow_mod_q(v as i64, (Q - 2) as i64)).collect();
    intt(&mut f_inv_ntt, n);

    let cap_g = poly_mul_ntt(&gf, &f_inv_ntt, n);
    Some(cap_g.iter().map(|&v| if v > Q / 2 { v - Q } else { v }).collect())
}

/// Babai nearest-plane lattice sampler over the NTRU basis.
/// Returns (s1, s2) where s1*h + s2 = c (mod q).
pub fn ff_sampling_babai(
    c: &[i32], f: &[i32], g: &[i32], cap_f: &[i32], cap_g: &[i32], n: usize,
) -> (Vec<i32>, Vec<i32>) {
    let c_fft = int32s_to_fft(c, n);
    let f_fft = int32s_to_fft(f, n);
    let g_fft = int32s_to_fft(g, n);
    let ff_fft = int32s_to_fft(cap_f, n);
    let gf_fft = int32s_to_fft(cap_g, n);

    // Gram-Schmidt: b1^* = b1 - mu10 * b0^*
    let mut b1_star: Vec<[Complex64; 2]> = vec![[(0.0, 0.0); 2]; n];
    let mut b1_star_norm_sq: Vec<f64> = vec![0.0; n];

    for j in 0..n {
        let gj = g_fft[j];
        let fj = f_fft[j];
        let gfj = gf_fft[j];
        let ffj = ff_fft[j];

        let b0_norm_sq = gj.0 * gj.0 + gj.1 * gj.1 + fj.0 * fj.0 + fj.1 * fj.1;
        let mu10 = if b0_norm_sq != 0.0 {
            // num = G_j*conj(g_j) + F_j*conj(f_j)
            let num = (
                gfj.0 * gj.0 + gfj.1 * gj.1 + ffj.0 * fj.0 + ffj.1 * fj.1,
                gfj.1 * gj.0 - gfj.0 * gj.1 + ffj.1 * fj.0 - ffj.0 * fj.1,
            );
            (num.0 / b0_norm_sq, num.1 / b0_norm_sq)
        } else {
            (0.0, 0.0)
        };

        // b1^*[j] = [G_j - mu10*g_j, -F_j + mu10*f_j]
        let b1s0 = (gfj.0 - (mu10.0 * gj.0 - mu10.1 * gj.1), gfj.1 - (mu10.0 * gj.1 + mu10.1 * gj.0));
        let b1s1 = (-ffj.0 + (mu10.0 * fj.0 - mu10.1 * fj.1), -ffj.1 + (mu10.0 * fj.1 + mu10.1 * fj.0));
        b1_star[j] = [b1s0, b1s1];
        b1_star_norm_sq[j] = b1s0.0 * b1s0.0 + b1s0.1 * b1s0.1 + b1s1.0 * b1s1.0 + b1s1.1 * b1s1.1;
    }

    // Step 1: project (c_j, 0) along b1^*
    let mut tau1_fft: Vec<Complex64> = vec![(0.0, 0.0); n];
    for j in 0..n {
        let b1s_norm = b1_star_norm_sq[j];
        if b1s_norm != 0.0 {
            let b1s0 = b1_star[j][0];
            // num = c_j * conj(b1^*[0])
            let num = (c_fft[j].0 * b1s0.0 + c_fft[j].1 * b1s0.1,
                       c_fft[j].1 * b1s0.0 - c_fft[j].0 * b1s0.1);
            tau1_fft[j] = (num.0 / b1s_norm, num.1 / b1s_norm);
        }
    }

    let z1 = round_fft_to_int32s(&tau1_fft, n);
    let z1_fft = int32s_to_fft(&z1, n);

    // Update target: t'_j = (c_j - z1_j*G_j, z1_j*F_j)
    let mut c_prime_fft: Vec<Complex64> = vec![(0.0, 0.0); n];
    let mut x_prime_fft: Vec<Complex64> = vec![(0.0, 0.0); n];
    for j in 0..n {
        let z1g = (z1_fft[j].0 * gf_fft[j].0 - z1_fft[j].1 * gf_fft[j].1,
                   z1_fft[j].0 * gf_fft[j].1 + z1_fft[j].1 * gf_fft[j].0);
        let z1f = (z1_fft[j].0 * ff_fft[j].0 - z1_fft[j].1 * ff_fft[j].1,
                   z1_fft[j].0 * ff_fft[j].1 + z1_fft[j].1 * ff_fft[j].0);
        c_prime_fft[j] = (c_fft[j].0 - z1g.0, c_fft[j].1 - z1g.1);
        x_prime_fft[j] = z1f;
    }

    // Step 2: project t' along b0^* = (g_j, -f_j)
    let mut tau0_fft: Vec<Complex64> = vec![(0.0, 0.0); n];
    for j in 0..n {
        let gj = g_fft[j];
        let fj = f_fft[j];
        let b0_norm_sq = gj.0 * gj.0 + gj.1 * gj.1 + fj.0 * fj.0 + fj.1 * fj.1;
        if b0_norm_sq != 0.0 {
            // num = c'_j*conj(g_j) - x'_j*conj(f_j)
            let cp = c_prime_fft[j];
            let xp = x_prime_fft[j];
            let num = (
                cp.0 * gj.0 + cp.1 * gj.1 - (xp.0 * fj.0 + xp.1 * fj.1),
                cp.1 * gj.0 - cp.0 * gj.1 - (xp.1 * fj.0 - xp.0 * fj.1),
            );
            tau0_fft[j] = (num.0 / b0_norm_sq, num.1 / b0_norm_sq);
        }
    }

    let z0 = round_fft_to_int32s(&tau0_fft, n);
    let z0_fft = int32s_to_fft(&z0, n);

    // s1 = z0*f + z1*F, s2 = c - z0*g - z1*G
    let mut s1_fft: Vec<Complex64> = vec![(0.0, 0.0); n];
    let mut s2_fft: Vec<Complex64> = vec![(0.0, 0.0); n];
    for j in 0..n {
        let z0f = (z0_fft[j].0 * f_fft[j].0 - z0_fft[j].1 * f_fft[j].1,
                   z0_fft[j].0 * f_fft[j].1 + z0_fft[j].1 * f_fft[j].0);
        let z1f_cap = (z1_fft[j].0 * ff_fft[j].0 - z1_fft[j].1 * ff_fft[j].1,
                       z1_fft[j].0 * ff_fft[j].1 + z1_fft[j].1 * ff_fft[j].0);
        let z0g = (z0_fft[j].0 * g_fft[j].0 - z0_fft[j].1 * g_fft[j].1,
                   z0_fft[j].0 * g_fft[j].1 + z0_fft[j].1 * g_fft[j].0);
        let z1g = (z1_fft[j].0 * gf_fft[j].0 - z1_fft[j].1 * gf_fft[j].1,
                   z1_fft[j].0 * gf_fft[j].1 + z1_fft[j].1 * gf_fft[j].0);
        s1_fft[j] = (z0f.0 + z1f_cap.0, z0f.1 + z1f_cap.1);
        s2_fft[j] = (c_fft[j].0 - z0g.0 - z1g.0, c_fft[j].1 - z0g.1 - z1g.1);
    }

    let s1_raw = round_fft_to_int32s(&s1_fft, n);
    let s2_raw = round_fft_to_int32s(&s2_fft, n);

    let s1: Vec<i32> = s1_raw.iter().map(|&v| center_mod_q(v)).collect();
    let s2: Vec<i32> = s2_raw.iter().map(|&v| center_mod_q(v)).collect();

    (s1, s2)
}

/// Signs msg using the encoded secret key sk under parameter set p.
pub fn sign<R: RngCore>(sk: &[u8], msg: &[u8], p: Params, rng: &mut R) -> Result<Vec<u8>, FnDsaError> {
    let (f, g, cap_f) = decode_sk(sk, p).ok_or(FnDsaError::InvalidKey)?;
    let n = p.n;

    let cap_g = recover_g(&f, &g, &cap_f, n).ok_or(FnDsaError::InvalidKey)?;

    // Pre-compute h for verification.
    let h = {
        let f_mod: Vec<i32> = f.iter().map(|&v| ((v % Q) + Q) % Q).collect();
        let g_mod: Vec<i32> = g.iter().map(|&v| ((v % Q) + Q) % Q).collect();
        let mut f_ntt = f_mod.clone();
        ntt(&mut f_ntt, n);
        let f_inv_ntt: Vec<i32> = f_ntt.iter().map(|&v| pow_mod_q(v as i64, (Q - 2) as i64)).collect();
        let mut g_ntt = g_mod.clone();
        ntt(&mut g_ntt, n);
        let mut h_ntt: Vec<i32> = g_ntt.iter().zip(f_inv_ntt.iter())
            .map(|(&gi, &fi)| (i64::from(gi) * i64::from(fi) % i64::from(Q)) as i32)
            .collect();
        intt(&mut h_ntt, n);
        h_ntt
    };

    let mut salt = vec![0u8; 40];
    for _ in 0..1000 {
        rng.fill_bytes(&mut salt);

        let mut hash_input = vec![0u8; 40 + msg.len()];
        hash_input[..40].copy_from_slice(&salt);
        hash_input[40..].copy_from_slice(msg);
        let c = hash_to_point(&hash_input, p);

        let c_centered: Vec<i32> = c.iter().map(|&v| center_mod_q(v)).collect();
        let (s1, s2) = ff_sampling_babai(&c_centered, &f, &g, &cap_f, &cap_g, n);

        // Verify s1*h + s2 ≡ c (mod q).
        let s1_mod: Vec<i32> = s1.iter().map(|&v| ((v % Q) + Q) % Q).collect();
        let s1h = poly_mul_ntt(&s1_mod, &h, n);
        let valid = c.iter().enumerate().all(|(i, &ci)| {
            let sum = ((i64::from(s1h[i]) + i64::from(s2[i])) % i64::from(Q) + i64::from(Q)) % i64::from(Q);
            sum == i64::from(ci)
        });
        if !valid {
            continue;
        }

        // Norm check.
        if norm_sq(&s1, &s2) > p.beta_sq {
            continue;
        }

        // Encode.
        if let Some(sig) = encode_sig(&salt, &s1, p) {
            return Ok(sig);
        }
    }

    Err(FnDsaError::SigningFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::FNDSA512;

    #[test]
    fn test_hash_to_point_length() {
        let p = FNDSA512;
        let msg = b"test message";
        let c = hash_to_point(msg, p);
        assert_eq!(c.len(), p.n);
        for &v in &c {
            assert!(v >= 0 && v < Q, "coefficient out of range: {}", v);
        }
    }
}
