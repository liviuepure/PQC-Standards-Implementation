/// Reed-Solomon encoding and decoding over GF(2^8) for HQC.
///
/// RS(n1, k) with minimum distance d = n1 - k + 1 = 2*delta + 1.
/// The generator polynomial g(x) = prod(x - alpha^i) for i = 1..2*delta.
/// alpha is the primitive element of GF(2^8) (alpha = 2, using polynomial 0x11D).

use crate::gf256::*;
use crate::params::Params;

/// Computes the generator polynomial of the RS code.
/// Returns coefficients [g0, g1, ..., g_{2*delta}] where g_{2*delta} = 1.
fn rs_generator_poly(delta: usize) -> Vec<u8> {
    let deg = 2 * delta;
    let mut g = vec![0u8; deg + 1];
    g[0] = 1; // g(x) = 1

    // Multiply by (x - alpha^i) for i = 1..2*delta
    for i in 1..=deg {
        let alphai = gf256_pow(GENERATOR, i as i32);
        let mut prev = 0u8;
        for j in 0..=deg {
            let tmp = g[j];
            g[j] = gf256_mul(g[j], alphai) ^ prev;
            prev = tmp;
        }
    }

    g
}

/// Performs systematic RS encoding.
/// Input: msg of length k bytes.
/// Output: codeword of length n1 bytes (parity || msg).
pub fn rs_encode(msg: &[u8], p: &Params) -> Vec<u8> {
    let k = p.k;
    let n1 = p.n1;
    let delta = p.delta;
    let g = rs_generator_poly(delta);
    let parity_len = 2 * delta;

    // Linear feedback shift register encoding
    let mut feedback = vec![0u8; parity_len];

    for i in (0..k).rev() {
        let coeff = gf256_add(msg[i], feedback[parity_len - 1]);
        for j in (1..parity_len).rev() {
            feedback[j] = gf256_add(feedback[j - 1], gf256_mul(coeff, g[j]));
        }
        feedback[0] = gf256_mul(coeff, g[0]);
    }

    // Codeword = [parity bytes] [message bytes]
    let mut codeword = vec![0u8; n1];
    codeword[..parity_len].copy_from_slice(&feedback[..parity_len]);
    codeword[parity_len..parity_len + k].copy_from_slice(&msg[..k]);

    codeword
}

/// Decodes a received RS codeword.
/// Returns the decoded message (k bytes) and success flag.
pub fn rs_decode(received: &[u8], p: &Params) -> (Vec<u8>, bool) {
    let n1 = p.n1;
    let k = p.k;
    let delta = p.delta;

    let mut r = vec![0u8; n1];
    r[..received.len().min(n1)].copy_from_slice(&received[..received.len().min(n1)]);

    // Step 1: Compute syndromes S[1..2*delta]
    let mut syndromes = vec![0u8; 2 * delta + 1]; // syndromes[0] unused
    let mut all_zero = true;
    for i in 1..=2 * delta {
        let alphai = gf256_pow(GENERATOR, i as i32);
        let mut s = 0u8;
        for j in (0..n1).rev() {
            s = gf256_add(gf256_mul(s, alphai), r[j]);
        }
        syndromes[i] = s;
        if s != 0 {
            all_zero = false;
        }
    }

    if all_zero {
        let mut msg = vec![0u8; k];
        msg.copy_from_slice(&r[2 * delta..2 * delta + k]);
        return (msg, true);
    }

    // Step 2: Berlekamp-Massey algorithm
    let sigma = berlekamp_massey(&syndromes, delta);
    let mut sig_deg = 0;
    for i in (0..=delta).rev() {
        if sigma[i] != 0 {
            sig_deg = i;
            break;
        }
    }
    if sig_deg > delta {
        return (vec![], false);
    }

    // Step 3: Chien search - find roots of sigma
    let mut error_positions = Vec::with_capacity(sig_deg);
    for i in 0..n1 {
        let alpha_inv = gf256_pow(GENERATOR, 255 - i as i32);
        let mut val = 0u8;
        let mut alpha_pow = 1u8;
        for j in 0..=sig_deg {
            val ^= gf256_mul(sigma[j], alpha_pow);
            alpha_pow = gf256_mul(alpha_pow, alpha_inv);
        }
        if val == 0 {
            error_positions.push(i);
        }
    }

    if error_positions.len() != sig_deg {
        return (vec![], false);
    }

    // Step 4: Forney's algorithm - compute error values
    // omega(x) = S(x) * sigma(x) mod x^(2*delta+1)
    let mut omega = vec![0u8; 2 * delta + 1];
    for i in 0..2 * delta {
        for j in 0..=sig_deg.min(i) {
            omega[i + 1] ^= gf256_mul(sigma[j], syndromes[i + 1 - j]);
        }
    }

    // sigma'(x) = formal derivative of sigma
    let mut sigma_prime = vec![0u8; delta + 1];
    for i in (1..=sig_deg).step_by(2) {
        sigma_prime[i - 1] = sigma[i];
    }

    // Correct errors
    for &pos in &error_positions {
        let alpha_inv_i = gf256_inv(gf256_pow(GENERATOR, pos as i32));

        // Evaluate omega(alpha^(-pos))
        let mut omega_val = 0u8;
        let mut alpha_pow = 1u8;
        for j in 0..=2 * delta {
            omega_val ^= gf256_mul(omega[j], alpha_pow);
            alpha_pow = gf256_mul(alpha_pow, alpha_inv_i);
        }

        // Evaluate sigma'(alpha^(-pos))
        let mut sig_prime_val = 0u8;
        let mut alpha_pow = 1u8;
        for j in 0..sigma_prime.len() {
            sig_prime_val ^= gf256_mul(sigma_prime[j], alpha_pow);
            alpha_pow = gf256_mul(alpha_pow, alpha_inv_i);
        }

        if sig_prime_val == 0 {
            return (vec![], false);
        }

        // Forney's formula: e_j = X_j * omega(X_j^{-1}) / sigma'(X_j^{-1})
        // where X_j = alpha^pos
        let xj = gf256_pow(GENERATOR, pos as i32);
        let error_val = gf256_mul(gf256_mul(xj, omega_val), gf256_inv(sig_prime_val));
        r[pos] ^= error_val;
    }

    // Extract message
    let mut msg = vec![0u8; k];
    msg.copy_from_slice(&r[2 * delta..2 * delta + k]);
    (msg, true)
}

/// Berlekamp-Massey algorithm.
/// Returns the error locator polynomial sigma with coefficients sigma[0..=delta].
fn berlekamp_massey(syndromes: &[u8], delta: usize) -> Vec<u8> {
    let n = 2 * delta;
    let mut sigma = vec![0u8; delta + 2];
    sigma[0] = 1;
    let mut b = vec![0u8; delta + 2];
    b[0] = 1;
    let mut big_l = 0usize;
    let mut m = 1usize;
    let mut delta_n: u8 = 1; // previous discrepancy

    for k in 1..=n {
        // Compute discrepancy d
        let mut d = syndromes[k];
        for i in 1..=big_l {
            d ^= gf256_mul(sigma[i], syndromes[k - i]);
        }

        if d == 0 {
            m += 1;
            continue;
        }

        // t(x) = sigma(x) - (d/delta_n) * x^m * b(x)
        let mut t = vec![0u8; delta + 2];
        t[..sigma.len()].copy_from_slice(&sigma);
        let coeff = gf256_mul(d, gf256_inv(delta_n));
        for i in 0..=delta + 1 - m {
            if i + m <= delta + 1 {
                t[i + m] ^= gf256_mul(coeff, b[i]);
            }
        }

        if 2 * big_l < k {
            b.copy_from_slice(&sigma);
            big_l = k - big_l;
            delta_n = d;
            m = 1;
        } else {
            m += 1;
        }
        sigma.copy_from_slice(&t);
    }

    sigma.truncate(delta + 1);
    sigma
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::*;

    #[test]
    fn test_rs_roundtrip() {
        for p in all_params() {
            let mut msg = vec![0u8; p.k];
            for i in 0..p.k {
                msg[i] = (i + 1) as u8;
            }
            let cw = rs_encode(&msg, p);
            let (decoded, ok) = rs_decode(&cw, p);
            assert!(ok, "{}: decode failed on clean codeword", p.name);
            assert_eq!(decoded, msg, "{}: roundtrip mismatch", p.name);
        }
    }

    #[test]
    fn test_rs_decode_with_errors() {
        for p in all_params() {
            let mut msg = vec![0u8; p.k];
            for i in 0..p.k {
                msg[i] = (i * 3 + 7) as u8;
            }
            let mut cw = rs_encode(&msg, p);
            // Introduce delta errors
            for i in 0..p.delta {
                cw[i] ^= (i + 1) as u8;
            }
            let (decoded, ok) = rs_decode(&cw, p);
            assert!(ok, "{}: decode failed with correctable errors", p.name);
            assert_eq!(decoded, msg, "{}: decode mismatch after error correction", p.name);
        }
    }
}
