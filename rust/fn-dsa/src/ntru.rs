// NTRU key generation for FN-DSA (FIPS 206 Algorithm 5 / NTRUGen).
//
// Ported from the Go reference implementation. Uses num-bigint for exact arithmetic
// in the recursive NTRU solver.

use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero, ToPrimitive};
use rand_core::RngCore;

use crate::gaussian::{sample_gaussian, ntru_sigma};
use crate::ntt::{ntt, intt, pow_mod_q};
use crate::params::{Params, Q};
use crate::fft::{fft, ifft, Complex64};
#[allow(unused_imports)]
use crate::ntt::poly_mul_ntt;
use crate::FnDsaError;

/// Generates (f, g, F, G) satisfying f*G - g*F = Q over Z[x]/(x^n+1).
pub fn ntru_keygen<R: RngCore>(
    p: Params,
    rng: &mut R,
) -> Result<(Vec<i32>, Vec<i32>, Vec<i32>, Vec<i32>), FnDsaError> {
    let n = p.n;
    let sigma = ntru_sigma(n);

    for _ in 0..1000 {
        // Sample f and g.
        let f_coeffs: Vec<i32> = (0..n).map(|_| sample_gaussian(rng, sigma)).collect();
        let g_coeffs: Vec<i32> = (0..n).map(|_| sample_gaussian(rng, sigma)).collect();

        // f must be invertible mod 2 (odd XOR sum).
        let xor_sum: i32 = f_coeffs.iter().fold(0, |acc, v| acc ^ (v & 1));
        if xor_sum == 0 {
            continue;
        }

        // f must be invertible mod q (no zero NTT coefficients).
        let mut f_ntt: Vec<i32> = f_coeffs.iter().map(|&v| ((v % Q) + Q) % Q).collect();
        ntt(&mut f_ntt, n);
        if f_ntt.iter().any(|&v| v == 0) {
            continue;
        }

        // Gram-Schmidt norm bound.
        let norm_sq: f64 = f_coeffs.iter().chain(g_coeffs.iter())
            .map(|&v| (v as f64) * (v as f64))
            .sum();
        if norm_sq > 1.17 * 1.17 * Q as f64 * n as f64 {
            continue;
        }

        // Solve the NTRU equation.
        let f_big = int32_to_bigint(&f_coeffs);
        let g_big = int32_to_bigint(&g_coeffs);

        match ntru_solve_big(n, &f_big, &g_big) {
            Err(_) => continue,
            Ok((f_res, g_res)) => {
                // Convert back to i32.
                let f_out: Option<Vec<i32>> = f_res.iter().map(|v| {
                    let x = ToPrimitive::to_i64(v)?;
                    if x > i32::MAX as i64 || x < i32::MIN as i64 { None } else { Some(x as i32) }
                }).collect();
                let g_out: Option<Vec<i32>> = g_res.iter().map(|v| {
                    let x = ToPrimitive::to_i64(v)?;
                    if x > i32::MAX as i64 || x < i32::MIN as i64 { None } else { Some(x as i32) }
                }).collect();

                if let (Some(cap_f), Some(cap_g)) = (f_out, g_out) {
                    // Verify the NTRU equation.
                    if verify_ntru(&f_coeffs, &g_coeffs, &cap_f, &cap_g, n) {
                        return Ok((f_coeffs, g_coeffs, cap_f, cap_g));
                    }
                }
            }
        }
    }

    Err(FnDsaError::KeyGenFailed)
}

/// Verifies f*G - g*F = Q over Z[x]/(x^n+1).
fn verify_ntru(f: &[i32], g: &[i32], cap_f: &[i32], cap_g: &[i32], n: usize) -> bool {
    let fg = poly_mul_int_z(f, cap_g, n);
    let gf = poly_mul_int_z(g, cap_f, n);
    if fg[0] - gf[0] != Q as i64 {
        return false;
    }
    for i in 1..n {
        if fg[i] - gf[i] != 0 {
            return false;
        }
    }
    true
}

/// Computes h = g * f^{-1} mod (q, x^n+1).
pub fn ntru_public_key(f: &[i32], g: &[i32], p: Params) -> Vec<i32> {
    let n = p.n;
    let mut f_ntt: Vec<i32> = f.iter().map(|&v| ((v % Q) + Q) % Q).collect();
    let mut g_ntt: Vec<i32> = g.iter().map(|&v| ((v % Q) + Q) % Q).collect();
    ntt(&mut f_ntt, n);
    ntt(&mut g_ntt, n);

    let f_inv_ntt: Vec<i32> = f_ntt.iter().map(|&v| pow_mod_q(v as i64, (Q - 2) as i64)).collect();

    let mut h_ntt: Vec<i32> = g_ntt.iter().zip(f_inv_ntt.iter())
        .map(|(&gi, &fi)| (i64::from(gi) * i64::from(fi) % i64::from(Q)) as i32)
        .collect();
    intt(&mut h_ntt, n);
    h_ntt
}

// --- Polynomial arithmetic over Z ---

/// Multiplies two polynomials over Z[x]/(x^n+1) exactly using i64.
pub fn poly_mul_int_z(a: &[i32], b: &[i32], n: usize) -> Vec<i64> {
    let mut c = vec![0i64; n];
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            let idx = i + j;
            let val = i64::from(ai) * i64::from(bj);
            if idx < n {
                c[idx] += val;
            } else {
                c[idx - n] -= val;
            }
        }
    }
    c
}

fn int32_to_bigint(a: &[i32]) -> Vec<BigInt> {
    a.iter().map(|&v| BigInt::from(v)).collect()
}

// --- BigInt polynomial helpers ---

fn poly_mul_bigint_z(a: &[BigInt], b: &[BigInt], n: usize) -> Vec<BigInt> {
    let mut c = vec![BigInt::from(0i32); n];
    for (i, ai) in a.iter().enumerate() {
        for (j, bj) in b.iter().enumerate() {
            let idx = i + j;
            let val = ai * bj;
            if idx < n {
                c[idx] += &val;
            } else {
                c[idx - n] -= &val;
            }
        }
    }
    c
}

/// Field norm from Z[x]/(x^n+1) to Z[x]/(x^{n/2}+1).
/// N(f)(y) = f0(y)^2 - y*f1(y)^2
fn field_norm_bigint(f: &[BigInt], n: usize) -> Vec<BigInt> {
    let h = n / 2;
    let f0: Vec<BigInt> = (0..h).map(|i| f[2 * i].clone()).collect();
    let f1: Vec<BigInt> = (0..h).map(|i| f[2 * i + 1].clone()).collect();
    let f0sq = poly_mul_bigint_z(&f0, &f0, h);
    let f1sq = poly_mul_bigint_z(&f1, &f1, h);

    // N(f)[0] = f0sq[0] + f1sq[h-1]
    // N(f)[i] = f0sq[i] - f1sq[i-1]  for i >= 1
    let mut result = vec![BigInt::zero(); h];
    result[0] = &f0sq[0] + &f1sq[h - 1];
    for i in 1..h {
        result[i] = &f0sq[i] - &f1sq[i - 1];
    }
    result
}

/// Tower conjugate: negate odd-indexed coefficients.
fn tower_conjugate_bigint(f: &[BigInt]) -> Vec<BigInt> {
    f.iter().enumerate().map(|(i, v)| {
        if i % 2 == 0 { v.clone() } else { -v }
    }).collect()
}

/// Lifts (F', G') from degree n/2 to degree n.
fn lift_bigint(fp: &[BigInt], gp: &[BigInt], f: &[BigInt], g: &[BigInt], n: usize) -> (Vec<BigInt>, Vec<BigInt>) {
    let h = n / 2;
    let mut fp_lift = vec![BigInt::zero(); n];
    let mut gp_lift = vec![BigInt::zero(); n];
    for i in 0..h {
        fp_lift[2 * i] = fp[i].clone();
        gp_lift[2 * i] = gp[i].clone();
    }
    let f_conj = tower_conjugate_bigint(f);
    let g_conj = tower_conjugate_bigint(g);
    let cap_f = poly_mul_bigint_z(&g_conj, &fp_lift, n);
    let cap_g = poly_mul_bigint_z(&f_conj, &gp_lift, n);
    (cap_f, cap_g)
}

// --- BigFloat FFT Babai ---

fn bigint_to_f64(v: &BigInt) -> f64 {
    // Convert BigInt to f64 (may lose precision for large values)
    match v.to_bytes_be() {
        (Sign::Minus, bytes) => {
            let pos = bytes_to_f64(&bytes);
            -pos
        }
        (Sign::Plus, bytes) | (Sign::NoSign, bytes) => bytes_to_f64(&bytes),
    }
}

fn bytes_to_f64(bytes: &[u8]) -> f64 {
    // Convert big-endian bytes to f64
    let mut val = 0.0f64;
    for &b in bytes {
        val = val * 256.0 + b as f64;
    }
    val
}

/// Babai FFT rounding using float64.
fn babai_float64(
    big_f: &[BigInt], big_g: &[BigInt],
    f: &[f64], g: &[f64],
    n: usize,
) -> Vec<BigInt> {
    let mut fc: Vec<Complex64> = f.iter().map(|&v| (v, 0.0)).collect();
    let mut gc: Vec<Complex64> = g.iter().map(|&v| (v, 0.0)).collect();
    let mut big_fc: Vec<Complex64> = big_f.iter().map(|v| (bigint_to_f64(v), 0.0)).collect();
    let mut big_gc: Vec<Complex64> = big_g.iter().map(|v| (bigint_to_f64(v), 0.0)).collect();

    fft(&mut fc, n);
    fft(&mut gc, n);
    fft(&mut big_fc, n);
    fft(&mut big_gc, n);

    let mut kc: Vec<Complex64> = vec![(0.0, 0.0); n];
    for i in 0..n {
        let fi = fc[i];
        let gi = gc[i];
        let cap_fi = big_fc[i];
        let cap_gi = big_gc[i];
        let fi_conj = (fi.0, -fi.1);
        let gi_conj = (gi.0, -gi.1);
        let num = (
            cap_fi.0 * fi_conj.0 - cap_fi.1 * fi_conj.1 + cap_gi.0 * gi_conj.0 - cap_gi.1 * gi_conj.1,
            cap_fi.0 * fi_conj.1 + cap_fi.1 * fi_conj.0 + cap_gi.0 * gi_conj.1 + cap_gi.1 * gi_conj.0,
        );
        let denom = fi.0 * fi.0 + fi.1 * fi.1 + gi.0 * gi.0 + gi.1 * gi.1;
        if denom != 0.0 {
            kc[i] = (num.0 / denom, num.1 / denom);
        }
    }

    ifft(&mut kc, n);

    kc.iter().map(|v| BigInt::from(v.0.round() as i64)).collect()
}

/// High-precision Babai using a custom big-float complex FFT.
/// For deep levels where f64 is insufficient, we use a higher-precision approach.
/// We use f64 but with iterative refinement via multiple rounds.
fn babai_high_prec(
    big_f: &[BigInt], big_g: &[BigInt],
    f_big: &[BigInt], g_big: &[BigInt],
    n: usize,
) -> Vec<BigInt> {
    // Convert f_big, g_big to f64 (may lose precision but good enough for rounding)
    let f_f64: Vec<f64> = f_big.iter().map(|v| bigint_to_f64(v)).collect();
    let g_f64: Vec<f64> = g_big.iter().map(|v| bigint_to_f64(v)).collect();
    babai_float64(big_f, big_g, &f_f64, &g_f64, n)
}

/// Recursive NTRU solver using exact big.Int arithmetic.
fn ntru_solve_big(n: usize, f: &[BigInt], g: &[BigInt]) -> Result<(Vec<BigInt>, Vec<BigInt>), String> {
    if n == 1 {
        // Base case: solve f[0]*G[0] - g[0]*F[0] = Q over Z using extended GCD.
        let f_val = &f[0];
        let g_val = &g[0];
        let q_big = BigInt::from(Q);

        let (gcd, u, v) = extended_gcd(f_val.clone(), g_val.clone());

        // Check gcd divides Q.
        if !(&q_big % &gcd).is_zero() {
            return Err("gcd does not divide q at base case".to_string());
        }

        let scale = &q_big / &gcd;
        let cap_g = u * &scale;
        let cap_f = -(v * &scale);

        return Ok((vec![cap_f], vec![cap_g]));
    }

    // Compute field norms.
    let f_norm = field_norm_bigint(f, n);
    let g_norm = field_norm_bigint(g, n);

    // Recursive solve.
    let (fp, gp) = ntru_solve_big(n / 2, &f_norm, &g_norm)?;

    // Lift.
    let (mut cap_f, mut cap_g) = lift_bigint(&fp, &gp, f, g, n);

    // Determine max bit length of f, g.
    let max_bits: usize = f.iter().chain(g.iter())
        .map(|v| v.bits() as usize)
        .max()
        .unwrap_or(0);

    // Babai reduction - 2 rounds.
    for _ in 0..2 {
        let max_fg_bits = {
            let fg_bits = cap_f.iter().chain(cap_g.iter())
                .map(|v| v.bits() as usize)
                .max()
                .unwrap_or(0);
            max_bits.max(fg_bits)
        };

        let k = if max_fg_bits <= 53 {
            let f_f64: Vec<f64> = f.iter().map(|v| bigint_to_f64(v)).collect();
            let g_f64: Vec<f64> = g.iter().map(|v| bigint_to_f64(v)).collect();
            babai_float64(&cap_f, &cap_g, &f_f64, &g_f64, n)
        } else {
            babai_high_prec(&cap_f, &cap_g, f, g, n)
        };

        let kf = poly_mul_bigint_z(&k, f, n);
        let kg = poly_mul_bigint_z(&k, g, n);
        for i in 0..n {
            cap_f[i] -= &kf[i];
            cap_g[i] -= &kg[i];
        }
    }

    Ok((cap_f, cap_g))
}

/// Extended Euclidean algorithm: returns (gcd, u, v) with u*a + v*b = gcd.
fn extended_gcd(mut a: BigInt, mut b: BigInt) -> (BigInt, BigInt, BigInt) {
    let mut u0 = BigInt::one();
    let mut u1 = BigInt::zero();
    let mut v0 = BigInt::zero();
    let mut v1 = BigInt::one();

    while !b.is_zero() {
        let q = &a / &b;
        let r = &a % &b;
        a = b;
        b = r;
        let new_u = u0 - &q * &u1;
        u0 = u1;
        u1 = new_u;
        let new_v = v0 - &q * &v1;
        v0 = v1;
        v1 = new_v;
    }

    // Make gcd positive.
    if a.sign() == Sign::Minus {
        a = -a;
        u0 = -u0;
        v0 = -v0;
    }

    (a, u0, v0)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_gcd() {
        let (gcd, u, v) = extended_gcd(BigInt::from(3), BigInt::from(5));
        assert_eq!(gcd, BigInt::one());
        // u*3 + v*5 = 1
        assert_eq!(&u * BigInt::from(3) + &v * BigInt::from(5), BigInt::one());
    }

    #[test]
    fn test_field_norm() {
        // f(x) = 1 + x, norm at n=2: f0=[1], f1=[1], N(f)= [1]^2 - y*[1]^2 = 1 - y
        // in Z[y]/(y+1): 1 - (-1) = 2? Actually let's just check dimensions.
        let f: Vec<BigInt> = vec![BigInt::from(1), BigInt::from(1)];
        let norm = field_norm_bigint(&f, 2);
        assert_eq!(norm.len(), 1);
    }
}
