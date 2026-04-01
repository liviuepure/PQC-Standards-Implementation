// NTT and INTT for FN-DSA (FIPS 206 / FALCON) mod q = 12289.
//
// Negacyclic NTT over Z[x]/(x^n+1), same algorithm as the Go reference.

use crate::params::Q;

/// Returns (a * b) mod Q.
pub fn mul_mod_q(a: i64, b: i64) -> i32 {
    (a * b % i64::from(Q)) as i32
}

/// Returns (a + b) mod Q with inputs in [0, Q).
pub fn add_mod_q(a: i32, b: i32) -> i32 {
    let r = a + b;
    if r >= Q { r - Q } else { r }
}

/// Returns (a - b) mod Q with inputs in [0, Q).
pub fn sub_mod_q(a: i32, b: i32) -> i32 {
    let r = a - b;
    if r < 0 { r + Q } else { r }
}

/// Returns base^exp mod Q using fast exponentiation.
pub fn pow_mod_q(base: i64, exp: i64) -> i32 {
    let mut result = 1i64;
    let mut b = base % i64::from(Q);
    if b < 0 { b += i64::from(Q); }
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = result * b % i64::from(Q);
        }
        e >>= 1;
        b = b * b % i64::from(Q);
    }
    result as i32
}

/// Reverses the low logn bits of k.
pub fn bit_rev(mut k: usize, logn: usize) -> usize {
    let mut r = 0usize;
    for _ in 0..logn {
        r = (r << 1) | (k & 1);
        k >>= 1;
    }
    r
}

/// Builds the forward zeta table for size n.
fn build_zetas(n: usize, logn: usize) -> Vec<i32> {
    let psi = pow_mod_q(11, ((Q - 1) / (2 * n as i32)) as i64);
    (0..n).map(|k| {
        let br = bit_rev(k, logn);
        pow_mod_q(psi as i64, br as i64)
    }).collect()
}

/// Builds the inverse zeta table for size n.
fn build_zetas_inv(zetas: &[i32]) -> Vec<i32> {
    zetas.iter().map(|&z| pow_mod_q(z as i64, (Q - 2) as i64)).collect()
}

/// In-place forward negacyclic NTT, n must be 512 or 1024.
pub fn ntt(f: &mut [i32], n: usize) {
    let logn = if n == 512 { 9 } else { 10 };
    let zetas = build_zetas(n, logn);

    let mut k = 0usize;
    let mut length = n >> 1;
    while length >= 1 {
        let mut start = 0;
        while start < n {
            k += 1;
            let zeta = i64::from(zetas[k]);
            for j in start..start + length {
                let t = mul_mod_q(zeta, i64::from(f[j + length]));
                f[j + length] = sub_mod_q(f[j], t);
                f[j] = add_mod_q(f[j], t);
            }
            start += 2 * length;
        }
        length >>= 1;
    }
}

/// In-place inverse negacyclic NTT, n must be 512 or 1024.
pub fn intt(f: &mut [i32], n: usize) {
    let logn = if n == 512 { 9 } else { 10 };
    let zetas = build_zetas(n, logn);
    let zetas_inv = build_zetas_inv(&zetas);

    let n_inv = pow_mod_q(n as i64, (Q - 2) as i64);

    let mut k = n;
    let mut length = 1usize;
    while length < n {
        let mut start = (n - 2 * length) as isize;
        while start >= 0 {
            k -= 1;
            let zeta_inv = i64::from(zetas_inv[k]);
            for j in (start as usize)..(start as usize) + length {
                let t = f[j];
                f[j] = add_mod_q(t, f[j + length]);
                f[j + length] = mul_mod_q(zeta_inv, i64::from(sub_mod_q(t, f[j + length])));
            }
            start -= (2 * length) as isize;
        }
        length <<= 1;
    }

    // Scale by n^{-1} mod Q
    for x in f.iter_mut() {
        *x = mul_mod_q(i64::from(n_inv), i64::from(*x));
    }
}

/// Multiplies two polynomials mod (q, x^n+1) using NTT. Inputs must be in [0, Q).
pub fn poly_mul_ntt(a: &[i32], b: &[i32], n: usize) -> Vec<i32> {
    let mut a_ntt = a.to_vec();
    let mut b_ntt = b.to_vec();
    ntt(&mut a_ntt, n);
    ntt(&mut b_ntt, n);
    let mut c_ntt: Vec<i32> = a_ntt.iter().zip(b_ntt.iter())
        .map(|(&ai, &bi)| (i64::from(ai) * i64::from(bi) % i64::from(Q)) as i32)
        .collect();
    intt(&mut c_ntt, n);
    c_ntt
}

/// Adds two polynomials mod q.
pub fn poly_add(a: &[i32], b: &[i32], n: usize) -> Vec<i32> {
    (0..n).map(|i| {
        let ai = ((a[i] % Q) + Q) % Q;
        let bi = ((b[i] % Q) + Q) % Q;
        add_mod_q(ai, bi)
    }).collect()
}

/// Subtracts two polynomials mod q.
pub fn poly_sub(a: &[i32], b: &[i32], n: usize) -> Vec<i32> {
    (0..n).map(|i| {
        let ai = ((a[i] % Q) + Q) % Q;
        let bi = ((b[i] % Q) + Q) % Q;
        sub_mod_q(ai, bi)
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_intt_roundtrip_512() {
        let orig: Vec<i32> = (0..512).map(|i| (i as i32 * 3 + 1) % Q).collect();
        let mut f = orig.clone();
        ntt(&mut f, 512);
        intt(&mut f, 512);
        assert_eq!(f, orig);
    }

    #[test]
    fn test_ntt_intt_roundtrip_1024() {
        let orig: Vec<i32> = (0..1024).map(|i| (i as i32 * 7 + 5) % Q).collect();
        let mut f = orig.clone();
        ntt(&mut f, 1024);
        intt(&mut f, 1024);
        assert_eq!(f, orig);
    }

    #[test]
    fn test_poly_mul_ntt() {
        let n = 512;
        // Multiply (1) * (1) = (1)
        let a: Vec<i32> = (0..n).map(|i| if i == 0 { 1 } else { 0 }).collect();
        let b = a.clone();
        let c = poly_mul_ntt(&a, &b, n);
        assert_eq!(c[0], 1);
        for i in 1..n {
            assert_eq!(c[i], 0);
        }
    }
}
