// Complex FFT/IFFT/SplitFFT/MergeFFT for FN-DSA (FIPS 206 / FALCON).
//
// Uses Rust f64 (IEEE 754 double), matching Go float64.

use std::f64::consts::PI;

pub type Complex64 = (f64, f64);

#[inline]
fn cadd(a: Complex64, b: Complex64) -> Complex64 {
    (a.0 + b.0, a.1 + b.1)
}

#[inline]
fn csub(a: Complex64, b: Complex64) -> Complex64 {
    (a.0 - b.0, a.1 - b.1)
}

#[inline]
fn cmul(a: Complex64, b: Complex64) -> Complex64 {
    (a.0 * b.0 - a.1 * b.1, a.0 * b.1 + a.1 * b.0)
}

#[inline]
fn cconj(a: Complex64) -> Complex64 {
    (a.0, -a.1)
}

#[inline]
fn cdiv_real(a: Complex64, r: f64) -> Complex64 {
    (a.0 / r, a.1 / r)
}

fn bit_rev(mut k: usize, logn: usize) -> usize {
    let mut r = 0usize;
    for _ in 0..logn {
        r = (r << 1) | (k & 1);
        k >>= 1;
    }
    r
}

fn log2n(n: usize) -> usize {
    let mut logn = 0;
    let mut t = n;
    while t > 1 {
        logn += 1;
        t >>= 1;
    }
    logn
}

/// In-place forward negacyclic complex FFT over C[x]/(x^n+1).
pub fn fft(f: &mut [Complex64], n: usize) {
    let logn = log2n(n);
    let mut k = 0usize;
    let mut length = n >> 1;
    while length >= 1 {
        let mut start = 0;
        while start < n {
            k += 1;
            let brk = bit_rev(k, logn);
            let angle = PI * brk as f64 / n as f64;
            let w: Complex64 = (angle.cos(), angle.sin());
            for j in start..start + length {
                let t = cmul(w, f[j + length]);
                f[j + length] = csub(f[j], t);
                f[j] = cadd(f[j], t);
            }
            start += 2 * length;
        }
        length >>= 1;
    }
}

/// In-place inverse negacyclic complex FFT over C[x]/(x^n+1). Result scaled by 1/n.
pub fn ifft(f: &mut [Complex64], n: usize) {
    let logn = log2n(n);
    let mut k = n;
    let mut length = 1usize;
    while length < n {
        let mut start = (n - 2 * length) as isize;
        while start >= 0 {
            k -= 1;
            let brk = bit_rev(k, logn);
            let angle = -PI * brk as f64 / n as f64;
            let w_inv: Complex64 = (angle.cos(), angle.sin());
            for j in (start as usize)..(start as usize) + length {
                let t = f[j];
                f[j] = cadd(t, f[j + length]);
                f[j + length] = cmul(w_inv, csub(t, f[j + length]));
            }
            start -= (2 * length) as isize;
        }
        length <<= 1;
    }
    let inv_n = 1.0 / n as f64;
    for x in f.iter_mut() {
        x.0 *= inv_n;
        x.1 *= inv_n;
    }
}

/// Splits n-element FFT polynomial into two (n/2)-element polynomials.
/// f(x) = f0(x²) + x·f1(x²)
pub fn split_fft(f: &[Complex64], n: usize) -> (Vec<Complex64>, Vec<Complex64>) {
    let logn = log2n(n);
    let h = n / 2;
    let mut f0 = vec![(0.0f64, 0.0f64); h];
    let mut f1 = vec![(0.0f64, 0.0f64); h];
    for k in 0..h {
        let j = bit_rev(k, logn - 1);
        let angle = PI * (2 * j + 1) as f64 / n as f64;
        let omega_j: Complex64 = (angle.cos(), angle.sin());
        let a = f[2 * k];
        let b = f[2 * k + 1];
        f0[k] = cdiv_real(cadd(a, b), 2.0);
        // (a - b) / (2 * omega_j)
        let two_omega = (2.0 * omega_j.0, 2.0 * omega_j.1);
        // division by complex: (a-b) / (2*omega) = (a-b) * conj(2*omega) / |2*omega|^2
        let num = csub(a, b);
        let denom_conj = cconj(two_omega);
        let denom_sq = two_omega.0 * two_omega.0 + two_omega.1 * two_omega.1;
        f1[k] = cdiv_real(cmul(num, denom_conj), denom_sq);
    }
    (f0, f1)
}

/// Merges two (n/2)-element FFT polynomials into one n-element polynomial.
pub fn merge_fft(f0: &[Complex64], f1: &[Complex64], n: usize) -> Vec<Complex64> {
    let logn = log2n(n);
    let h = n / 2;
    let mut f = vec![(0.0f64, 0.0f64); n];
    for k in 0..h {
        let j = bit_rev(k, logn - 1);
        let angle = PI * (2 * j + 1) as f64 / n as f64;
        let omega_j: Complex64 = (angle.cos(), angle.sin());
        let t = cmul(omega_j, f1[k]);
        f[2 * k] = cadd(f0[k], t);
        f[2 * k + 1] = csub(f0[k], t);
    }
    f
}

/// Converts i32 polynomial to complex FFT domain.
pub fn int32s_to_fft(a: &[i32], n: usize) -> Vec<Complex64> {
    let mut f: Vec<Complex64> = a.iter().map(|&v| (v as f64, 0.0)).collect();
    fft(&mut f, n);
    f
}

/// Applies IFFT and rounds to nearest integer polynomial.
pub fn round_fft_to_int32s(fv: &[Complex64], n: usize) -> Vec<i32> {
    let mut tmp = fv.to_vec();
    ifft(&mut tmp, n);
    tmp.iter().map(|v| v.0.round() as i32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fft_ifft_roundtrip() {
        let n = 64;
        let orig: Vec<Complex64> = (0..n).map(|i| (i as f64, 0.0)).collect();
        let mut f = orig.clone();
        fft(&mut f, n);
        ifft(&mut f, n);
        for (a, b) in orig.iter().zip(f.iter()) {
            assert!((a.0 - b.0).abs() < 1e-6, "mismatch: {} vs {}", a.0, b.0);
        }
    }

    #[test]
    fn test_fft_split_merge() {
        let n = 64;
        let orig: Vec<Complex64> = (0..n).map(|i| (i as f64 * 0.5, 0.0)).collect();
        let mut f = orig.clone();
        fft(&mut f, n);
        let (f0, f1) = split_fft(&f, n);
        let reconstructed = merge_fft(&f0, &f1, n);
        for (a, b) in f.iter().zip(reconstructed.iter()) {
            assert!((a.0 - b.0).abs() < 1e-9, "re mismatch");
            assert!((a.1 - b.1).abs() < 1e-9, "im mismatch");
        }
    }
}
