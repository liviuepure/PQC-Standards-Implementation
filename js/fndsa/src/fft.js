/**
 * Complex FFT for FN-DSA (FIPS 206 / FALCON).
 * Negacyclic complex FFT over C[x]/(x^n+1).
 * Mirrors Python fft.py exactly.
 */

function fftLogN(n) {
  let logn = 0, t = n;
  while (t > 1) { t >>= 1; logn++; }
  return logn;
}

function fftBitRev(k, logn) {
  let r = 0;
  for (let i = 0; i < logn; i++) {
    r = (r << 1) | (k & 1);
    k >>= 1;
  }
  return r;
}

/**
 * Forward negacyclic complex FFT over C[x]/(x^n+1).
 * f: array of n numbers (real polynomial coefficients).
 * Returns array of n [re, im] pairs.
 */
export function fft(f, n) {
  const logn = fftLogN(n);
  // Copy input as complex pairs [re, im]
  const a = new Array(n);
  for (let i = 0; i < n; i++) a[i] = [f[i], 0.0];

  let k = 0;
  let length = n >> 1;
  while (length >= 1) {
    for (let start = 0; start < n; start += 2 * length) {
      k++;
      const brk = fftBitRev(k, logn);
      const angle = Math.PI * brk / n;
      const wRe = Math.cos(angle), wIm = Math.sin(angle);
      for (let j = start; j < start + length; j++) {
        const [aRe, aIm] = a[j];
        const [bRe, bIm] = a[j + length];
        // t = w * a[j+length]
        const tRe = wRe * bRe - wIm * bIm;
        const tIm = wRe * bIm + wIm * bRe;
        a[j + length] = [aRe - tRe, aIm - tIm];
        a[j] = [aRe + tRe, aIm + tIm];
      }
    }
    length >>= 1;
  }
  return a;
}

/**
 * Inverse negacyclic complex FFT over C[x]/(x^n+1).
 * f: array of n [re, im] pairs.
 * Returns array of n [re, im] pairs (scaled by 1/n).
 */
export function ifft(f, n) {
  const logn = fftLogN(n);
  const a = f.map(v => [v[0], v[1]]);

  let k = n;
  let length = 1;
  while (length < n) {
    for (let start = n - 2 * length; start >= 0; start -= 2 * length) {
      k--;
      const brk = fftBitRev(k, logn);
      const angle = Math.PI * brk / n;
      const wRe = Math.cos(angle), wIm = -Math.sin(angle); // conjugate = inverse twiddle
      for (let j = start; j < start + length; j++) {
        const [tRe, tIm] = a[j];
        const [bRe, bIm] = a[j + length];
        a[j] = [tRe + bRe, tIm + bIm];
        // a[j+length] = w_inv * (t - a[j+length])
        const dRe = tRe - bRe, dIm = tIm - bIm;
        a[j + length] = [wRe * dRe - wIm * dIm, wRe * dIm + wIm * dRe];
      }
    }
    length <<= 1;
  }
  const invN = 1.0 / n;
  return a.map(v => [v[0] * invN, v[1] * invN]);
}

/**
 * Split FFT-domain polynomial into two halves.
 * Given f in FFT domain (bit-reversed), computes f0, f1 where
 * f(x) = f0(x^2) + x*f1(x^2).
 */
export function splitFft(F, n) {
  const logn = fftLogN(n);
  const h = n >> 1;
  const f0 = new Array(h);
  const f1 = new Array(h);
  for (let k = 0; k < h; k++) {
    const j = fftBitRev(k, logn - 1);
    const angle = Math.PI * (2 * j + 1) / n;
    const omRe = Math.cos(angle), omIm = Math.sin(angle);
    const [aRe, aIm] = F[2 * k];
    const [bRe, bIm] = F[2 * k + 1];
    f0[k] = [(aRe + bRe) / 2, (aIm + bIm) / 2];
    // f1[k] = (a - b) / (2 * omega_j)
    const dRe = (aRe - bRe) / 2, dIm = (aIm - bIm) / 2;
    // Divide by omega_j: multiply by conj(omega_j) / |omega_j|^2, but |omega_j|=1
    // So divide by omega_j = multiply by conj(omega_j)
    f1[k] = [dRe * omRe + dIm * omIm, dIm * omRe - dRe * omIm];
  }
  return [f0, f1];
}

/**
 * Merge two FFT-domain half-polynomials into one.
 * Inverse of splitFft.
 */
export function mergeFft(f0, f1, n) {
  const logn = fftLogN(n);
  const h = n >> 1;
  const result = new Array(n);
  for (let k = 0; k < h; k++) {
    const j = fftBitRev(k, logn - 1);
    const angle = Math.PI * (2 * j + 1) / n;
    const omRe = Math.cos(angle), omIm = Math.sin(angle);
    const [f0Re, f0Im] = f0[k];
    const [f1Re, f1Im] = f1[k];
    // t = omega_j * f1[k]
    const tRe = omRe * f1Re - omIm * f1Im;
    const tIm = omRe * f1Im + omIm * f1Re;
    result[2 * k] = [f0Re + tRe, f0Im + tIm];
    result[2 * k + 1] = [f0Re - tRe, f0Im - tIm];
  }
  return result;
}
