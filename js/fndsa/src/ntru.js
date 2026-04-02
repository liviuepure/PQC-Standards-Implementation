/**
 * NTRU key generation for FN-DSA (FIPS 206 Algorithm 5).
 * Port of Python ntru.py / Go ntru.go.
 * Uses BigInt for all exact integer arithmetic.
 * Uses BigInt fixed-point FFT for high-precision Babai reduction.
 */
import { Q } from './params.js';
import { sampleGaussian } from './gaussian.js';
import { ntt } from './ntt.js';

function ntruSigma(n) {
  return 1.17 * Math.sqrt(Q / (2 * n));
}

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
 * Multiply two polynomials over Z[x]/(x^n+1) using BigInt.
 * Returns Array of BigInt.
 */
function polyMulBig(a, b, n) {
  const c = new Array(n).fill(0n);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      const idx = i + j;
      const val = a[i] * b[j];
      if (idx < n) {
        c[idx] += val;
      } else {
        c[idx - n] -= val;
      }
    }
  }
  return c;
}

/**
 * Compute field norm N(f) from Z[x]/(x^n+1) to Z[x]/(x^{n/2}+1).
 */
function fieldNorm(f, n) {
  const h = n >> 1;
  const f0 = new Array(h), f1 = new Array(h);
  for (let i = 0; i < h; i++) {
    f0[i] = f[2 * i];
    f1[i] = f[2 * i + 1];
  }
  const f0sq = polyMulBig(f0, f0, h);
  const f1sq = polyMulBig(f1, f1, h);
  const result = new Array(h);
  result[0] = f0sq[0] + f1sq[h - 1];
  for (let i = 1; i < h; i++) {
    result[i] = f0sq[i] - f1sq[i - 1];
  }
  return result;
}

/**
 * Tower conjugate: f*(x) = f0(x^2) - x*f1(x^2).
 */
function towerConjugate(f) {
  const result = f.slice();
  for (let i = 1; i < f.length; i += 2) {
    result[i] = -result[i];
  }
  return result;
}

/**
 * Lift (Fp, Gp) from degree n/2 to degree n.
 */
function lift(Fp, Gp, f, g, n) {
  const h = n >> 1;
  const fpLift = new Array(n).fill(0n);
  const gpLift = new Array(n).fill(0n);
  for (let i = 0; i < h; i++) {
    fpLift[2 * i] = Fp[i];
    gpLift[2 * i] = Gp[i];
  }
  const fConj = towerConjugate(f);
  const gConj = towerConjugate(g);
  const F = polyMulBig(gConj, fpLift, n);
  const G = polyMulBig(fConj, gpLift, n);
  return [F, G];
}

// ─────────────────────────────────────────────────────────────────────────────
// BigInt fixed-point FFT infrastructure
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute π * 2^P as BigInt using Machin's formula.
 */
function bigIntPi(P) {
  function arctanRecip(d, bits) {
    const D = BigInt(d);
    const D2 = D * D;
    const S = 1n << bits;
    let term = S / D;
    let sum = term;
    let sign = -1n;
    let k = 3n;
    while (true) {
      term = term / D2;
      const addend = term / k;
      if (addend === 0n) break;
      sum += sign * addend;
      sign = -sign;
      k += 2n;
    }
    return sum;
  }
  const EXTRA = BigInt(P) + 64n;
  return 4n * (4n * arctanRecip(5, EXTRA) - arctanRecip(239, EXTRA)) >> 64n;
}

// Cache for pi values at various precisions
// bigIntPi(P) returns π * 2^P as a BigInt (P fractional bits).
const _piCache = new Map();
function getCachedPi(P) {
  if (!_piCache.has(P)) {
    _piCache.set(P, bigIntPi(P));
  }
  return _piCache.get(P);
}

/**
 * Compute twiddle factors for BigInt FFT of size n at PREC bits of precision.
 * Returns {cosArr, sinArr, SCALE} where:
 *   cosArr[k] = round(cos(π*k/n) * SCALE)
 *   sinArr[k] = round(sin(π*k/n) * SCALE)
 *   SCALE = 2^PREC
 */
function computeTwiddles(n, PREC) {
  const P = BigInt(PREC);
  const SCALE = 1n << P;

  // Compute cos(π/n) and sin(π/n) using Taylor series (small angle x = π/n)
  // getCachedPi(PREC) returns π * 2^PREC (PREC fractional bits of precision)
  const pi = getCachedPi(PREC);
  const x = pi / BigInt(n); // = π/n * 2^PREC (SCALE units)
  const x2 = x * x / SCALE; // = (π/n)^2 * 2^PREC (SCALE units)

  let sinSum = x;
  let cosSum = SCALE;
  let sinTerm = x;
  let cosTerm = SCALE;

  for (let i = 1n; i <= 500n; i++) {
    cosTerm = -(cosTerm * x2) / (SCALE * (2n * i - 1n) * (2n * i));
    sinTerm = -(sinTerm * x2) / (SCALE * (2n * i) * (2n * i + 1n));
    cosSum += cosTerm;
    sinSum += sinTerm;
    const ac = cosTerm < 0n ? -cosTerm : cosTerm;
    const as = sinTerm < 0n ? -sinTerm : sinTerm;
    if (ac === 0n && as === 0n) break;
  }

  const c1 = cosSum; // cos(π/n) * SCALE
  const s1 = sinSum; // sin(π/n) * SCALE

  // Use Chebyshev recurrence: cos(kθ) = 2*c1*cos((k-1)θ) - cos((k-2)θ)
  const cosArr = new Array(n + 1);
  const sinArr = new Array(n + 1);
  cosArr[0] = SCALE;
  sinArr[0] = 0n;
  cosArr[1] = c1;
  sinArr[1] = s1;

  for (let k = 2; k <= n; k++) {
    cosArr[k] = (2n * c1 * cosArr[k - 1] - SCALE * cosArr[k - 2]) / SCALE;
    sinArr[k] = (2n * c1 * sinArr[k - 1] - SCALE * sinArr[k - 2]) / SCALE;
  }

  return { cosArr, sinArr, SCALE };
}

// Cache for twiddle factors
const _twiddleCache = new Map();

function getCachedTwiddles(n, PREC) {
  const key = `${n}_${PREC}`;
  if (!_twiddleCache.has(key)) {
    _twiddleCache.set(key, computeTwiddles(n, PREC));
  }
  return _twiddleCache.get(key);
}

/**
 * Forward BigInt fixed-point FFT.
 * a: array of [re, im] BigInt pairs (scaled by SCALE)
 * Returns array of [re, im] BigInt pairs (scaled by SCALE)
 */
function bigFFT(a, n, twiddles) {
  const { cosArr, sinArr, SCALE } = twiddles;
  const logN = fftLogN(n);
  const arr = a.map(v => [v[0], v[1]]);

  let k = 0;
  let length = n >> 1;
  while (length >= 1) {
    for (let start = 0; start < n; start += 2 * length) {
      k++;
      const brk = fftBitRev(k, logN);
      const wRe = cosArr[brk];
      const wIm = sinArr[brk];
      for (let j = start; j < start + length; j++) {
        const [aRe, aIm] = arr[j];
        const [bRe, bIm] = arr[j + length];
        // t = w * b, scaled
        const tRe = (wRe * bRe - wIm * bIm) / SCALE;
        const tIm = (wRe * bIm + wIm * bRe) / SCALE;
        arr[j + length] = [aRe - tRe, aIm - tIm];
        arr[j] = [aRe + tRe, aIm + tIm];
      }
    }
    length >>= 1;
  }
  return arr;
}

/**
 * Inverse BigInt fixed-point FFT.
 * Returns array of [re, im] BigInt pairs (scaled by SCALE, divided by n)
 */
function bigIFFT(a, n, twiddles) {
  const { cosArr, sinArr, SCALE } = twiddles;
  const logN = fftLogN(n);
  const arr = a.map(v => [v[0], v[1]]);
  const nBig = BigInt(n);

  let k = n;
  let length = 1;
  while (length < n) {
    for (let start = n - 2 * length; start >= 0; start -= 2 * length) {
      k--;
      const brk = fftBitRev(k, logN);
      const wRe = cosArr[brk];
      const wIm = -sinArr[brk]; // conjugate = inverse
      for (let j = start; j < start + length; j++) {
        const [tRe, tIm] = arr[j];
        const [bRe, bIm] = arr[j + length];
        arr[j] = [tRe + bRe, tIm + bIm];
        const dRe = tRe - bRe, dIm = tIm - bIm;
        arr[j + length] = [
          (wRe * dRe - wIm * dIm) / SCALE,
          (wRe * dIm + wIm * dRe) / SCALE
        ];
      }
    }
    length <<= 1;
  }
  // Scale by 1/n
  return arr.map(([re, im]) => [re / nBig, im / nBig]);
}

// Fixed precision table for each n level (worst-case coefficient sizes + margin).
// These are derived from empirical observation of NTRU keygen for n=512 and n=1024.
// Using fixed values ensures twiddle cache hits across multiple keygen attempts.
// For n >= 256, coefficients are small enough for float64 (handled separately).
const _FIXED_PREC = new Map([
  [2, 2600],
  [4, 1400],
  [8, 750],
  [16, 440],
  [32, 300],
  [64, 200],
  [128, 150],
]);

/**
 * Babai reduction using BigInt fixed-point FFT.
 * Returns k as array of BigInt (values may be large!).
 */
function babaiReduceBigInt(F, G, f, g, n) {
  // Use fixed PREC per n level for effective twiddle caching
  const PREC = _FIXED_PREC.get(n) || 200;

  const twiddles = getCachedTwiddles(n, PREC);
  const SCALE = twiddles.SCALE;

  // Convert to BigInt scaled complex
  const toScaled = arr => arr.map(v => [v * SCALE, 0n]);

  const fC = bigFFT(toScaled(f), n, twiddles);
  const gC = bigFFT(toScaled(g), n, twiddles);
  const FC = bigFFT(toScaled(F), n, twiddles);
  const GC = bigFFT(toScaled(G), n, twiddles);

  const kC = new Array(n);
  for (let i = 0; i < n; i++) {
    const [fiRe, fiIm] = fC[i];
    const [giRe, giIm] = gC[i];
    const [FiRe, FiIm] = FC[i];
    const [GiRe, GiIm] = GC[i];

    // num = F*conj(f) + G*conj(g)  (using conj since IFFT computes inner product)
    // In the negacyclic FFT, the Babai formula is:
    // k_j = (F_j * conj(f_j) + G_j * conj(g_j)) / (|f_j|^2 + |g_j|^2)
    // Here f_j = fiRe + i*fiIm (all scaled by SCALE)
    const numRe = FiRe * fiRe + FiIm * fiIm + GiRe * giRe + GiIm * giIm;
    const numIm = FiIm * fiRe - FiRe * fiIm + GiIm * giRe - GiRe * giIm;
    const denom = fiRe * fiRe + fiIm * fiIm + giRe * giRe + giIm * giIm;

    if (denom === 0n) {
      kC[i] = [0n, 0n];
    } else {
      // k_j = (numRe + i*numIm) / denom, all scaled by SCALE^2
      // We need result scaled by SCALE for IFFT
      // = (numRe * SCALE) / denom + i * (numIm * SCALE) / denom
      kC[i] = [
        (numRe * SCALE) / denom,
        (numIm * SCALE) / denom
      ];
    }
  }

  const kIfft = bigIFFT(kC, n, twiddles);

  // Round to nearest integer (BigInt)
  function bigRound(v) {
    // v = real_value * SCALE, divide by SCALE with rounding
    const halfScale = SCALE / 2n;
    const absDenom = SCALE;
    let q = v / absDenom;
    const r = v - q * absDenom;
    // Round: if |r| >= SCALE/2, adjust
    const ar = r < 0n ? -r : r;
    if (ar >= halfScale) {
      if (r > 0n) q++;
      else q--;
    }
    return q;
  }

  return kIfft.map(([re]) => bigRound(re));
}

/**
 * Fast float64 Babai reduction for small coefficients (< 2^53).
 * Returns k as array of Number.
 */
function babaiReduceFloat64(F, G, f, g, n) {
  // Import fft/ifft dynamically to avoid circular... actually import at top
  // We'll reimplement the minimal FFT needed here
  const logN = fftLogN(n);

  function bitRev(k, logn) {
    let r = 0;
    for (let i = 0; i < logn; i++) { r = (r << 1) | (k & 1); k >>= 1; }
    return r;
  }

  function doFFT(a) {
    const arr = a.map(v => [v[0], v[1]]);
    let k = 0;
    let length = n >> 1;
    while (length >= 1) {
      for (let start = 0; start < n; start += 2 * length) {
        k++;
        const brk = bitRev(k, logN);
        const angle = Math.PI * brk / n;
        const wRe = Math.cos(angle), wIm = Math.sin(angle);
        for (let j = start; j < start + length; j++) {
          const [aRe, aIm] = arr[j];
          const [bRe, bIm] = arr[j + length];
          const tRe = wRe * bRe - wIm * bIm;
          const tIm = wRe * bIm + wIm * bRe;
          arr[j + length] = [aRe - tRe, aIm - tIm];
          arr[j] = [aRe + tRe, aIm + tIm];
        }
      }
      length >>= 1;
    }
    return arr;
  }

  function doIFFT(a) {
    const arr = a.map(v => [v[0], v[1]]);
    let k = n;
    let length = 1;
    while (length < n) {
      for (let start = n - 2 * length; start >= 0; start -= 2 * length) {
        k--;
        const brk = bitRev(k, logN);
        const angle = Math.PI * brk / n;
        const wRe = Math.cos(angle), wIm = -Math.sin(angle);
        for (let j = start; j < start + length; j++) {
          const [tRe, tIm] = arr[j];
          const [bRe, bIm] = arr[j + length];
          arr[j] = [tRe + bRe, tIm + bIm];
          const dRe = tRe - bRe, dIm = tIm - bIm;
          arr[j + length] = [wRe * dRe - wIm * dIm, wRe * dIm + wIm * dRe];
        }
      }
      length <<= 1;
    }
    const invN = 1.0 / n;
    return arr.map(([re, im]) => [re * invN, im * invN]);
  }

  const fC = doFFT(f.map(v => [Number(v), 0]));
  const gC = doFFT(g.map(v => [Number(v), 0]));
  const FC = doFFT(F.map(v => [Number(v), 0]));
  const GC = doFFT(G.map(v => [Number(v), 0]));

  const kC = new Array(n);
  for (let i = 0; i < n; i++) {
    const [fiRe, fiIm] = fC[i];
    const [giRe, giIm] = gC[i];
    const [FiRe, FiIm] = FC[i];
    const [GiRe, GiIm] = GC[i];
    const numRe = FiRe * fiRe + FiIm * fiIm + GiRe * giRe + GiIm * giIm;
    const numIm = FiIm * fiRe - FiRe * fiIm + GiIm * giRe - GiRe * giIm;
    const denom = fiRe * fiRe + fiIm * fiIm + giRe * giRe + giIm * giIm;
    kC[i] = denom !== 0 ? [numRe / denom, numIm / denom] : [0, 0];
  }

  const kIfft = doIFFT(kC);
  // Return as BigInt
  return kIfft.map(([re]) => BigInt(Math.round(re)));
}

function maxBitLength(polys) {
  let result = 0;
  for (const p of polys) {
    for (const v of p) {
      const av = v < 0n ? -v : v;
      const bl = av === 0n ? 0 : av.toString(2).length;
      if (bl > result) result = bl;
    }
  }
  return result;
}

/**
 * Recursively solve f*G - g*F = Q over Z[x]/(x^n+1).
 * Returns [F, G] as BigInt arrays.
 */
function ntruSolveRecursive(n, f, g) {
  if (n === 1) {
    function extGcd(a, b) {
      if (b === 0n) return [a, 1n, 0n];
      const [g2, u, v] = extGcd(b, a % b);
      return [g2, v, u - (a / b) * v];
    }
    const [gcdVal, u, v] = extGcd(f[0], g[0]);
    const Qb = BigInt(Q);
    const absGcd = gcdVal < 0n ? -gcdVal : gcdVal;
    if (Qb % absGcd !== 0n) throw new Error("gcd does not divide Q at base case");
    const scale = Qb / absGcd;
    const su = gcdVal < 0n ? -u : u;
    const sv = gcdVal < 0n ? -v : v;
    return [[-sv * scale], [su * scale]];
  }

  const fNorm = fieldNorm(f, n);
  const gNorm = fieldNorm(g, n);

  const [Fp, Gp] = ntruSolveRecursive(n >> 1, fNorm, gNorm);
  let [F, G] = lift(Fp, Gp, f, g, n);

  // Babai reduction: 2 rounds
  for (let round = 0; round < 2; round++) {
    const maxB = maxBitLength([f, g, F, G]);
    let kBig;
    if (maxB <= 50) {
      // All fit in float64, use fast path
      kBig = babaiReduceFloat64(F, G, f, g, n);
    } else {
      // Need BigInt precision
      kBig = babaiReduceBigInt(F, G, f, g, n);
    }
    const kf = polyMulBig(kBig, f, n);
    const kg = polyMulBig(kBig, g, n);
    for (let i = 0; i < n; i++) {
      F[i] -= kf[i];
      G[i] -= kg[i];
    }
  }

  return [F, G];
}

function verifyNtru(f, g, F, G, n) {
  const fG = polyMulBig(f, G, n);
  const gF = polyMulBig(g, F, n);
  const Qb = BigInt(Q);
  if (fG[0] - gF[0] !== Qb) return false;
  for (let i = 1; i < n; i++) {
    if (fG[i] - gF[i] !== 0n) return false;
  }
  return true;
}

/**
 * Generate NTRU key pair (f, g, F) for FN-DSA.
 * rng: function(nBytes) -> Uint8Array
 * Returns {f, g, F} as regular number arrays.
 */
export function ntruKeygen(params, rng) {
  const n = params.n;
  const sigma = ntruSigma(n);

  for (let attempt = 0; attempt < 1000; attempt++) {
    const f = [];
    const g = [];
    for (let i = 0; i < n; i++) {
      f.push(sampleGaussian(sigma, rng));
      g.push(sampleGaussian(sigma, rng));
    }

    // f must be invertible mod 2
    let xorSum = 0;
    for (const v of f) xorSum ^= v & 1;
    if (xorSum === 0) continue;

    // f must be invertible mod q
    const fModQ = f.map(v => ((v % Q) + Q) % Q);
    const fNtt = ntt(fModQ, n);
    if (Array.from(fNtt).some(v => v === 0)) continue;

    // Gram-Schmidt norm bound
    let normSq = 0;
    for (const v of f) normSq += v * v;
    for (const v of g) normSq += v * v;
    if (normSq > 1.17 * 1.17 * Q * n) continue;

    // Solve NTRU equation
    let Fbig, Gbig;
    try {
      const fBig = f.map(BigInt);
      const gBig = g.map(BigInt);
      [Fbig, Gbig] = ntruSolveRecursive(n, fBig, gBig);
    } catch (e) {
      continue;
    }

    const F = Fbig.map(Number);
    const G = Gbig.map(Number);

    // Check F coefficients fit in int8
    if (F.some(v => v < -128 || v > 127)) continue;

    // Verify NTRU equation
    const fBig2 = f.map(BigInt);
    const gBig2 = g.map(BigInt);
    if (!verifyNtru(fBig2, gBig2, Fbig, Gbig, n)) continue;

    return { f, g, F };
  }

  throw new Error("NTRU key generation failed after 1000 attempts");
}
