/**
 * FN-DSA signing (FIPS 206).
 * Port of Python sign.py.
 */
import { createHash } from 'crypto';
import { Q } from './params.js';
import { decodeSk, encodeSig } from './encode.js';
import { ntt, intt, polyMulNtt, polyInvNtt } from './ntt.js';
import { fft, ifft } from './fft.js';

export function hashToPoint(msg, params) {
  const n = params.n;
  const out = new Int32Array(n);
  let count = 0;
  let outputLen = 4 * n;
  while (count < n) {
    const buf = createHash('shake256', {outputLength: outputLen}).update(msg).digest();
    for (let i = 0; i + 1 < buf.length && count < n; i += 2) {
      const v = buf[i] | (buf[i + 1] << 8);
      if (v < 5 * Q) out[count++] = v % Q;
    }
    outputLen *= 2;
  }
  return out;
}

function centerModQ(v) {
  v = ((v % Q) + Q) % Q;
  if (v > (Q >> 1)) v -= Q;
  return v;
}

function polyToFft(a, n) {
  return fft(Array.from(a), n);
}

function roundFftToInts(fFft, n) {
  const tmp = ifft(fFft, n);
  return tmp.map(v => Math.round(v[0]));
}

function recoverG(f, g, F, n) {
  const gModQ = Array.from(g).map(v => ((v % Q) + Q) % Q);
  const FModQ = Array.from(F).map(v => ((v % Q) + Q) % Q);
  const gF = polyMulNtt(gModQ, FModQ, n);

  const fModQ = Array.from(f).map(v => ((v % Q) + Q) % Q);
  const fNttVals = ntt(fModQ, n);
  if (Array.from(fNttVals).some(v => v === 0)) return null;

  const fInv = polyInvNtt(fModQ, n);
  const G = polyMulNtt(gF, Array.from(fInv), n);
  return Array.from(G).map(centerModQ);
}

function normSq(s1, s2) {
  let sum = 0;
  for (const v of s1) sum += v * v;
  for (const v of s2) sum += v * v;
  return sum;
}

/**
 * Babai nearest-plane sampler for FN-DSA signing.
 * NOT FIPS 206 Algorithm 11 — Babai nearest-plane.
 * Suitable for correctness testing only.
 */
function ffSamplingBabai(c, f, g, F, G, n) {
  const cFft = polyToFft(c, n);
  const fFft = polyToFft(f, n);
  const gFft = polyToFft(g, n);
  const FFft = polyToFft(F, n);
  const GFft = polyToFft(G, n);

  // Gram-Schmidt: compute b1* per FFT point
  const b1StarFft = new Array(n);
  const b1StarNormSq = new Array(n);

  for (let j = 0; j < n; j++) {
    const [gjRe, gjIm] = gFft[j];
    const [fjRe, fjIm] = fFft[j];
    const [GjRe, GjIm] = GFft[j];
    const [FjRe, FjIm] = FFft[j];

    const b0NormSq = gjRe * gjRe + gjIm * gjIm + fjRe * fjRe + fjIm * fjIm;

    let mu10Re = 0, mu10Im = 0;
    if (b0NormSq !== 0) {
      // mu10 = (Gj*conj(gj) + Fj*conj(fj)) / b0NormSq
      const numRe = GjRe * gjRe + GjIm * gjIm + FjRe * fjRe + FjIm * fjIm;
      const numIm = GjIm * gjRe - GjRe * gjIm + FjIm * fjRe - FjRe * fjIm;
      mu10Re = numRe / b0NormSq;
      mu10Im = numIm / b0NormSq;
    }

    // b1s = (Gj - mu10*gj, -Fj + mu10*fj)
    const b1s0Re = GjRe - (mu10Re * gjRe - mu10Im * gjIm);
    const b1s0Im = GjIm - (mu10Re * gjIm + mu10Im * gjRe);
    const b1s1Re = -FjRe + (mu10Re * fjRe - mu10Im * fjIm);
    const b1s1Im = -FjIm + (mu10Re * fjIm + mu10Im * fjRe);

    b1StarFft[j] = [[b1s0Re, b1s0Im], [b1s1Re, b1s1Im]];
    b1StarNormSq[j] = b1s0Re * b1s0Re + b1s0Im * b1s0Im + b1s1Re * b1s1Re + b1s1Im * b1s1Im;
  }

  // Step 1: project (c_j, 0) along b1*_j
  const tau1Fft = new Array(n);
  for (let j = 0; j < n; j++) {
    const b1sNorm = b1StarNormSq[j];
    if (b1sNorm !== 0) {
      const [cjRe, cjIm] = cFft[j];
      const [b1s0Re, b1s0Im] = b1StarFft[j][0];
      // tau1 = c_j * conj(b1s0) / b1sNorm
      const numRe = cjRe * b1s0Re + cjIm * b1s0Im;
      const numIm = cjIm * b1s0Re - cjRe * b1s0Im;
      tau1Fft[j] = [numRe / b1sNorm, numIm / b1sNorm];
    } else {
      tau1Fft[j] = [0, 0];
    }
  }

  const z1 = roundFftToInts(tau1Fft, n);
  const z1Fft = polyToFft(z1, n);

  // Update target: t'_j = (c_j, 0) - z1_j*(G_j, -F_j)
  const cPrimeFft = new Array(n);
  const xPrimeFft = new Array(n);
  for (let j = 0; j < n; j++) {
    const [cjRe, cjIm] = cFft[j];
    const [z1jRe, z1jIm] = z1Fft[j];
    const [GjRe, GjIm] = GFft[j];
    const [FjRe, FjIm] = FFft[j];
    cPrimeFft[j] = [cjRe - (z1jRe * GjRe - z1jIm * GjIm), cjIm - (z1jRe * GjIm + z1jIm * GjRe)];
    xPrimeFft[j] = [z1jRe * FjRe - z1jIm * FjIm, z1jRe * FjIm + z1jIm * FjRe];
  }

  // Step 2: project t'_j along b0*_j = (g_j, -f_j)
  const tau0Fft = new Array(n);
  for (let j = 0; j < n; j++) {
    const [gjRe, gjIm] = gFft[j];
    const [fjRe, fjIm] = fFft[j];
    const b0NormSq = gjRe * gjRe + gjIm * gjIm + fjRe * fjRe + fjIm * fjIm;
    if (b0NormSq !== 0) {
      const [cpRe, cpIm] = cPrimeFft[j];
      const [xpRe, xpIm] = xPrimeFft[j];
      // tau0 = (c'_j*conj(g_j) - x'_j*conj(f_j)) / b0NormSq
      const numRe = cpRe * gjRe + cpIm * gjIm - (xpRe * fjRe + xpIm * fjIm);
      const numIm = cpIm * gjRe - cpRe * gjIm - (xpIm * fjRe - xpRe * fjIm);
      tau0Fft[j] = [numRe / b0NormSq, numIm / b0NormSq];
    } else {
      tau0Fft[j] = [0, 0];
    }
  }

  const z0 = roundFftToInts(tau0Fft, n);
  const z0Fft = polyToFft(z0, n);

  // Compute signature components
  const s1Fft = new Array(n);
  const s2Fft = new Array(n);
  for (let j = 0; j < n; j++) {
    const [z0jRe, z0jIm] = z0Fft[j];
    const [z1jRe, z1jIm] = z1Fft[j];
    const [fjRe, fjIm] = fFft[j];
    const [gjRe, gjIm] = gFft[j];
    const [FjRe, FjIm] = FFft[j];
    const [GjRe, GjIm] = GFft[j];
    const [cjRe, cjIm] = cFft[j];

    s1Fft[j] = [
      z0jRe * fjRe - z0jIm * fjIm + z1jRe * FjRe - z1jIm * FjIm,
      z0jRe * fjIm + z0jIm * fjRe + z1jRe * FjIm + z1jIm * FjRe
    ];
    s2Fft[j] = [
      cjRe - (z0jRe * gjRe - z0jIm * gjIm) - (z1jRe * GjRe - z1jIm * GjIm),
      cjIm - (z0jRe * gjIm + z0jIm * gjRe) - (z1jRe * GjIm + z1jIm * GjRe)
    ];
  }

  const s1Raw = roundFftToInts(s1Fft, n);
  const s2Raw = roundFftToInts(s2Fft, n);

  const s1 = s1Raw.map(centerModQ);
  const s2 = s2Raw.map(centerModQ);
  return [s1, s2];
}

export function signInternal(sk, msg, params, rng) {
  const result = decodeSk(sk instanceof Uint8Array ? sk : new Uint8Array(sk), params);
  if (result === null) throw new Error("fndsa: invalid secret key");
  const { f, g, F } = result;
  const n = params.n;

  const G = recoverG(f, g, F, n);
  if (G === null) throw new Error("fndsa: invalid secret key: f is not invertible mod q");

  // Pre-compute h = g * f^{-1} mod q
  const fModQ = Array.from(f).map(v => ((v % Q) + Q) % Q);
  const gModQ = Array.from(g).map(v => ((v % Q) + Q) % Q);
  const fInv = polyInvNtt(fModQ, n);
  const h = polyMulNtt(gModQ, Array.from(fInv), n);

  for (let attempt = 0; attempt < 1000; attempt++) {
    const saltArr = rng(40);
    const salt = saltArr instanceof Uint8Array ? saltArr : new Uint8Array(saltArr);

    // Compute target c = HashToPoint(salt || msg)
    const hashInput = new Uint8Array(40 + msg.length);
    hashInput.set(salt, 0);
    hashInput.set(msg instanceof Uint8Array ? msg : Buffer.from(msg), 40);
    const c = hashToPoint(hashInput, params);

    // Center c in (-Q/2, Q/2]
    const cCentered = Array.from(c).map(centerModQ);

    const [s1, s2] = ffSamplingBabai(cCentered, Array.from(f), Array.from(g), Array.from(F), G, n);

    // Verify s1*h + s2 ≡ c (mod q)
    const s1ModQ = s1.map(v => ((v % Q) + Q) % Q);
    const s1h = polyMulNtt(s1ModQ, Array.from(h), n);
    let valid = true;
    for (let i = 0; i < n; i++) {
      const total = ((s1h[i] + s2[i]) % Q + Q) % Q;
      if (total !== c[i]) { valid = false; break; }
    }
    if (!valid) continue;

    // Check norm bound
    const ns = normSq(s1, s2);
    if (ns > params.betaSq) continue;

    // Encode signature
    const sig = encodeSig(salt, s1, params);
    if (sig === null) continue;

    return sig;
  }

  throw new Error("fndsa: signing failed after 1000 attempts");
}
