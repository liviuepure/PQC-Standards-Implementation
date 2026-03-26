/**
 * ML-DSA key generation, signing, and verification (FIPS 204)
 */

import { randomBytes } from 'node:crypto';
import { Q, modQ, fieldAdd, fieldSub } from './field.js';
import { ntt, invNtt, pointwiseMul } from './ntt.js';
import { h, expandA, expandS, expandMask, sampleInBall } from './hash.js';
import { power2Round, highBits, lowBits, makeHint, useHint, decompose } from './decompose.js';
import { encodePK, decodePK, encodeSK, decodeSK, encodeSig, decodeSig, encodeW1 } from './encode.js';

/**
 * Multiply matrix A (in NTT domain) by vector s (applying NTT first).
 * Returns the result in NTT domain.
 * @param {Int32Array[][]} A - k x l matrix of NTT-domain polynomials
 * @param {Int32Array[]} s - l-vector of polynomials (normal domain)
 * @returns {Int32Array[]} k-vector in NTT domain
 */
function matVecMul(A, s) {
  const k = A.length;
  const l = A[0].length;
  const sNtt = s.map(p => ntt(Int32Array.from(p)));
  const result = [];
  for (let i = 0; i < k; i++) {
    const acc = new Int32Array(256);
    for (let j = 0; j < l; j++) {
      const prod = pointwiseMul(A[i][j], sNtt[j]);
      for (let c = 0; c < 256; c++) {
        acc[c] = modQ(acc[c] + prod[c]);
      }
    }
    result.push(acc);
  }
  return result;
}

/**
 * Multiply matrix A (in NTT domain) by NTT-domain vector.
 * Returns result in NTT domain.
 */
function matVecMulNtt(A, sNtt) {
  const k = A.length;
  const l = A[0].length;
  const result = [];
  for (let i = 0; i < k; i++) {
    const acc = new Int32Array(256);
    for (let j = 0; j < l; j++) {
      const prod = pointwiseMul(A[i][j], sNtt[j]);
      for (let c = 0; c < 256; c++) {
        acc[c] = modQ(acc[c] + prod[c]);
      }
    }
    result.push(acc);
  }
  return result;
}

/**
 * Add two polynomial vectors element-wise.
 */
function vecAdd(a, b) {
  return a.map((p, i) => {
    const r = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      r[j] = modQ(p[j] + b[i][j]);
    }
    return r;
  });
}

/**
 * Subtract polynomial vectors: a - b.
 */
function vecSub(a, b) {
  return a.map((p, i) => {
    const r = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      r[j] = modQ(p[j] - b[i][j]);
    }
    return r;
  });
}

/**
 * Check if all coefficients of a polynomial are within [-bound, bound].
 * Coefficients are in [0, Q), centered representation means val or val - Q.
 */
function checkNormBound(poly, bound) {
  for (let i = 0; i < 256; i++) {
    let val = poly[i];
    // Center to [-Q/2, Q/2)
    if (val > (Q >>> 1)) val -= Q;
    if (val < 0) val = -val;
    if (val >= bound) return false;
  }
  return true;
}

/**
 * Check norm bound for an entire vector.
 */
function checkVecNormBound(vec, bound) {
  for (const poly of vec) {
    if (!checkNormBound(poly, bound)) return false;
  }
  return true;
}

/**
 * ML-DSA Key Generation (Algorithm 1 in FIPS 204)
 * @param {object} params - parameter set (ML_DSA_44, ML_DSA_65, or ML_DSA_87)
 * @param {Uint8Array} [seed] - optional 32-byte seed for deterministic keygen
 * @returns {{ pk: Uint8Array, sk: Uint8Array }}
 */
export function keyGen(params, seed) {
  const { k, l, eta } = params;

  // Step 1: xi = random 32 bytes (or provided seed)
  const xi = seed || randomBytes(32);

  // Step 2: (rho, rhoPrime, K) = H(xi || k || l, 128)
  const hashInput = new Uint8Array(xi.length + 2);
  hashInput.set(xi);
  hashInput[xi.length] = k;
  hashInput[xi.length + 1] = l;
  const expanded = h(hashInput, 128);
  const rho = expanded.slice(0, 32);
  const rhoPrime = expanded.slice(32, 96);
  const K = expanded.slice(96, 128);

  // Step 3: A = expandA(rho)
  const A = expandA(rho, k, l);

  // Step 4: (s1, s2) = expandS(rhoPrime, eta, k, l)
  const { s1, s2 } = expandS(rhoPrime, eta, k, l);

  // Step 5: t = NTT^{-1}(A * NTT(s1)) + s2
  const As1Ntt = matVecMul(A, s1);
  const As1 = As1Ntt.map(p => invNtt(Int32Array.from(p)));
  const t = vecAdd(As1, s2);

  // Step 6: (t1, t0) = power2Round(t)
  const t1 = [];
  const t0 = [];
  for (let i = 0; i < k; i++) {
    const t1i = new Int32Array(256);
    const t0i = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      const [hi, lo] = power2Round(t[i][j]);
      t1i[j] = hi;
      t0i[j] = lo;
    }
    t1.push(t1i);
    t0.push(t0i);
  }

  // Step 7: pk = encodePK(rho, t1)
  const pk = encodePK(rho, t1);

  // Step 8: tr = H(pk, 64)
  const tr = h(pk, 64);

  // Step 9: sk = encodeSK(rho, K, tr, s1, s2, t0, eta)
  const sk = encodeSK(rho, K, tr, s1, s2, t0, eta);

  return { pk, sk };
}

/**
 * ML-DSA Signing (Algorithm 2 in FIPS 204)
 * @param {Uint8Array} sk - secret key
 * @param {Uint8Array} msg - message to sign
 * @param {object} params - parameter set
 * @param {Uint8Array} [rnd] - optional 32-byte randomness (zeros for deterministic)
 * @returns {Uint8Array} signature
 */
export function sign(sk, msg, params, rnd) {
  const { k, l, eta, tau, beta, gamma1, gamma2, omega, lambda } = params;
  const alpha = 2 * gamma2;

  // Decode secret key
  const { rho, K, tr, s1, s2, t0 } = decodeSK(sk, k, l, eta);

  // Precompute A
  const A = expandA(rho, k, l);

  // Precompute NTT of s1, s2, t0
  const s1Ntt = s1.map(p => ntt(Int32Array.from(p)));
  const s2Ntt = s2.map(p => ntt(Int32Array.from(p)));
  const t0Ntt = t0.map(p => ntt(Int32Array.from(p)));

  // mu = H(tr || msg, 64)
  const muInput = new Uint8Array(tr.length + msg.length);
  muInput.set(tr);
  muInput.set(msg, tr.length);
  const mu = h(muInput, 64);

  // rnd = random 32 bytes or zeros for deterministic
  const rndBytes = rnd || new Uint8Array(32);

  // rhoPrime = H(K || rnd || mu, 64)
  const rhoPrimeInput = new Uint8Array(32 + 32 + 64);
  rhoPrimeInput.set(K);
  rhoPrimeInput.set(rndBytes, 32);
  rhoPrimeInput.set(mu, 64);
  const rhoPP = h(rhoPrimeInput, 64);

  let kappa = 0;
  const cTildeLen = lambda / 4;

  // Rejection sampling loop
  while (true) {
    // y = expandMask(rhoPP, gamma1, l, kappa)
    const y = expandMask(rhoPP, gamma1, l, kappa);

    // w = NTT^{-1}(A * NTT(y))
    const AyNtt = matVecMul(A, y);
    const w = AyNtt.map(p => invNtt(Int32Array.from(p)));

    // w1 = highBits(w)
    const w1 = w.map(p => {
      const r = new Int32Array(256);
      for (let j = 0; j < 256; j++) {
        r[j] = highBits(p[j], alpha);
      }
      return r;
    });

    // cTilde = H(mu || encodeW1(w1), cTildeLen)
    const w1Enc = encodeW1(w1, gamma2);
    const cInput = new Uint8Array(mu.length + w1Enc.length);
    cInput.set(mu);
    cInput.set(w1Enc, mu.length);
    const cTilde = h(cInput, cTildeLen);

    // c = sampleInBall(cTilde, tau)
    const c = sampleInBall(cTilde, tau);
    const cNtt = ntt(Int32Array.from(c));

    // z = y + NTT^{-1}(NTT(c) * NTT(s1))
    const cs1 = s1Ntt.map(p => invNtt(Int32Array.from(pointwiseMul(cNtt, p))));
    const z = vecAdd(y.map(p => {
      const r = new Int32Array(256);
      for (let j = 0; j < 256; j++) {
        r[j] = modQ(p[j]);
      }
      return r;
    }), cs1);

    // Check ||z||_inf < gamma1 - beta
    if (!checkVecNormBound(z, gamma1 - beta)) {
      kappa += l;
      continue;
    }

    // r0 = lowBits(w - NTT^{-1}(NTT(c) * NTT(s2)))
    const cs2 = s2Ntt.map(p => invNtt(Int32Array.from(pointwiseMul(cNtt, p))));
    const wMinusCs2 = vecSub(w, cs2);

    // Check lowBits norm
    let lowBitsOk = true;
    for (let i = 0; i < k; i++) {
      for (let j = 0; j < 256; j++) {
        const r0 = lowBits(wMinusCs2[i][j], alpha);
        let absR0 = r0;
        if (absR0 < 0) absR0 = -absR0;
        if (absR0 >= gamma2 - beta) {
          lowBitsOk = false;
          break;
        }
      }
      if (!lowBitsOk) break;
    }
    if (!lowBitsOk) {
      kappa += l;
      continue;
    }

    // Compute hints
    const ct0 = t0Ntt.map(p => invNtt(Int32Array.from(pointwiseMul(cNtt, p))));

    // Check ||ct0||_inf
    if (!checkVecNormBound(ct0, gamma2)) {
      kappa += l;
      continue;
    }

    const hints = [];
    let hintCount = 0;
    let hintsOk = true;
    for (let i = 0; i < k; i++) {
      hints[i] = [];
      for (let j = 0; j < 256; j++) {
        const hBit = makeHint(modQ(Q - ct0[i][j]), modQ(wMinusCs2[i][j] + ct0[i][j]), alpha);
        if (hBit) {
          hints[i].push(j);
          hintCount++;
          if (hintCount > omega) {
            hintsOk = false;
            break;
          }
        }
      }
      if (!hintsOk) break;
    }
    if (!hintsOk) {
      kappa += l;
      continue;
    }

    return encodeSig(cTilde, z, hints, params);
  }
}

/**
 * ML-DSA Verification (Algorithm 3 in FIPS 204)
 * @param {Uint8Array} pk - public key
 * @param {Uint8Array} msg - message
 * @param {Uint8Array} sig - signature
 * @param {object} params - parameter set
 * @returns {boolean} true if valid
 */
export function verify(pk, msg, sig, params) {
  const { k, l, tau, beta, gamma1, gamma2, omega, lambda } = params;
  const alpha = 2 * gamma2;

  // Decode public key
  const { rho, t1 } = decodePK(pk, k);

  // Decode signature
  const decoded = decodeSig(sig, params);
  if (!decoded) return false;
  const { cTilde, z, hints } = decoded;

  // Check ||z||_inf < gamma1 - beta
  if (!checkVecNormBound(z, gamma1 - beta)) return false;

  // Check hint count
  let hintCount = 0;
  for (let i = 0; i < k; i++) {
    hintCount += hints[i].length;
  }
  if (hintCount > omega) return false;

  // A = expandA(rho)
  const A = expandA(rho, k, l);

  // tr = H(pk, 64)
  const tr = h(pk, 64);

  // mu = H(tr || msg, 64)
  const muInput = new Uint8Array(tr.length + msg.length);
  muInput.set(tr);
  muInput.set(msg, tr.length);
  const mu = h(muInput, 64);

  // c = sampleInBall(cTilde, tau)
  const c = sampleInBall(cTilde, tau);
  const cNtt = ntt(Int32Array.from(c));

  // Az = NTT^{-1}(A * NTT(z))
  const AzNtt = matVecMul(A, z);

  // ct1*2^d: t1 scaled by 2^d in NTT domain, multiplied by c
  const d = 13;
  const t1Ntt = t1.map(p => {
    const scaled = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      scaled[j] = modQ(p[j] * (1 << d));
    }
    return ntt(scaled);
  });
  const ct1d = t1Ntt.map(p => pointwiseMul(cNtt, p));

  // w' = Az - ct1*2^d (in NTT domain, then invNtt)
  const wPrime = [];
  for (let i = 0; i < k; i++) {
    const poly = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      poly[j] = modQ(AzNtt[i][j] - ct1d[i][j]);
    }
    wPrime.push(invNtt(poly));
  }

  // w1' = useHint(h, w', alpha)
  const w1Prime = [];
  for (let i = 0; i < k; i++) {
    const r = new Int32Array(256);
    // Build a hint array for this polynomial
    const hintSet = new Set(hints[i]);
    for (let j = 0; j < 256; j++) {
      const hBit = hintSet.has(j) ? 1 : 0;
      r[j] = useHint(hBit, wPrime[i][j], alpha);
    }
    w1Prime.push(r);
  }

  // cTilde' = H(mu || encodeW1(w1'), cTildeLen)
  const w1Enc = encodeW1(w1Prime, gamma2);
  const cInput = new Uint8Array(mu.length + w1Enc.length);
  cInput.set(mu);
  cInput.set(w1Enc, mu.length);
  const cTildeLen = lambda / 4;
  const cTildePrime = h(cInput, cTildeLen);

  // Check cTilde == cTilde'
  if (cTilde.length !== cTildePrime.length) return false;
  for (let i = 0; i < cTilde.length; i++) {
    if (cTilde[i] !== cTildePrime[i]) return false;
  }

  return true;
}
