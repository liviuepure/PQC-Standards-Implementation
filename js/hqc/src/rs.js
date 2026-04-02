/**
 * Reed-Solomon encoding and decoding over GF(2^8) for HQC.
 *
 * RS(n1, k) with minimum distance d = n1 - k + 1 = 2*delta + 1.
 * Generator polynomial g(x) = prod(x - alpha^i) for i = 1..2*delta.
 * alpha = 2 (primitive element of GF(2^8) with polynomial 0x11D).
 *
 * CRITICAL: Forney's formula includes X_j factor:
 *   error_val = X_j * omega(X_j^{-1}) / sigma'(X_j^{-1})
 */

import { gf256Add, gf256Mul, gf256Inv, gf256Pow, GF_GEN } from './gf256.js';

/**
 * Compute the RS generator polynomial.
 * Returns coefficients [g0, g1, ..., g_{2*delta}] where g_{2*delta} = 1.
 * @param {number} delta
 * @returns {Uint8Array}
 */
export function rsGeneratorPoly(delta) {
  const deg = 2 * delta;
  const g = new Uint8Array(deg + 1);
  g[0] = 1; // g(x) = 1

  // Multiply by (x - alpha^i) for i = 1..2*delta
  for (let i = 1; i <= deg; i++) {
    const alphai = gf256Pow(GF_GEN, i);
    let prev = 0;
    for (let j = 0; j <= deg; j++) {
      const tmp = g[j];
      g[j] = gf256Mul(g[j], alphai) ^ prev;
      prev = tmp;
    }
  }

  return g;
}

/**
 * Systematic RS encoding.
 * Input: msg of length k bytes.
 * Output: codeword of length n1 bytes (parity || msg).
 * @param {Uint8Array} msg
 * @param {import('./params.js').HQCParams} p
 * @returns {Uint8Array}
 */
export function rsEncode(msg, p) {
  const k = p.k;
  const n1 = p.n1;
  const delta = p.delta;
  const g = rsGeneratorPoly(delta);
  const parityLen = 2 * delta;

  // LFSR encoding
  const feedback = new Uint8Array(parityLen);

  for (let i = k - 1; i >= 0; i--) {
    const coeff = gf256Add(msg[i], feedback[parityLen - 1]);
    for (let j = parityLen - 1; j > 0; j--) {
      feedback[j] = gf256Add(feedback[j - 1], gf256Mul(coeff, g[j]));
    }
    feedback[0] = gf256Mul(coeff, g[0]);
  }

  // Codeword = [parity] [message]
  const codeword = new Uint8Array(n1);
  codeword.set(feedback.subarray(0, parityLen));
  codeword.set(msg, parityLen);

  return codeword;
}

/**
 * Berlekamp-Massey algorithm.
 * Returns error locator polynomial sigma[0..delta].
 * @param {Uint8Array} syndromes - syndromes[0] unused, syndromes[1..2*delta]
 * @param {number} delta
 * @returns {Uint8Array}
 */
function berlekampMassey(syndromes, delta) {
  const n = 2 * delta;
  const sigma = new Uint8Array(delta + 2);
  sigma[0] = 1;
  const b = new Uint8Array(delta + 2);
  b[0] = 1;
  let L = 0;
  let m = 1;
  let deltaN = 1; // previous discrepancy

  for (let k = 1; k <= n; k++) {
    // Compute discrepancy d
    let d = syndromes[k];
    for (let i = 1; i <= L; i++) {
      d ^= gf256Mul(sigma[i], syndromes[k - i]);
    }

    if (d === 0) {
      m++;
      continue;
    }

    // t(x) = sigma(x) - (d/deltaN) * x^m * b(x)
    const t = new Uint8Array(delta + 2);
    t.set(sigma);
    const coeff = gf256Mul(d, gf256Inv(deltaN));
    for (let i = 0; i <= delta + 1 - m; i++) {
      if (i + m <= delta + 1) {
        t[i + m] ^= gf256Mul(coeff, b[i]);
      }
    }

    if (2 * L < k) {
      b.set(sigma);
      L = k - L;
      deltaN = d;
      m = 1;
    } else {
      m++;
    }
    sigma.set(t);
  }

  return sigma.subarray(0, delta + 1);
}

/**
 * Decode a received RS codeword.
 * Returns [decodedMessage, success].
 * @param {Uint8Array} received
 * @param {import('./params.js').HQCParams} p
 * @returns {[Uint8Array|null, boolean]}
 */
export function rsDecode(received, p) {
  const n1 = p.n1;
  const k = p.k;
  const delta = p.delta;

  // Working copy
  const r = new Uint8Array(n1);
  r.set(received.subarray(0, n1));

  // Step 1: Compute syndromes S[1..2*delta]
  const syndromes = new Uint8Array(2 * delta + 1);
  let allZero = true;
  for (let i = 1; i <= 2 * delta; i++) {
    const alphai = gf256Pow(GF_GEN, i);
    let s = 0;
    for (let j = n1 - 1; j >= 0; j--) {
      s = gf256Add(gf256Mul(s, alphai), r[j]);
    }
    syndromes[i] = s;
    if (s !== 0) allZero = false;
  }

  if (allZero) {
    const msg = new Uint8Array(k);
    msg.set(r.subarray(2 * delta, 2 * delta + k));
    return [msg, true];
  }

  // Step 2: Berlekamp-Massey
  const sigma = berlekampMassey(syndromes, delta);
  let sigDeg = 0;
  for (let i = delta; i >= 0; i--) {
    if (sigma[i] !== 0) { sigDeg = i; break; }
  }
  if (sigDeg > delta) return [null, false];

  // Step 3: Chien search - find roots of sigma
  const errorPositions = [];
  for (let i = 0; i < n1; i++) {
    const alphaInv = gf256Pow(GF_GEN, 255 - i);
    let val = 0;
    let alphaPow = 1;
    for (let j = 0; j <= sigDeg; j++) {
      val ^= gf256Mul(sigma[j], alphaPow);
      alphaPow = gf256Mul(alphaPow, alphaInv);
    }
    if (val === 0) {
      errorPositions.push(i);
    }
  }

  if (errorPositions.length !== sigDeg) return [null, false];

  // Step 4: Forney's algorithm - compute error values
  // omega(x) = S(x) * sigma(x) mod x^(2*delta+1)
  const omega = new Uint8Array(2 * delta + 1);
  for (let i = 0; i < 2 * delta; i++) {
    for (let j = 0; j <= sigDeg && j <= i; j++) {
      omega[i + 1] ^= gf256Mul(sigma[j], syndromes[i + 1 - j]);
    }
  }

  // sigma'(x) = formal derivative of sigma
  const sigmaPrime = new Uint8Array(delta + 1);
  for (let i = 1; i <= sigDeg; i += 2) {
    sigmaPrime[i - 1] = sigma[i];
  }

  // Correct errors
  for (const pos of errorPositions) {
    const alphaInvI = gf256Inv(gf256Pow(GF_GEN, pos));

    // Evaluate omega(alpha^(-pos))
    let omegaVal = 0;
    let alphaPow = 1;
    for (let j = 0; j <= 2 * delta; j++) {
      omegaVal ^= gf256Mul(omega[j], alphaPow);
      alphaPow = gf256Mul(alphaPow, alphaInvI);
    }

    // Evaluate sigma'(alpha^(-pos))
    let sigPrimeVal = 0;
    alphaPow = 1;
    for (let j = 0; j < sigmaPrime.length; j++) {
      sigPrimeVal ^= gf256Mul(sigmaPrime[j], alphaPow);
      alphaPow = gf256Mul(alphaPow, alphaInvI);
    }

    if (sigPrimeVal === 0) return [null, false];

    // Forney: e_j = X_j * omega(X_j^{-1}) / sigma'(X_j^{-1})
    const xj = gf256Pow(GF_GEN, pos);
    const errorVal = gf256Mul(gf256Mul(xj, omegaVal), gf256Inv(sigPrimeVal));
    r[pos] ^= errorVal;
  }

  // Extract message
  const msg = new Uint8Array(k);
  msg.set(r.subarray(2 * delta, 2 * delta + k));
  return [msg, true];
}
