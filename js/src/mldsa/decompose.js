/**
 * Decomposition functions for ML-DSA (FIPS 204)
 * power2Round, decompose, highBits, lowBits, makeHint, useHint
 */

import { Q, modQ } from './field.js';

/**
 * Power2Round: decompose r into (r1, r0) such that r = r1 * 2^d + r0
 * where d = 13 and r0 is in (-2^(d-1), 2^(d-1)].
 * @param {number} r - value in [0, Q)
 * @returns {[number, number]} [r1, r0]
 */
export function power2Round(r) {
  const d = 13;
  const rPlus = modQ(r);
  const r0 = centeredMod(rPlus, 1 << d);
  return [((rPlus - r0) >>> d), r0];
}

/**
 * Centered modular reduction: returns r mod m in range (-m/2, m/2].
 * @param {number} r
 * @param {number} m
 * @returns {number}
 */
function centeredMod(r, m) {
  let r0 = r % m;
  if (r0 < 0) r0 += m;
  if (r0 > (m >>> 1)) r0 -= m;
  return r0;
}

/**
 * Decompose r into (r1, r0) such that r = r1 * alpha + r0
 * with r0 in (-alpha/2, alpha/2] except for corner case.
 * alpha = 2*gamma2.
 * @param {number} r - value in [0, Q)
 * @param {number} alpha - decomposition base (2*gamma2)
 * @returns {[number, number]} [r1, r0]
 */
export function decompose(r, alpha) {
  const rPlus = modQ(r);
  let r0 = centeredMod(rPlus, alpha);
  let r1;
  if (rPlus - r0 === Q - 1) {
    r1 = 0;
    r0 = r0 - 1;
  } else {
    r1 = (rPlus - r0) / alpha;
  }
  return [r1, r0];
}

/**
 * Extract high bits of r with respect to alpha = 2*gamma2.
 * @param {number} r
 * @param {number} alpha
 * @returns {number}
 */
export function highBits(r, alpha) {
  return decompose(r, alpha)[0];
}

/**
 * Extract low bits of r with respect to alpha = 2*gamma2.
 * @param {number} r
 * @param {number} alpha
 * @returns {number}
 */
export function lowBits(r, alpha) {
  return decompose(r, alpha)[1];
}

/**
 * Compute a hint bit: 1 if highBits of z differs from highBits of r.
 * @param {number} z - low part
 * @param {number} r - full value
 * @param {number} alpha
 * @returns {number} 0 or 1
 */
export function makeHint(z, r, alpha) {
  const r1 = highBits(r, alpha);
  const v1 = highBits(modQ(r + z), alpha);
  return r1 !== v1 ? 1 : 0;
}

/**
 * Use a hint to recover the correct high bits.
 * @param {number} hint - 0 or 1
 * @param {number} r - value in [0, Q)
 * @param {number} alpha
 * @returns {number} corrected high bits
 */
export function useHint(hint, r, alpha) {
  const [r1, r0] = decompose(r, alpha);
  if (hint === 0) {
    return r1;
  }
  const m = (Q - 1) / alpha;
  if (r0 > 0) {
    return (r1 + 1) % m;
  } else {
    return (r1 - 1 + m) % m;
  }
}
