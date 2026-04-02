/**
 * GF(2^8) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
 *
 * Generator (primitive element): alpha = 2 (x).
 * Multiplicative order: 255.
 */

const GF_POLY = 0x11D;
const GF_GEN = 2;
const GF_MUL_ORDER = 255;

/** Exp table: gf256Exp[i] = alpha^i, doubled for easy mod-255. */
const gf256Exp = new Uint8Array(512);

/** Log table: gf256Log[x] = i such that alpha^i = x. */
const gf256Log = new Uint8Array(256);

// Initialize tables
(function initGF256Tables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    gf256Exp[i] = x;
    gf256Exp[i + 255] = x; // wrap-around
    gf256Log[x] = i;
    x <<= 1;
    if (x >= 256) x ^= GF_POLY;
  }
  gf256Log[0] = 0; // convention (never used for valid math)
  gf256Exp[510] = gf256Exp[0]; // ensure full wrap
})();

/**
 * Addition in GF(2^8): XOR.
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
export function gf256Add(a, b) {
  return a ^ b;
}

/**
 * Multiplication in GF(2^8) via log/exp tables.
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
export function gf256Mul(a, b) {
  if (a === 0 || b === 0) return 0;
  return gf256Exp[gf256Log[a] + gf256Log[b]];
}

/**
 * Multiplicative inverse in GF(2^8). Returns 0 if a === 0.
 * @param {number} a
 * @returns {number}
 */
export function gf256Inv(a) {
  if (a === 0) return 0;
  return gf256Exp[255 - gf256Log[a]];
}

/**
 * a^n in GF(2^8).
 * @param {number} a
 * @param {number} n
 * @returns {number}
 */
export function gf256Pow(a, n) {
  if (a === 0) return n === 0 ? 1 : 0;
  let logA = gf256Log[a];
  let logResult = (logA * n) % 255;
  if (logResult < 0) logResult += 255;
  return gf256Exp[logResult];
}

/**
 * Division a / b in GF(2^8). Throws if b === 0.
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
export function gf256Div(a, b) {
  if (b === 0) throw new Error('hqc: gf256 division by zero');
  if (a === 0) return 0;
  let logDiff = gf256Log[a] - gf256Log[b];
  if (logDiff < 0) logDiff += 255;
  return gf256Exp[logDiff];
}

export { GF_GEN, GF_MUL_ORDER, GF_POLY };
