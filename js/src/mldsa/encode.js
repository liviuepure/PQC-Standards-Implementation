/**
 * Encoding/decoding functions for ML-DSA (FIPS 204)
 * bitPack/bitUnpack, encodePK/decodePK, encodeSK/decodeSK,
 * encodeSig/decodeSig, encodeW1
 */

import { Q, modQ } from './field.js';

/**
 * Pack polynomial coefficients into bytes.
 * Each coefficient is in [a, b] mapped to [0, b-a], packed with bitLen bits.
 * @param {Int32Array} poly - polynomial
 * @param {number} bitLen - bits per coefficient
 * @param {number} offset - subtracted from each coefficient to normalize to [0, ...)
 * @returns {Uint8Array}
 */
export function bitPack(poly, bitLen, offset = 0) {
  const totalBits = 256 * bitLen;
  const bytes = new Uint8Array(Math.ceil(totalBits / 8));
  let bitPos = 0;
  for (let i = 0; i < 256; i++) {
    let val = poly[i] - offset;
    for (let b = 0; b < bitLen; b++) {
      if (val & 1) {
        bytes[bitPos >>> 3] |= (1 << (bitPos & 7));
      }
      val >>>= 1;
      bitPos++;
    }
  }
  return bytes;
}

/**
 * Unpack bytes into polynomial coefficients.
 * @param {Uint8Array} bytes - packed bytes
 * @param {number} bitLen - bits per coefficient
 * @param {number} offset - added back to each coefficient
 * @param {number} [startByte=0] - byte offset in the input
 * @returns {Int32Array}
 */
export function bitUnpack(bytes, bitLen, offset = 0, startByte = 0) {
  const poly = new Int32Array(256);
  let bitPos = startByte * 8;
  const mask = (1 << bitLen) - 1;
  for (let i = 0; i < 256; i++) {
    let val = 0;
    for (let b = 0; b < bitLen; b++) {
      if (bytes[bitPos >>> 3] & (1 << (bitPos & 7))) {
        val |= (1 << b);
      }
      bitPos++;
    }
    poly[i] = val + offset;
  }
  return poly;
}

/**
 * Encode public key: pk = rho || t1_encoded
 * t1 coefficients are in [0, 2^10 - 1], each packed with 10 bits.
 * @param {Uint8Array} rho - 32-byte seed
 * @param {Int32Array[]} t1 - k polynomials
 * @returns {Uint8Array}
 */
export function encodePK(rho, t1) {
  const k = t1.length;
  // Each polynomial: 256 * 10 / 8 = 320 bytes
  const pk = new Uint8Array(32 + k * 320);
  pk.set(rho);
  for (let i = 0; i < k; i++) {
    const packed = bitPack(t1[i], 10);
    pk.set(packed, 32 + i * 320);
  }
  return pk;
}

/**
 * Decode public key.
 * @param {Uint8Array} pk - encoded public key
 * @param {number} k - number of polynomials
 * @returns {{ rho: Uint8Array, t1: Int32Array[] }}
 */
export function decodePK(pk, k) {
  const rho = pk.slice(0, 32);
  const t1 = [];
  for (let i = 0; i < k; i++) {
    const start = 32 + i * 320;
    t1.push(bitUnpack(pk, 10, 0, start));
  }
  return { rho, t1 };
}

/**
 * Encode secret key: sk = rho || K || tr || s1_encoded || s2_encoded || t0_encoded
 * s1, s2 coefficients in [-eta, eta] packed appropriately
 * t0 coefficients in [-(2^(d-1)-1), 2^(d-1)] where d=13
 * @param {Uint8Array} rho - 32 bytes
 * @param {Uint8Array} K - 32 bytes
 * @param {Uint8Array} tr - 64 bytes
 * @param {Int32Array[]} s1 - l polynomials
 * @param {Int32Array[]} s2 - k polynomials
 * @param {Int32Array[]} t0 - k polynomials
 * @param {number} eta
 * @returns {Uint8Array}
 */
export function encodeSK(rho, K, tr, s1, s2, t0, eta) {
  const l = s1.length;
  const k = s2.length;

  // Bits per eta coefficient
  let etaBits;
  if (eta === 2) etaBits = 3;
  else if (eta === 4) etaBits = 4;

  const etaPolyBytes = Math.ceil(256 * etaBits / 8);
  // t0: d=13 bits per coeff => 256*13/8 = 416 bytes per poly
  const t0PolyBytes = 416;

  const totalSize = 32 + 32 + 64 + l * etaPolyBytes + k * etaPolyBytes + k * t0PolyBytes;
  const sk = new Uint8Array(totalSize);
  let offset = 0;

  sk.set(rho, offset); offset += 32;
  sk.set(K, offset); offset += 32;
  sk.set(tr, offset); offset += 64;

  // Encode s1 (coefficients in [-eta, eta], store as eta - coeff to get [0, 2*eta])
  for (let i = 0; i < l; i++) {
    const poly = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      poly[j] = eta - s1[i][j]; // map [-eta, eta] -> [0, 2*eta]
    }
    const packed = bitPack(poly, etaBits);
    sk.set(packed, offset);
    offset += etaPolyBytes;
  }

  // Encode s2
  for (let i = 0; i < k; i++) {
    const poly = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      poly[j] = eta - s2[i][j];
    }
    const packed = bitPack(poly, etaBits);
    sk.set(packed, offset);
    offset += etaPolyBytes;
  }

  // Encode t0 (coefficients in [-(2^12 - 1), 2^12] ~ [-4095, 4096])
  // Store as 2^(d-1) - t0[j] to get [0, 2^d - 1] = [0, 8191]
  const halfD = 1 << 12; // 4096
  for (let i = 0; i < k; i++) {
    const poly = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      poly[j] = halfD - t0[i][j];
    }
    const packed = bitPack(poly, 13);
    sk.set(packed, offset);
    offset += t0PolyBytes;
  }

  return sk;
}

/**
 * Decode secret key.
 * @param {Uint8Array} sk
 * @param {number} k
 * @param {number} l
 * @param {number} eta
 * @returns {{ rho: Uint8Array, K: Uint8Array, tr: Uint8Array, s1: Int32Array[], s2: Int32Array[], t0: Int32Array[] }}
 */
export function decodeSK(sk, k, l, eta) {
  let etaBits;
  if (eta === 2) etaBits = 3;
  else if (eta === 4) etaBits = 4;

  const etaPolyBytes = Math.ceil(256 * etaBits / 8);
  const t0PolyBytes = 416;

  let offset = 0;
  const rho = sk.slice(offset, offset + 32); offset += 32;
  const K = sk.slice(offset, offset + 32); offset += 32;
  const tr = sk.slice(offset, offset + 64); offset += 64;

  const s1 = [];
  for (let i = 0; i < l; i++) {
    const raw = bitUnpack(sk, etaBits, 0, offset);
    const poly = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      poly[j] = eta - raw[j];
    }
    s1.push(poly);
    offset += etaPolyBytes;
  }

  const s2 = [];
  for (let i = 0; i < k; i++) {
    const raw = bitUnpack(sk, etaBits, 0, offset);
    const poly = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      poly[j] = eta - raw[j];
    }
    s2.push(poly);
    offset += etaPolyBytes;
  }

  const t0 = [];
  const halfD = 1 << 12;
  for (let i = 0; i < k; i++) {
    const raw = bitUnpack(sk, 13, 0, offset);
    const poly = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      poly[j] = halfD - raw[j];
    }
    t0.push(poly);
    offset += t0PolyBytes;
  }

  return { rho, K, tr, s1, s2, t0 };
}

/**
 * Encode w1 (high bits). The number of bits depends on gamma2:
 * gamma2 = 95232 => (Q-1)/(2*gamma2) = 44 => need 6 bits
 * gamma2 = 261888 => (Q-1)/(2*gamma2) = 16 => need 4 bits
 * @param {Int32Array[]} w1 - k polynomials of high bits
 * @param {number} gamma2
 * @returns {Uint8Array}
 */
export function encodeW1(w1, gamma2) {
  const k = w1.length;
  let bitLen;
  if (gamma2 === 95232) {
    bitLen = 6;
  } else if (gamma2 === 261888) {
    bitLen = 4;
  }
  const polyBytes = Math.ceil(256 * bitLen / 8);
  const out = new Uint8Array(k * polyBytes);
  for (let i = 0; i < k; i++) {
    const packed = bitPack(w1[i], bitLen);
    out.set(packed, i * polyBytes);
  }
  return out;
}

/**
 * Encode signature: sig = cTilde || z_encoded || h_encoded
 * z coefficients in [-(gamma1-1), gamma1], packed with gamma1 bits
 * h is encoded as a hint bitstring (omega + k bytes)
 * @param {Uint8Array} cTilde - challenge hash (lambda/4 bytes)
 * @param {Int32Array[]} z - l polynomials
 * @param {Int32Array[][]} hints - k arrays of hint positions
 * @param {object} params
 * @returns {Uint8Array}
 */
export function encodeSig(cTilde, z, hints, params) {
  const { gamma1, omega, k, l } = params;

  // z encoding: gamma1 - z[j] maps to [0, 2*gamma1 - 1]
  let zBitLen;
  if (gamma1 === (1 << 17)) zBitLen = 18;
  else if (gamma1 === (1 << 19)) zBitLen = 20;

  const zPolyBytes = Math.ceil(256 * zBitLen / 8);
  const hintBytes = omega + k;
  const sigSize = cTilde.length + l * zPolyBytes + hintBytes;
  const sig = new Uint8Array(sigSize);
  let offset = 0;

  // cTilde
  sig.set(cTilde, offset);
  offset += cTilde.length;

  // z: pack as gamma1 - z[j] (z must be centered to signed form first)
  for (let i = 0; i < l; i++) {
    const poly = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      let zj = z[i][j];
      // Center from [0, Q) to [-(Q-1)/2, (Q-1)/2]
      if (zj > (Q >>> 1)) zj -= Q;
      poly[j] = gamma1 - zj;
    }
    const packed = bitPack(poly, zBitLen);
    sig.set(packed, offset);
    offset += zPolyBytes;
  }

  // Hints encoding: FIPS 204 format
  // omega + k bytes total
  const hintBuf = new Uint8Array(hintBytes);
  let idx = 0;
  for (let i = 0; i < k; i++) {
    for (let j = 0; j < hints[i].length; j++) {
      hintBuf[idx++] = hints[i][j];
    }
    hintBuf[omega + i] = idx;
  }
  sig.set(hintBuf, offset);

  return sig;
}

/**
 * Decode signature.
 * @param {Uint8Array} sig
 * @param {object} params
 * @returns {{ cTilde: Uint8Array, z: Int32Array[], hints: Int32Array[][] } | null}
 */
export function decodeSig(sig, params) {
  const { gamma1, omega, k, l, lambda } = params;
  const cTildeLen = lambda / 4;

  let zBitLen;
  if (gamma1 === (1 << 17)) zBitLen = 18;
  else if (gamma1 === (1 << 19)) zBitLen = 20;

  const zPolyBytes = Math.ceil(256 * zBitLen / 8);
  let offset = 0;

  const cTilde = sig.slice(offset, offset + cTildeLen);
  offset += cTildeLen;

  const z = [];
  for (let i = 0; i < l; i++) {
    const raw = bitUnpack(sig, zBitLen, 0, offset);
    const poly = new Int32Array(256);
    for (let j = 0; j < 256; j++) {
      poly[j] = gamma1 - raw[j];
    }
    z.push(poly);
    offset += zPolyBytes;
  }

  // Decode hints
  const hintStart = offset;
  const hints = [];
  let idx = 0;
  for (let i = 0; i < k; i++) {
    hints[i] = [];
    const end = sig[hintStart + omega + i];
    if (end < idx || end > omega) return null;
    while (idx < end) {
      hints[i].push(sig[hintStart + idx]);
      idx++;
    }
  }

  return { cTilde, z, hints };
}
