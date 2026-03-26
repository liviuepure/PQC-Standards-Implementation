/**
 * Hash and sampling functions for ML-DSA (FIPS 204)
 * Uses Node.js crypto for SHAKE-128 and SHAKE-256
 */

import { createHash } from 'node:crypto';
import { Q, modQ } from './field.js';

/**
 * SHAKE-256 hash.
 * @param {Uint8Array} data - input data
 * @param {number} outLen - output length in bytes
 * @returns {Uint8Array}
 */
export function h(data, outLen) {
  const hasher = createHash('shake256', { outputLength: outLen });
  hasher.update(data);
  return new Uint8Array(hasher.digest());
}

/**
 * SHAKE-128 XOF.
 * @param {Uint8Array} data - input data
 * @param {number} outLen - output length in bytes
 * @returns {Uint8Array}
 */
function shake128(data, outLen) {
  const hasher = createHash('shake128', { outputLength: outLen });
  hasher.update(data);
  return new Uint8Array(hasher.digest());
}

/**
 * Expand the matrix A from seed rho using SHAKE-128.
 * Each element A[i][j] is a polynomial of 256 coefficients in NTT domain.
 * Rejection sampling: read 3 bytes, form 24-bit value, accept if < Q.
 * @param {Uint8Array} rho - 32-byte seed
 * @param {number} k - rows
 * @param {number} l - columns
 * @returns {Int32Array[][]} k x l matrix of polynomials
 */
export function expandA(rho, k, l) {
  const A = [];
  for (let i = 0; i < k; i++) {
    A[i] = [];
    for (let j = 0; j < l; j++) {
      A[i][j] = rejectionSampleA(rho, i, j);
    }
  }
  return A;
}

/**
 * Rejection sample a single polynomial for matrix A.
 */
function rejectionSampleA(rho, i, j) {
  // Domain separator: rho || intToLe16(j) || intToLe16(i)
  // FIPS 204 uses rho || j (low byte) || i (low byte) for the two-byte nonce
  // but actually the spec uses: rho || IntegerToBytes(s, 1) || IntegerToBytes(r, 1)
  // where s = column index (j), r = row index (i)
  const input = new Uint8Array(rho.length + 2);
  input.set(rho);
  input[rho.length] = j & 0xFF;
  input[rho.length + 1] = i & 0xFF;

  // We need exactly 256 coefficients; request enough bytes
  // Each coefficient needs ~3 bytes on average with ~Q/2^24 rejection rate
  const poly = new Int32Array(256);
  let coeffIdx = 0;
  let streamLen = 840; // Start with enough for ~256 samples

  while (coeffIdx < 256) {
    const stream = shake128(input, streamLen);
    let pos = 0;
    while (coeffIdx < 256 && pos + 2 < stream.length) {
      const b0 = stream[pos++];
      const b1 = stream[pos++];
      const b2 = stream[pos++];
      const val = b0 | (b1 << 8) | ((b2 & 0x7F) << 16);
      if (val < Q) {
        poly[coeffIdx++] = val;
      }
    }
    if (coeffIdx < 256) {
      streamLen += 840;
    }
  }
  return poly;
}

/**
 * Expand secret vectors s1, s2 from rhoPrime using SHAKE-256.
 * Coefficients are in [-eta, eta].
 * @param {Uint8Array} rhoPrime - 64-byte seed
 * @param {number} eta - bound parameter
 * @param {number} k - number of polynomials in s2
 * @param {number} l - number of polynomials in s1
 * @returns {{ s1: Int32Array[], s2: Int32Array[] }}
 */
export function expandS(rhoPrime, eta, k, l) {
  const s1 = [];
  const s2 = [];
  for (let r = 0; r < l; r++) {
    s1.push(rejectionSampleEta(rhoPrime, eta, r));
  }
  for (let r = 0; r < k; r++) {
    s2.push(rejectionSampleEta(rhoPrime, eta, l + r));
  }
  return { s1, s2 };
}

/**
 * Rejection sample a polynomial with coefficients in [-eta, eta].
 */
function rejectionSampleEta(seed, eta, nonce) {
  const input = new Uint8Array(seed.length + 2);
  input.set(seed);
  input[seed.length] = nonce & 0xFF;
  input[seed.length + 1] = (nonce >>> 8) & 0xFF;

  const poly = new Int32Array(256);
  let coeffIdx = 0;
  let streamLen = 272; // enough for most cases

  while (coeffIdx < 256) {
    const stream = h(input, streamLen);
    let pos = 0;

    if (eta === 2) {
      // Each byte gives 2 samples: low nibble and high nibble
      while (coeffIdx < 256 && pos < stream.length) {
        const b = stream[pos++];
        const t0 = b & 0x0F;
        const t1 = (b >>> 4) & 0x0F;
        if (t0 < 15) {
          poly[coeffIdx++] = 2 - (t0 % 5);
        }
        if (coeffIdx < 256 && t1 < 15) {
          poly[coeffIdx++] = 2 - (t1 % 5);
        }
      }
    } else if (eta === 4) {
      // Each byte gives 2 samples
      while (coeffIdx < 256 && pos < stream.length) {
        const b = stream[pos++];
        const t0 = b & 0x0F;
        const t1 = (b >>> 4) & 0x0F;
        if (t0 < 9) {
          poly[coeffIdx++] = 4 - t0;
        }
        if (coeffIdx < 256 && t1 < 9) {
          poly[coeffIdx++] = 4 - t1;
        }
      }
    }

    if (coeffIdx < 256) {
      streamLen += 272;
    }
  }
  return poly;
}

/**
 * Expand the mask vector y from rhoPrime using SHAKE-256.
 * Coefficients are in (-gamma1, gamma1].
 * @param {Uint8Array} rhoPP - seed (typically rho'' or rhoPrime)
 * @param {number} gamma1 - bound
 * @param {number} l - number of polynomials
 * @param {number} kappa - counter (nonce base)
 * @returns {Int32Array[]}
 */
export function expandMask(rhoPP, gamma1, l, kappa) {
  const y = [];
  for (let i = 0; i < l; i++) {
    const nonce = kappa + i;
    const input = new Uint8Array(rhoPP.length + 2);
    input.set(rhoPP);
    input[rhoPP.length] = nonce & 0xFF;
    input[rhoPP.length + 1] = (nonce >>> 8) & 0xFF;

    const poly = new Int32Array(256);

    if (gamma1 === (1 << 17)) {
      // 18 bits per coefficient => 256 * 18 / 8 = 576 bytes
      const stream = h(input, 576);
      for (let j = 0; j < 256; j++) {
        const bitOffset = j * 18;
        const byteIdx = bitOffset >>> 3;
        const bitIdx = bitOffset & 7;
        let val = (stream[byteIdx] >>> bitIdx)
          | (stream[byteIdx + 1] << (8 - bitIdx))
          | (stream[byteIdx + 2] << (16 - bitIdx));
        val &= 0x3FFFF; // 18 bits
        poly[j] = gamma1 - val;
      }
    } else if (gamma1 === (1 << 19)) {
      // 20 bits per coefficient => 256 * 20 / 8 = 640 bytes
      const stream = h(input, 640);
      for (let j = 0; j < 256; j++) {
        const bitOffset = j * 20;
        const byteIdx = bitOffset >>> 3;
        const bitIdx = bitOffset & 7;
        let val = (stream[byteIdx] >>> bitIdx)
          | (stream[byteIdx + 1] << (8 - bitIdx))
          | (stream[byteIdx + 2] << (16 - bitIdx));
        if (bitIdx > 4) {
          val |= (stream[byteIdx + 3] << (24 - bitIdx));
        }
        val &= 0xFFFFF; // 20 bits
        poly[j] = gamma1 - val;
      }
    }

    y.push(poly);
  }
  return y;
}

/**
 * Sample a polynomial c in the ball: exactly tau non-zero coefficients,
 * each +/-1, using Fisher-Yates with SHAKE-256.
 * @param {Uint8Array} cTilde - seed (lambda/4 bytes)
 * @param {number} tau - number of non-zero coefficients
 * @returns {Int32Array} polynomial with tau entries in {-1, +1}, rest 0
 */
export function sampleInBall(cTilde, tau) {
  // We need 8 bytes for signs (64 bits), plus bytes for the Fisher-Yates indices.
  // Generous buffer: tau indices with rejection sampling may need extra bytes.
  const stream = h(cTilde, 8 + 512);
  const c = new Int32Array(256);

  // First 8 bytes encode sign bits (little-endian 64-bit integer)
  let signs = BigInt(0);
  for (let i = 7; i >= 0; i--) {
    signs = (signs << BigInt(8)) | BigInt(stream[i]);
  }

  let pos = 8;
  for (let i = 256 - tau; i < 256; i++) {
    // Rejection sample: read bytes until we get j <= i
    let j = stream[pos++];
    while (j > i) {
      j = stream[pos++];
    }

    c[i] = c[j];
    c[j] = (signs & BigInt(1)) ? -1 : 1;
    signs >>= BigInt(1);
  }

  return c;
}
