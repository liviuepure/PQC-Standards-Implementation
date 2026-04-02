/**
 * GF(2) polynomial arithmetic using Uint32Array word packing.
 *
 * Polynomials over GF(2) are packed into Uint32Array words (32 bits each).
 * Arithmetic is in GF(2)[x] / (x^n - 1).
 */

const WORD_BITS = 32;

/**
 * Allocate a zero vector with enough words for nBits.
 * @param {number} nBits
 * @returns {Uint32Array}
 */
export function vectAlloc(nBits) {
  return new Uint32Array(Math.ceil(nBits / WORD_BITS));
}

/**
 * Compute out = a XOR b (polynomial addition in GF(2)).
 * @param {Uint32Array} a
 * @param {Uint32Array} b
 * @returns {Uint32Array}
 */
export function vectAdd(a, b) {
  const n = Math.max(a.length, b.length);
  const out = new Uint32Array(n);
  for (let i = 0; i < a.length; i++) out[i] = a[i];
  for (let i = 0; i < b.length; i++) out[i] ^= b[i];
  return out;
}

/**
 * Set bit at position pos in vector v.
 * @param {Uint32Array} v
 * @param {number} pos
 */
export function vectSetBit(v, pos) {
  v[pos >>> 5] |= 1 << (pos & 31);
}

/**
 * Get bit at position pos in vector v.
 * @param {Uint32Array} v
 * @param {number} pos
 * @returns {number} 0 or 1
 */
export function vectGetBit(v, pos) {
  return (v[pos >>> 5] >>> (pos & 31)) & 1;
}

/**
 * Hamming weight of a GF(2) vector.
 * @param {Uint32Array} v
 * @returns {number}
 */
export function vectWeight(v) {
  let w = 0;
  for (let i = 0; i < v.length; i++) {
    let x = v[i];
    // Kernighan's bit counting
    while (x) {
      x &= x - 1;
      w++;
    }
  }
  return w;
}

/**
 * Convert Uint32Array to bytes (little-endian).
 * @param {Uint32Array} v
 * @param {number} nBytes
 * @returns {Uint8Array}
 */
export function vectToBytes(v, nBytes) {
  const out = new Uint8Array(nBytes);
  for (let i = 0; i < v.length && i * 4 < nBytes; i++) {
    const remaining = nBytes - i * 4;
    const word = v[i];
    if (remaining >= 4) {
      out[i * 4] = word & 0xFF;
      out[i * 4 + 1] = (word >>> 8) & 0xFF;
      out[i * 4 + 2] = (word >>> 16) & 0xFF;
      out[i * 4 + 3] = (word >>> 24) & 0xFF;
    } else {
      for (let b = 0; b < remaining; b++) {
        out[i * 4 + b] = (word >>> (b * 8)) & 0xFF;
      }
    }
  }
  return out;
}

/**
 * Convert bytes to Uint32Array (little-endian).
 * @param {Uint8Array} data
 * @param {number} nWords
 * @returns {Uint32Array}
 */
export function vectFromBytes(data, nWords) {
  const v = new Uint32Array(nWords);
  for (let i = 0; i < nWords; i++) {
    const start = i * 4;
    if (start >= data.length) break;
    let word = 0;
    const end = Math.min(start + 4, data.length);
    for (let b = start; b < end; b++) {
      word |= data[b] << ((b - start) * 8);
    }
    v[i] = word >>> 0;
  }
  return v;
}

/**
 * Resize vector to exactly nBits, masking the last word.
 * @param {Uint32Array} v
 * @param {number} nBits
 * @returns {Uint32Array}
 */
export function vectResize(v, nBits) {
  const nWords = Math.ceil(nBits / WORD_BITS);
  const out = new Uint32Array(nWords);
  const copyLen = Math.min(v.length, nWords);
  for (let i = 0; i < copyLen; i++) out[i] = v[i];
  const rem = nBits & 31;
  if (rem !== 0 && nWords > 0) {
    out[nWords - 1] &= (1 << rem) - 1;
  }
  return out;
}

/**
 * Constant-time equality check. Returns 1 if equal, 0 otherwise.
 * @param {Uint32Array} a
 * @param {Uint32Array} b
 * @returns {number}
 */
export function vectEqual(a, b) {
  let diff = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= a[i] ^ b[i];
  for (let i = n; i < a.length; i++) diff |= a[i];
  for (let i = n; i < b.length; i++) diff |= b[i];
  // Collapse diff to a single bit
  diff |= diff >>> 16;
  diff |= diff >>> 8;
  diff |= diff >>> 4;
  diff |= diff >>> 2;
  diff |= diff >>> 1;
  return 1 - (diff & 1);
}

/**
 * Carryless multiplication of two 32-bit words.
 * Returns [lo, hi] such that a * b = hi<<32 | lo in GF(2).
 * @param {number} a
 * @param {number} b
 * @returns {[number, number]}
 */
function baseMul(a, b) {
  // Use BigInt for the carryless multiply to avoid precision issues
  let lo = 0n;
  const ab = BigInt(a >>> 0);
  const bb = BigInt(b >>> 0);

  for (let i = 0; i < 32; i++) {
    if ((ab >> BigInt(i)) & 1n) {
      lo ^= bb << BigInt(i);
    }
  }

  return [Number(lo & 0xFFFFFFFFn), Number((lo >> 32n) & 0xFFFFFFFFn)];
}

/**
 * Schoolbook polynomial multiplication of two GF(2) polynomials.
 * @param {Uint32Array} a - size sizeA words
 * @param {number} sizeA
 * @param {Uint32Array} b - size sizeB words
 * @param {number} sizeB
 * @returns {Uint32Array} - size sizeA+sizeB words
 */
function schoolbookMul(a, sizeA, b, sizeB) {
  const out = new Uint32Array(sizeA + sizeB);
  for (let i = 0; i < sizeA; i++) {
    if (a[i] === 0) continue;
    for (let j = 0; j < sizeB; j++) {
      if (b[j] === 0) continue;
      const [lo, hi] = baseMul(a[i], b[j]);
      out[i + j] ^= lo;
      out[i + j + 1] ^= hi;
    }
  }
  return out;
}

/**
 * Compute out = a * b mod (x^n - 1) in GF(2)[x].
 * @param {Uint32Array} a
 * @param {Uint32Array} b
 * @param {number} n
 * @returns {Uint32Array}
 */
export function vectMul(a, b, n) {
  const nWords = Math.ceil(n / WORD_BITS);

  // Pad and mask inputs
  const aPad = new Uint32Array(nWords);
  const bPad = new Uint32Array(nWords);
  const copyA = Math.min(a.length, nWords);
  const copyB = Math.min(b.length, nWords);
  for (let i = 0; i < copyA; i++) aPad[i] = a[i];
  for (let i = 0; i < copyB; i++) bPad[i] = b[i];

  const rem = n & 31;
  if (rem !== 0) {
    aPad[nWords - 1] &= (1 << rem) - 1;
    bPad[nWords - 1] &= (1 << rem) - 1;
  }

  // Full product
  const prod = schoolbookMul(aPad, nWords, bPad, nWords);

  // Reduce mod (x^n - 1)
  const out = new Uint32Array(nWords);
  for (let i = 0; i < nWords; i++) out[i] = prod[i];

  const wordOff = (n / WORD_BITS) | 0;

  if (rem === 0) {
    for (let i = 0; i < nWords; i++) {
      if (wordOff + i < 2 * nWords) {
        out[i] ^= prod[wordOff + i];
      }
    }
  } else {
    for (let i = 0; i < nWords; i++) {
      const idx = wordOff + i;
      if (idx < 2 * nWords) {
        out[i] ^= prod[idx] >>> rem;
      }
      if (idx + 1 < 2 * nWords) {
        out[i] ^= prod[idx + 1] << (WORD_BITS - rem);
      }
    }
  }

  // Mask last word
  if (rem !== 0) {
    out[nWords - 1] &= (1 << rem) - 1;
  }

  return out;
}

/**
 * Extract nBits bits from src starting at bitOffset.
 * @param {Uint32Array} src
 * @param {number} bitOffset
 * @param {number} nBits
 * @returns {Uint32Array}
 */
export function extractBits(src, bitOffset, nBits) {
  const nWords = Math.ceil(nBits / WORD_BITS);
  const out = new Uint32Array(nWords);

  const srcWord = (bitOffset / WORD_BITS) | 0;
  const srcBit = bitOffset & 31;

  if (srcBit === 0) {
    for (let i = 0; i < nWords && srcWord + i < src.length; i++) {
      out[i] = src[srcWord + i];
    }
  } else {
    for (let i = 0; i < nWords; i++) {
      const idx = srcWord + i;
      if (idx < src.length) {
        out[i] = src[idx] >>> srcBit;
      }
      if (idx + 1 < src.length) {
        out[i] |= src[idx + 1] << (WORD_BITS - srcBit);
      }
    }
  }

  // Mask last word
  const remBits = nBits & 31;
  if (remBits !== 0 && nWords > 0) {
    out[nWords - 1] &= (1 << remBits) - 1;
  }

  return out;
}
