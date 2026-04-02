/**
 * Reed-Muller code RM(1, 7) for HQC.
 *
 * RM(1, 7) encodes 8 bits (1 byte) into 128 bits.
 * The encoding uses the generator matrix of RM(1, 7).
 *
 * For HQC, the RM codeword is duplicated (multiplicity times)
 * to form an n2-bit codeword for additional error correction.
 */

const RM_BASE_LEN = 128;

/**
 * Encode a single byte into a 128-bit RM(1,7) codeword.
 * Returns [lo32_0, lo32_1, lo32_2, lo32_3] as four 32-bit words (128 bits).
 * @param {number} msg - byte to encode (0-255)
 * @returns {Uint32Array} - 4 words representing 128 bits
 */
export function rmEncodeBase(msg) {
  // Generator matrix rows for RM(1,7) as 128-bit patterns:
  // We work with 4 x 32-bit words.
  //
  // Row 0 (constant): all-ones
  // Row 1: 0xAAAAAAAA repeated
  // Row 2: 0xCCCCCCCC repeated
  // Row 3: 0xF0F0F0F0 repeated
  // Row 4: 0xFF00FF00 repeated
  // Row 5: 0xFFFF0000 repeated
  // Row 6: (0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF)
  // Row 7: (0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF)

  const out = new Uint32Array(4);

  const expand = (bit) => -((msg >>> bit) & 1); // all-0 or all-1

  // Bit 0: constant row (all-ones if set)
  const m0 = expand(0);
  out[0] ^= m0; out[1] ^= m0; out[2] ^= m0; out[3] ^= m0;

  // Bit 1: 0xAAAAAAAA
  const m1 = expand(1) & 0xAAAAAAAA;
  out[0] ^= m1; out[1] ^= m1; out[2] ^= m1; out[3] ^= m1;

  // Bit 2: 0xCCCCCCCC
  const m2 = expand(2) & 0xCCCCCCCC;
  out[0] ^= m2; out[1] ^= m2; out[2] ^= m2; out[3] ^= m2;

  // Bit 3: 0xF0F0F0F0
  const m3 = expand(3) & 0xF0F0F0F0;
  out[0] ^= m3; out[1] ^= m3; out[2] ^= m3; out[3] ^= m3;

  // Bit 4: 0xFF00FF00
  const m4 = expand(4) & 0xFF00FF00;
  out[0] ^= m4; out[1] ^= m4; out[2] ^= m4; out[3] ^= m4;

  // Bit 5: 0xFFFF0000
  const m5 = expand(5) & 0xFFFF0000;
  out[0] ^= m5; out[1] ^= m5; out[2] ^= m5; out[3] ^= m5;

  // Bit 6: (0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF)
  const m6 = expand(6);
  out[1] ^= m6; out[3] ^= m6;

  // Bit 7: (0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF)
  const m7 = expand(7);
  out[2] ^= m7; out[3] ^= m7;

  return out;
}

/**
 * Encode a byte into dst starting at bitOffset, with repetition.
 * @param {Uint32Array} dst
 * @param {number} msg
 * @param {number} bitOffset
 * @param {number} multiplicity
 */
export function rmEncodeInto(dst, msg, bitOffset, multiplicity) {
  const base = rmEncodeBase(msg);

  let bitPos = bitOffset;
  for (let rep = 0; rep < multiplicity; rep++) {
    for (let w = 0; w < 4; w++) {
      const word = base[w];
      const dstWord = bitPos >>> 5;
      const dstBit = bitPos & 31;

      if (dstBit === 0 && dstWord < dst.length) {
        // Aligned write
        dst[dstWord] ^= word;
        bitPos += 32;
      } else {
        // Unaligned: write bit by bit
        for (let bit = 0; bit < 32; bit++) {
          if (word & (1 << bit)) {
            const idx = bitPos >>> 5;
            const off = bitPos & 31;
            if (idx < dst.length) {
              dst[idx] ^= 1 << off;
            }
          }
          bitPos++;
        }
      }
    }
  }
}

/**
 * Decode an n2-bit received codeword (with duplicated RM(1,7)) to a single byte
 * using the Walsh-Hadamard transform.
 * @param {Uint32Array} src
 * @param {number} n2
 * @param {number} multiplicity
 * @returns {number} decoded byte
 */
export function rmDecode(src, n2, multiplicity) {
  // Step 1: accumulate all copies into signed sums of 128 entries
  const sums = new Int32Array(RM_BASE_LEN);

  let bitPos = 0;
  for (let rep = 0; rep < multiplicity; rep++) {
    for (let i = 0; i < RM_BASE_LEN; i++) {
      const wordIdx = bitPos >>> 5;
      const bitIdx = bitPos & 31;
      let bit = 0;
      if (wordIdx < src.length) {
        bit = (src[wordIdx] >>> bitIdx) & 1;
      }
      // Convert 0/1 to +1/-1 (0 -> +1, 1 -> -1)
      sums[i] += 1 - 2 * bit;
      bitPos++;
    }
  }

  // Step 2: Fast Walsh-Hadamard Transform (in-place, 7 passes)
  for (let pass = 0; pass < 7; pass++) {
    const step = 1 << pass;
    for (let i = 0; i < RM_BASE_LEN; i += 2 * step) {
      for (let j = i; j < i + step; j++) {
        const a = sums[j];
        const b = sums[j + step];
        sums[j] = a + b;
        sums[j + step] = a - b;
      }
    }
  }

  // Step 3: Find position with maximum absolute value
  let maxAbs = 0;
  let maxPos = 0;
  let sign = 1;

  for (let i = 0; i < RM_BASE_LEN; i++) {
    const v = sums[i];
    const abs = v < 0 ? -v : v;
    if (abs > maxAbs) {
      maxAbs = abs;
      maxPos = i;
      sign = v > 0 ? 1 : -1;
    }
  }

  // Step 4: Recover message byte
  let msg = (maxPos << 1) & 0xFF;
  if (sign < 0) msg |= 1;
  return msg;
}
