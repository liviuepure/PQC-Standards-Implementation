/**
 * Byte encoding/decoding for ML-KEM (FIPS 203)
 * Implements Algorithms 5 and 6 from the specification.
 */

import { Q } from './field.js';

/**
 * FIPS 203 Algorithm 5: ByteEncode_d
 * Encodes an array of 256 integers (each in [0, 2^d) or [0, Q) for d=12)
 * into 32*d bytes.
 * @param {number} d - bit width, 1 <= d <= 12
 * @param {number[]} F - array of 256 integers
 * @returns {Uint8Array} 32*d bytes
 */
export function byteEncode(d, F) {
  if (F.length !== 256) throw new RangeError('F must have 256 elements');
  if (d < 1 || d > 12) throw new RangeError('d must be in [1, 12]');

  const B = new Uint8Array(32 * d);
  // Pack 256 d-bit values into a byte stream using a bit buffer
  let bitPos = 0;
  for (let i = 0; i < 256; i++) {
    let val = F[i];
    for (let j = 0; j < d; j++) {
      const byteIdx = bitPos >> 3;
      const bitIdx = bitPos & 7;
      B[byteIdx] |= ((val & 1) << bitIdx);
      val >>= 1;
      bitPos++;
    }
  }
  return B;
}

/**
 * FIPS 203 Algorithm 6: ByteDecode_d
 * Decodes 32*d bytes into an array of 256 integers.
 * For d < 12, values are in [0, 2^d). For d = 12, values are reduced mod Q.
 * @param {number} d - bit width, 1 <= d <= 12
 * @param {Uint8Array} B - 32*d bytes
 * @returns {number[]} array of 256 integers
 */
export function byteDecode(d, B) {
  if (B.length !== 32 * d) throw new RangeError(`B must have ${32 * d} bytes`);
  if (d < 1 || d > 12) throw new RangeError('d must be in [1, 12]');

  const F = new Array(256);
  let bitPos = 0;
  for (let i = 0; i < 256; i++) {
    let val = 0;
    for (let j = 0; j < d; j++) {
      const byteIdx = bitPos >> 3;
      const bitIdx = bitPos & 7;
      val |= ((B[byteIdx] >> bitIdx) & 1) << j;
      bitPos++;
    }
    F[i] = (d === 12) ? val % Q : val;
  }
  return F;
}
