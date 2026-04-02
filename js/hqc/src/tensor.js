/**
 * Tensor product code: concatenated RS (outer) x RM (inner) code.
 *
 * Encoding: message m (k bytes) -> RS encode to n1 bytes -> each byte RM-encoded
 * to n2 bits -> total n1*n2 bits.
 *
 * Decoding: received n1*n2 bits -> split into n1 blocks of n2 bits each ->
 * RM-decode each block to get n1 bytes -> RS-decode to get k bytes.
 */

import { rsEncode, rsDecode } from './rs.js';
import { rmEncodeInto, rmDecode } from './rm.js';
import { extractBits } from './gf2.js';

/**
 * Encode a k-byte message into an n1*n2-bit codeword.
 * @param {Uint8Array} msg
 * @param {import('./params.js').HQCParams} p
 * @returns {Uint32Array}
 */
export function tensorEncode(msg, p) {
  // Step 1: RS encode the message
  const rsCodeword = rsEncode(msg, p);

  // Step 2: RM encode each RS symbol
  const out = new Uint32Array(p.vecN1N2Size64);

  for (let i = 0; i < p.n1; i++) {
    rmEncodeInto(out, rsCodeword[i], i * p.n2, p.multiplicity);
  }

  return out;
}

/**
 * Decode a received n1*n2-bit word back to a k-byte message.
 * @param {Uint32Array} received
 * @param {import('./params.js').HQCParams} p
 * @returns {[Uint8Array|null, boolean]}
 */
export function tensorDecode(received, p) {
  // Step 1: RM-decode each block of n2 bits to get one byte
  const rsReceived = new Uint8Array(p.n1);

  for (let i = 0; i < p.n1; i++) {
    const block = extractBits(received, i * p.n2, p.n2);
    rsReceived[i] = rmDecode(block, p.n2, p.multiplicity);
  }

  // Step 2: RS-decode the n1-byte received word to get k bytes
  return rsDecode(rsReceived, p);
}
