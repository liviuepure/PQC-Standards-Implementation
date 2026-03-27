/**
 * Hash function suites for SLH-DSA (FIPS 205)
 *
 * Two families:
 *   SHAKE - uses SHAKE-256 for all functions
 *   SHA2  - uses SHA-256 (n<=16) or SHA-512 (n>16), HMAC, MGF1
 */

import { createHash, createHmac } from 'node:crypto';
import { concat } from './utils.js';

// ============================================================
// SHAKE suite (Section 11.1 of FIPS 205)
// All functions use SHAKE-256
// ============================================================

function shakeHash(input, outputLen) {
  const h = createHash('shake256', { outputLength: outputLen });
  h.update(input);
  return h.digest();
}

function createShakeSuite(params) {
  const n = params.n;

  return {
    name: 'shake',

    /**
     * PRF(pkSeed, skSeed, adrs) -> n bytes
     * SHAKE-256(pkSeed || adrs || skSeed, 8n)
     */
    PRF(pkSeed, skSeed, adrs) {
      const input = concat(pkSeed, adrs.bytes(), skSeed);
      return new Uint8Array(shakeHash(Buffer.from(input), n));
    },

    /**
     * PRFMsg(skPrf, optRand, msg) -> n bytes
     * SHAKE-256(skPrf || optRand || msg, 8n)
     */
    PRFMsg(skPrf, optRand, msg) {
      const input = concat(skPrf, optRand, msg);
      return new Uint8Array(shakeHash(Buffer.from(input), n));
    },

    /**
     * F(pkSeed, adrs, m1) -> n bytes
     * SHAKE-256(pkSeed || adrs || m1, 8n)
     */
    F(pkSeed, adrs, m1) {
      const input = concat(pkSeed, adrs.bytes(), m1);
      return new Uint8Array(shakeHash(Buffer.from(input), n));
    },

    /**
     * H(pkSeed, adrs, m1, m2) -> n bytes
     * SHAKE-256(pkSeed || adrs || m1 || m2, 8n)
     */
    H(pkSeed, adrs, m1, m2) {
      const input = concat(pkSeed, adrs.bytes(), m1, m2);
      return new Uint8Array(shakeHash(Buffer.from(input), n));
    },

    /**
     * Tl(pkSeed, adrs, m) -> n bytes
     * SHAKE-256(pkSeed || adrs || m, 8n)
     * m is a concatenation of multiple n-byte blocks
     */
    Tl(pkSeed, adrs, m) {
      const input = concat(pkSeed, adrs.bytes(), m);
      return new Uint8Array(shakeHash(Buffer.from(input), n));
    },

    /**
     * HMsg(R, pkSeed, pkRoot, msg) -> hmsgLen bytes
     * SHAKE-256(R || pkSeed || pkRoot || msg, 8*hmsgLen)
     */
    HMsg(R, pkSeed, pkRoot, msg) {
      const input = concat(R, pkSeed, pkRoot, msg);
      return new Uint8Array(shakeHash(Buffer.from(input), params.hmsgLen));
    },
  };
}

// ============================================================
// SHA2 suite (Section 11.2 of FIPS 205)
// n <= 16 -> SHA-256; n > 16 -> SHA-512
// ============================================================

function sha256(data) {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

function sha512(data) {
  return new Uint8Array(createHash('sha512').update(data).digest());
}

function hmacSha(alg, key, data) {
  return new Uint8Array(
    createHmac(alg, Buffer.from(key)).update(data).digest()
  );
}

/**
 * MGF1 as defined in RFC 8017 using SHA-256 or SHA-512
 */
function mgf1(hashFn, hashLen, seed, maskLen) {
  const result = [];
  let counter = 0;
  let generated = 0;
  while (generated < maskLen) {
    const C = new Uint8Array(4);
    C[0] = (counter >> 24) & 0xff;
    C[1] = (counter >> 16) & 0xff;
    C[2] = (counter >> 8) & 0xff;
    C[3] = counter & 0xff;
    const block = hashFn(Buffer.from(concat(seed, C)));
    result.push(block);
    generated += hashLen;
    counter++;
  }
  const combined = concat(...result);
  return combined.slice(0, maskLen);
}

function createSha2Suite(params) {
  const n = params.n;
  // For n <= 16 use SHA-256 (32-byte output), else SHA-512 (64-byte output)
  const useSha256 = n <= 16;
  const hashFn = useSha256 ? sha256 : sha512;
  const hashLen = useSha256 ? 32 : 64;
  const hmacAlg = useSha256 ? 'sha256' : 'sha512';

  return {
    name: 'sha2',

    /**
     * PRF(pkSeed, skSeed, adrs) -> n bytes
     * For SHA2: HMAC(pkSeed, adrs_compressed || skSeed), truncated to n bytes
     * Per FIPS 205 Section 11.2.1:
     *   PRF = Trunc_n(SHA-256(pkSeed || toByte(0,64-n) || adrs_c || skSeed))
     */
    PRF(pkSeed, skSeed, adrs) {
      const adrsC = compressAdrs(adrs);
      const padding = new Uint8Array(hashLen - n);
      const input = concat(pkSeed, padding, adrsC, skSeed);
      return hashFn(Buffer.from(input)).slice(0, n);
    },

    /**
     * PRFMsg(skPrf, optRand, msg) -> n bytes
     * HMAC(skPrf, optRand || msg), truncated to n
     */
    PRFMsg(skPrf, optRand, msg) {
      const data = concat(optRand, msg);
      return hmacSha(hmacAlg, skPrf, Buffer.from(data)).slice(0, n);
    },

    /**
     * F(pkSeed, adrs, m1) -> n bytes
     * SHA-256(pkSeed || toByte(0, 64-n) || adrs_c || m1), truncated to n
     */
    F(pkSeed, adrs, m1) {
      const adrsC = compressAdrs(adrs);
      const padding = new Uint8Array(hashLen - n);
      const input = concat(pkSeed, padding, adrsC, m1);
      return hashFn(Buffer.from(input)).slice(0, n);
    },

    /**
     * H(pkSeed, adrs, m1, m2) -> n bytes
     * For n <= 16: SHA-256(pkSeed || toByte(0,64-n) || adrs_c || m1 || m2), trunc n
     * For n > 16:  SHA-512(...), trunc n
     */
    H(pkSeed, adrs, m1, m2) {
      const adrsC = compressAdrs(adrs);
      const padding = new Uint8Array(hashLen - n);
      const input = concat(pkSeed, padding, adrsC, m1, m2);
      return hashFn(Buffer.from(input)).slice(0, n);
    },

    /**
     * Tl(pkSeed, adrs, m) -> n bytes
     * For n <= 16: SHA-256(pkSeed || toByte(0,64-n) || adrs_c || m), trunc n
     * For n > 16:  SHA-512(...), trunc n
     */
    Tl(pkSeed, adrs, m) {
      const adrsC = compressAdrs(adrs);
      const padding = new Uint8Array(hashLen - n);
      const input = concat(pkSeed, padding, adrsC, m);
      return hashFn(Buffer.from(input)).slice(0, n);
    },

    /**
     * HMsg(R, pkSeed, pkRoot, msg) -> hmsgLen bytes
     * MGF1-SHA-X(SHA-X(R || pkSeed || pkRoot || msg), hmsgLen)
     */
    HMsg(R, pkSeed, pkRoot, msg) {
      const input = concat(R, pkSeed, pkRoot, msg);
      const seed = hashFn(Buffer.from(input));
      return mgf1(hashFn, hashLen, seed, params.hmsgLen);
    },
  };
}

/**
 * Compress ADRS for SHA2 suite (FIPS 205, Section 11.2.1)
 * Compresses the 32-byte ADRS to 22 bytes by:
 *   - Keeping bytes 0-2 of layerAddress (drop byte 3)
 *   - Keeping bytes 4-7 of treeAddress (last 8 bytes -> keep bytes 8-15)
 *   - Type: keep byte 19 only
 *   - Keep last 3 words as-is (12 bytes: 20-31)
 *
 * Actually per FIPS 205 Section 11.2.1:
 *   ADRS_c = ADRS[3] || ADRS[8..15] || ADRS[19] || ADRS[20..31]
 *   = 1 + 8 + 1 + 12 = 22 bytes
 */
function compressAdrs(adrs) {
  const d = adrs.bytes();
  const out = new Uint8Array(22);
  out[0] = d[3];           // layer (1 byte)
  out.set(d.slice(8, 16), 1);  // tree address (8 bytes)
  out[9] = d[19];          // type (1 byte)
  out.set(d.slice(20, 32), 10); // type-specific (12 bytes)
  return out;
}

/**
 * Create a hash suite for the given parameter set
 */
function createHashSuite(params) {
  if (params.hashFamily === 'shake') {
    return createShakeSuite(params);
  } else {
    return createSha2Suite(params);
  }
}

export { createHashSuite, createShakeSuite, createSha2Suite };
