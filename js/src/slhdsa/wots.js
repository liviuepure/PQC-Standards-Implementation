/**
 * WOTS+ (Winternitz One-Time Signature) for SLH-DSA (FIPS 205)
 * Algorithms 5-8
 */

import { ADRS, ADDR_TYPE } from './address.js';
import { base2b, concat, toByte } from './utils.js';

/**
 * chain(X, i, s, pkSeed, adrs, hashSuite) - Algorithm 5
 * Apply F s times starting from index i
 */
function chain(X, i, s, pkSeed, adrs, params, hashSuite) {
  if (s === 0) return new Uint8Array(X);
  let tmp = new Uint8Array(X);
  for (let j = i; j < i + s; j++) {
    adrs.setHashAddress(j);
    tmp = hashSuite.F(pkSeed, adrs, tmp);
  }
  return tmp;
}

/**
 * wotsPkgen(skSeed, pkSeed, adrs, params, hashSuite) - Algorithm 6
 * Generate a WOTS+ public key
 */
function wotsPkgen(skSeed, pkSeed, adrs, params, hashSuite) {
  const { n, len, w } = params;
  const skAdrs = adrs.copy();
  skAdrs.setType(ADDR_TYPE.WOTS_PRF);
  skAdrs.setKeyPairAddress(adrs.getKeyPairAddress());

  const tmp = new Uint8Array(len * n);
  for (let i = 0; i < len; i++) {
    skAdrs.setChainAddress(i);
    const sk = hashSuite.PRF(pkSeed, skSeed, skAdrs);
    adrs.setChainAddress(i);
    const pk_i = chain(sk, 0, w - 1, pkSeed, adrs, params, hashSuite);
    tmp.set(pk_i, i * n);
  }

  const wotsPkAdrs = adrs.copy();
  wotsPkAdrs.setType(ADDR_TYPE.WOTS_PK);
  wotsPkAdrs.setKeyPairAddress(adrs.getKeyPairAddress());
  return hashSuite.Tl(pkSeed, wotsPkAdrs, tmp);
}

/**
 * wotsSign(M, skSeed, pkSeed, adrs, params, hashSuite) - Algorithm 7
 * Generate a WOTS+ signature for message M
 */
function wotsSign(M, skSeed, pkSeed, adrs, params, hashSuite) {
  const { n, len, w, lgw } = params;

  // Per FIPS 205: len1 = ceil(8n / lgw), len2 = len - len1
  const len1 = Math.ceil((8 * n) / lgw);
  const len2 = len - len1;

  const msg1 = base2b(M, lgw, len1);

  // Compute checksum
  let csum = 0;
  for (let i = 0; i < len1; i++) {
    csum += w - 1 - msg1[i];
  }

  // csum needs ceil(floor(log2(len1*(w-1)))+1) bits, packed into bytes, then base2b
  const csumBits = Math.floor(Math.log2(len1 * (w - 1))) + 1;
  const csumBytes = Math.ceil(csumBits / 8);
  csum <<= (8 * csumBytes - csumBits); // left-shift per spec: csum << (8 - (csumBits % 8)) % 8
  const csumBuf = toByte(csum, csumBytes);
  const msg2 = base2b(csumBuf, lgw, len2);

  const msgAll = msg1.concat(msg2);

  // Sign
  const skAdrs = adrs.copy();
  skAdrs.setType(ADDR_TYPE.WOTS_PRF);
  skAdrs.setKeyPairAddress(adrs.getKeyPairAddress());

  const sig = new Uint8Array(len * n);
  for (let i = 0; i < len; i++) {
    skAdrs.setChainAddress(i);
    const sk = hashSuite.PRF(pkSeed, skSeed, skAdrs);
    adrs.setChainAddress(i);
    const s = chain(sk, 0, msgAll[i], pkSeed, adrs, params, hashSuite);
    sig.set(s, i * n);
  }
  return sig;
}

/**
 * wotsPkFromSig(sig, M, pkSeed, adrs, params, hashSuite) - Algorithm 8
 * Compute WOTS+ public key from signature
 */
function wotsPkFromSig(sig, M, pkSeed, adrs, params, hashSuite) {
  const { n, len, w, lgw } = params;

  const len1 = Math.ceil((8 * n) / lgw);
  const len2 = len - len1;

  const msg1 = base2b(M, lgw, len1);

  let csum = 0;
  for (let i = 0; i < len1; i++) {
    csum += w - 1 - msg1[i];
  }

  const csumBits = Math.floor(Math.log2(len1 * (w - 1))) + 1;
  const csumBytes = Math.ceil(csumBits / 8);
  csum <<= (8 * csumBytes - csumBits);
  const csumBuf = toByte(csum, csumBytes);
  const msg2 = base2b(csumBuf, lgw, len2);

  const msgAll = msg1.concat(msg2);

  const tmp = new Uint8Array(len * n);
  for (let i = 0; i < len; i++) {
    adrs.setChainAddress(i);
    const sigBlock = sig.slice(i * n, (i + 1) * n);
    const pk_i = chain(sigBlock, msgAll[i], w - 1 - msgAll[i], pkSeed, adrs, params, hashSuite);
    tmp.set(pk_i, i * n);
  }

  const wotsPkAdrs = adrs.copy();
  wotsPkAdrs.setType(ADDR_TYPE.WOTS_PK);
  wotsPkAdrs.setKeyPairAddress(adrs.getKeyPairAddress());
  return hashSuite.Tl(pkSeed, wotsPkAdrs, tmp);
}

export { chain, wotsPkgen, wotsSign, wotsPkFromSig };
