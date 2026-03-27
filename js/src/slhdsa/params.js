/**
 * SLH-DSA Parameter Sets (FIPS 205)
 *
 * Each parameter set defines:
 *   n     - security parameter (bytes)
 *   h     - total tree height
 *   d     - number of layers in hypertree
 *   hp    - height of each tree (h/d)
 *   a     - FORS tree height
 *   k     - number of FORS trees
 *   w     - Winternitz parameter
 *   len   - WOTS+ signature length (in n-byte blocks)
 *   sig   - total signature size in bytes
 *   lgw   - log2(w)
 *   m     - message digest length in bytes
 */

function makeParams(name, hashFamily, n, h, d, hp, a, k, w, len, sig) {
  const lgw = Math.log2(w);
  // m = k*a + (h - h/d) + ceil(h/d * log2(d? no...))
  // For FIPS 205, message digest length derivation:
  //   md = floor((k * a + 7) / 8)  -- FORS bits
  //   idx_tree bits = h - h/d
  //   idx_leaf bits = h/d
  // We store these as needed for HMsg parsing
  const forsMsgBits = k * a;
  const treeIdxBits = h - hp;  // h - h/d
  const leafIdxBits = hp;
  const mdBytes = Math.ceil(forsMsgBits / 8);
  const treeIdxBytes = Math.ceil(treeIdxBits / 8);
  const leafIdxBytes = Math.ceil(leafIdxBits / 8);
  const hmsgLen = mdBytes + treeIdxBytes + leafIdxBytes;

  return {
    name,
    hashFamily, // 'shake' or 'sha2'
    n,
    h,
    d,
    hp,
    a,
    k,
    w,
    len,
    sig,
    lgw,
    forsMsgBits,
    treeIdxBits,
    leafIdxBits,
    mdBytes,
    treeIdxBytes,
    leafIdxBytes,
    hmsgLen,
    // pk size = 2*n, sk size = 4*n
    pkLen: 2 * n,
    skLen: 4 * n,
  };
}

// SHAKE variants (all use SHAKE-256 internally per FIPS 205)
const SLH_DSA_SHAKE_128f = makeParams('SLH-DSA-SHAKE-128f', 'shake', 16, 66, 22, 3, 6, 33, 16, 35, 17088);
const SLH_DSA_SHAKE_128s = makeParams('SLH-DSA-SHAKE-128s', 'shake', 16, 63, 7, 9, 12, 14, 16, 35, 7856);
const SLH_DSA_SHAKE_192f = makeParams('SLH-DSA-SHAKE-192f', 'shake', 24, 66, 22, 3, 8, 33, 16, 51, 35664);
const SLH_DSA_SHAKE_192s = makeParams('SLH-DSA-SHAKE-192s', 'shake', 24, 63, 7, 9, 14, 17, 16, 51, 16224);
const SLH_DSA_SHAKE_256f = makeParams('SLH-DSA-SHAKE-256f', 'shake', 32, 68, 17, 4, 9, 35, 16, 67, 49856);
const SLH_DSA_SHAKE_256s = makeParams('SLH-DSA-SHAKE-256s', 'shake', 32, 64, 8, 8, 14, 22, 16, 67, 29792);

// SHA2 variants (same structural params, use SHA-256/512 backend)
const SLH_DSA_SHA2_128f = makeParams('SLH-DSA-SHA2-128f', 'sha2', 16, 66, 22, 3, 6, 33, 16, 35, 17088);
const SLH_DSA_SHA2_128s = makeParams('SLH-DSA-SHA2-128s', 'sha2', 16, 63, 7, 9, 12, 14, 16, 35, 7856);
const SLH_DSA_SHA2_192f = makeParams('SLH-DSA-SHA2-192f', 'sha2', 24, 66, 22, 3, 8, 33, 16, 51, 35664);
const SLH_DSA_SHA2_192s = makeParams('SLH-DSA-SHA2-192s', 'sha2', 24, 63, 7, 9, 14, 17, 16, 51, 16224);
const SLH_DSA_SHA2_256f = makeParams('SLH-DSA-SHA2-256f', 'sha2', 32, 68, 17, 4, 9, 35, 16, 67, 49856);
const SLH_DSA_SHA2_256s = makeParams('SLH-DSA-SHA2-256s', 'sha2', 32, 64, 8, 8, 14, 22, 16, 67, 29792);

const PARAMS = {
  'SLH-DSA-SHAKE-128f': SLH_DSA_SHAKE_128f,
  'SLH-DSA-SHAKE-128s': SLH_DSA_SHAKE_128s,
  'SLH-DSA-SHAKE-192f': SLH_DSA_SHAKE_192f,
  'SLH-DSA-SHAKE-192s': SLH_DSA_SHAKE_192s,
  'SLH-DSA-SHAKE-256f': SLH_DSA_SHAKE_256f,
  'SLH-DSA-SHAKE-256s': SLH_DSA_SHAKE_256s,
  'SLH-DSA-SHA2-128f': SLH_DSA_SHA2_128f,
  'SLH-DSA-SHA2-128s': SLH_DSA_SHA2_128s,
  'SLH-DSA-SHA2-192f': SLH_DSA_SHA2_192f,
  'SLH-DSA-SHA2-192s': SLH_DSA_SHA2_192s,
  'SLH-DSA-SHA2-256f': SLH_DSA_SHA2_256f,
  'SLH-DSA-SHA2-256s': SLH_DSA_SHA2_256s,
};

export {
  SLH_DSA_SHAKE_128f,
  SLH_DSA_SHAKE_128s,
  SLH_DSA_SHAKE_192f,
  SLH_DSA_SHAKE_192s,
  SLH_DSA_SHAKE_256f,
  SLH_DSA_SHAKE_256s,
  SLH_DSA_SHA2_128f,
  SLH_DSA_SHA2_128s,
  SLH_DSA_SHA2_192f,
  SLH_DSA_SHA2_192s,
  SLH_DSA_SHA2_256f,
  SLH_DSA_SHA2_256s,
  PARAMS,
};
