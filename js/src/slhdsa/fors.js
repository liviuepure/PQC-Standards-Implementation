/**
 * FORS (Forest of Random Subsets) for SLH-DSA (FIPS 205)
 * Algorithms 12-15
 */

import { ADRS, ADDR_TYPE } from './address.js';
import { concat } from './utils.js';

/**
 * forsSkgen(skSeed, pkSeed, adrs, idx, params, hashSuite) - Algorithm 12
 * Generate a FORS secret key value
 */
function forsSkgen(skSeed, pkSeed, adrs, idx, params, hashSuite) {
  const skAdrs = adrs.copy();
  skAdrs.setType(ADDR_TYPE.FORS_PRF);
  skAdrs.setKeyPairAddress(adrs.getKeyPairAddress());
  skAdrs.setTreeIndex(idx);
  return hashSuite.PRF(pkSeed, skSeed, skAdrs);
}

/**
 * forsNode(skSeed, pkSeed, i, z, adrs, params, hashSuite) - Algorithm 13
 * Compute FORS tree node at height z, index i
 */
function forsNode(skSeed, pkSeed, i, z, adrs, params, hashSuite) {
  const { n } = params;

  if (z === 0) {
    const sk = forsSkgen(skSeed, pkSeed, adrs, i, params, hashSuite);
    adrs.setTreeHeight(0);
    adrs.setTreeIndex(i);
    return hashSuite.F(pkSeed, adrs, sk);
  }

  const lNode = forsNode(skSeed, pkSeed, 2 * i, z - 1, adrs, params, hashSuite);
  const rNode = forsNode(skSeed, pkSeed, 2 * i + 1, z - 1, adrs, params, hashSuite);

  adrs.setTreeHeight(z);
  adrs.setTreeIndex(i);
  return hashSuite.H(pkSeed, adrs, lNode, rNode);
}

/**
 * forsSign(md, skSeed, pkSeed, adrs, params, hashSuite) - Algorithm 14
 * Generate FORS signature
 * md is an array of k a-bit indices (integers)
 */
function forsSign(md, skSeed, pkSeed, adrs, params, hashSuite) {
  const { k, a, n } = params;

  const sigParts = [];

  for (let i = 0; i < k; i++) {
    const idx = md[i];

    // Secret key value
    const sk = forsSkgen(skSeed, pkSeed, adrs, i * (1 << a) + idx, params, hashSuite);
    sigParts.push(sk);

    // Authentication path
    for (let j = 0; j < a; j++) {
      const s = ((i * (1 << a) + idx) >>> j) ^ 1;
      const node = forsNode(skSeed, pkSeed, s, j, adrs, params, hashSuite);
      sigParts.push(node);
    }
  }

  return concat(...sigParts);
}

/**
 * forsPkFromSig(sigFors, md, pkSeed, adrs, params, hashSuite) - Algorithm 15
 * Compute FORS public key from signature
 */
function forsPkFromSig(sigFors, md, pkSeed, adrs, params, hashSuite) {
  const { k, a, n } = params;

  const roots = [];
  let offset = 0;

  for (let i = 0; i < k; i++) {
    const idx = md[i];

    // Get secret key value from signature
    const sk = sigFors.slice(offset, offset + n);
    offset += n;

    // Compute leaf
    adrs.setTreeHeight(0);
    adrs.setTreeIndex(i * (1 << a) + idx);
    let node0 = hashSuite.F(pkSeed, adrs, sk);

    // Walk up using auth path
    for (let j = 0; j < a; j++) {
      const auth = sigFors.slice(offset, offset + n);
      offset += n;

      adrs.setTreeHeight(j + 1);
      const treeIdx = (i * (1 << a) + idx) >>> j;
      if (treeIdx % 2 === 0) {
        adrs.setTreeIndex(treeIdx >>> 1);
        node0 = hashSuite.H(pkSeed, adrs, node0, auth);
      } else {
        adrs.setTreeIndex((treeIdx - 1) >>> 1);
        node0 = hashSuite.H(pkSeed, adrs, auth, node0);
      }
    }
    roots.push(node0);
  }

  // Compute FORS public key as Tl of all roots
  const forsAdrs = adrs.copy();
  forsAdrs.setType(ADDR_TYPE.FORS_ROOTS);
  forsAdrs.setKeyPairAddress(adrs.getKeyPairAddress());
  return hashSuite.Tl(pkSeed, forsAdrs, concat(...roots));
}

export { forsSkgen, forsNode, forsSign, forsPkFromSig };
