/**
 * XMSS (eXtended Merkle Signature Scheme) for SLH-DSA (FIPS 205)
 * Algorithms 9-11
 */

import { ADRS, ADDR_TYPE } from './address.js';
import { wotsPkgen, wotsSign, wotsPkFromSig } from './wots.js';

/**
 * xmssNode(skSeed, pkSeed, i, z, adrs, params, hashSuite) - Algorithm 9
 * Compute the root of a subtree of height z at index i
 */
function xmssNode(skSeed, pkSeed, i, z, adrs, params, hashSuite) {
  const { hp, n } = params;

  if (z === 0) {
    // Leaf node: WOTS+ public key
    adrs.setType(ADDR_TYPE.WOTS_HASH);
    adrs.setKeyPairAddress(i);
    return wotsPkgen(skSeed, pkSeed, adrs, params, hashSuite);
  }

  const lNode = xmssNode(skSeed, pkSeed, 2 * i, z - 1, adrs, params, hashSuite);
  const rNode = xmssNode(skSeed, pkSeed, 2 * i + 1, z - 1, adrs, params, hashSuite);

  adrs.setType(ADDR_TYPE.TREE);
  adrs.setTreeHeight(z);
  adrs.setTreeIndex(i);
  return hashSuite.H(pkSeed, adrs, lNode, rNode);
}

/**
 * xmssSign(M, skSeed, idx, pkSeed, adrs, params, hashSuite) - Algorithm 10
 * Generate an XMSS signature
 * Returns { sig, authPath } as concatenated bytes: sig || auth[0] || ... || auth[hp-1]
 */
function xmssSign(M, skSeed, idx, pkSeed, adrs, params, hashSuite) {
  const { hp, n } = params;

  // Generate WOTS+ signature
  adrs.setType(ADDR_TYPE.WOTS_HASH);
  adrs.setKeyPairAddress(idx);
  const sig = wotsSign(M, skSeed, pkSeed, adrs, params, hashSuite);

  // Build authentication path
  const auth = new Uint8Array(hp * n);
  for (let j = 0; j < hp; j++) {
    const k = (idx >>> j) ^ 1;  // sibling index at level j
    const node = xmssNode(skSeed, pkSeed, k, j, adrs, params, hashSuite);
    auth.set(node, j * n);
  }

  // Concatenate sig || auth
  const result = new Uint8Array(sig.length + auth.length);
  result.set(sig, 0);
  result.set(auth, sig.length);
  return result;
}

/**
 * xmssPkFromSig(idx, sigXmss, M, pkSeed, adrs, params, hashSuite) - Algorithm 11
 * Compute XMSS public key from signature
 */
function xmssPkFromSig(idx, sigXmss, M, pkSeed, adrs, params, hashSuite) {
  const { hp, n, len } = params;

  // Parse signature: first len*n bytes = WOTS sig, then hp*n bytes = auth path
  const wotsSig = sigXmss.slice(0, len * n);
  const auth = [];
  for (let j = 0; j < hp; j++) {
    auth.push(sigXmss.slice(len * n + j * n, len * n + (j + 1) * n));
  }

  // Compute WOTS+ public key from signature
  adrs.setType(ADDR_TYPE.WOTS_HASH);
  adrs.setKeyPairAddress(idx);
  let node0 = wotsPkFromSig(wotsSig, M, pkSeed, adrs, params, hashSuite);

  // Walk up the tree
  adrs.setType(ADDR_TYPE.TREE);
  adrs.setTreeIndex(idx);
  for (let j = 0; j < hp; j++) {
    adrs.setTreeHeight(j + 1);
    const treeIdx = (idx >>> j);
    if (treeIdx % 2 === 0) {
      adrs.setTreeIndex(treeIdx >>> 1);
      node0 = hashSuite.H(pkSeed, adrs, node0, auth[j]);
    } else {
      adrs.setTreeIndex((treeIdx - 1) >>> 1);
      node0 = hashSuite.H(pkSeed, adrs, auth[j], node0);
    }
  }
  return node0;
}

export { xmssNode, xmssSign, xmssPkFromSig };
