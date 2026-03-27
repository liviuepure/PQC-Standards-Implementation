/**
 * Hypertree for SLH-DSA (FIPS 205)
 * Algorithms 16-17
 */

import { ADRS, ADDR_TYPE } from './address.js';
import { xmssNode, xmssSign, xmssPkFromSig } from './xmss.js';
import { concat } from './utils.js';

/**
 * htSign(M, skSeed, pkSeed, idxTree, idxLeaf, params, hashSuite) - Algorithm 16
 * Generate a hypertree signature
 *
 * idxTree: BigInt tree index
 * idxLeaf: integer leaf index
 */
function htSign(M, skSeed, pkSeed, idxTree, idxLeaf, params, hashSuite) {
  const { d, hp, n, len } = params;

  const adrs = new ADRS();
  adrs.setTreeAddress(idxTree);

  // Sign at layer 0
  const sigXmss0 = xmssSign(M, skSeed, idxLeaf, pkSeed, adrs, params, hashSuite);

  const sigParts = [sigXmss0];

  // Compute root at layer 0 for next layer's message
  let root = xmssPkFromSig(idxLeaf, sigXmss0, M, pkSeed, adrs, params, hashSuite);

  // Sign at subsequent layers
  let tree = idxTree;
  for (let j = 1; j < d; j++) {
    const leaf = Number(BigInt(tree) & BigInt((1 << hp) - 1));
    tree = BigInt(tree) >> BigInt(hp);

    adrs.setLayerAddress(j);
    adrs.setTreeAddress(tree);

    const sigJ = xmssSign(root, skSeed, leaf, pkSeed, adrs, params, hashSuite);
    sigParts.push(sigJ);

    if (j < d - 1) {
      root = xmssPkFromSig(leaf, sigJ, root, pkSeed, adrs, params, hashSuite);
    }
  }

  return concat(...sigParts);
}

/**
 * htVerify(M, sigHt, pkSeed, idxTree, idxLeaf, pkRoot, params, hashSuite) - Algorithm 17
 * Verify a hypertree signature
 */
function htVerify(M, sigHt, pkSeed, idxTree, idxLeaf, pkRoot, params, hashSuite) {
  const { d, hp, n, len } = params;
  const xmssSigLen = (len + hp) * n;

  const adrs = new ADRS();
  adrs.setTreeAddress(idxTree);

  // Parse first XMSS signature
  const sig0 = sigHt.slice(0, xmssSigLen);
  let node = xmssPkFromSig(idxLeaf, sig0, M, pkSeed, adrs, params, hashSuite);

  // Verify subsequent layers
  let tree = idxTree;
  for (let j = 1; j < d; j++) {
    const leaf = Number(BigInt(tree) & BigInt((1 << hp) - 1));
    tree = BigInt(tree) >> BigInt(hp);

    adrs.setLayerAddress(j);
    adrs.setTreeAddress(tree);

    const sigJ = sigHt.slice(j * xmssSigLen, (j + 1) * xmssSigLen);
    node = xmssPkFromSig(leaf, sigJ, node, pkSeed, adrs, params, hashSuite);
  }

  // Check if computed root matches pk root
  if (node.length !== pkRoot.length) return false;
  let eq = 0;
  for (let i = 0; i < node.length; i++) {
    eq |= node[i] ^ pkRoot[i];
  }
  return eq === 0;
}

export { htSign, htVerify };
