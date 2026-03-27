/**
 * SLH-DSA Top-Level Operations (FIPS 205)
 * Algorithms 18-20: keyGen, sign, verify
 */

import { randomBytes } from 'node:crypto';
import { ADRS, ADDR_TYPE } from './address.js';
import { createHashSuite } from './hash.js';
import { xmssNode } from './xmss.js';
import { forsSign, forsPkFromSig } from './fors.js';
import { htSign, htVerify } from './hypertree.js';
import { toInt, toBigInt, base2b, concat } from './utils.js';

/**
 * slhKeyGen(params) - Algorithm 18
 * Generate SLH-DSA key pair
 * Returns { sk, pk } where:
 *   sk = skSeed || skPrf || pkSeed || pkRoot (4*n bytes)
 *   pk = pkSeed || pkRoot (2*n bytes)
 */
function slhKeyGen(params) {
  const n = params.n;
  const hashSuite = createHashSuite(params);

  // Generate random seeds
  const skSeed = new Uint8Array(randomBytes(n));
  const skPrf = new Uint8Array(randomBytes(n));
  const pkSeed = new Uint8Array(randomBytes(n));

  // Compute root of the top XMSS tree in the hypertree
  const adrs = new ADRS();
  adrs.setLayerAddress(params.d - 1);
  const pkRoot = xmssNode(skSeed, pkSeed, 0, params.hp, adrs, params, hashSuite);

  const sk = concat(skSeed, skPrf, pkSeed, pkRoot);
  const pk = concat(pkSeed, pkRoot);

  return { sk, pk };
}

/**
 * slhSign(msg, sk, params, optRand) - Algorithm 19
 * Sign a message with SLH-DSA
 *
 * msg: Uint8Array message
 * sk:  Uint8Array secret key (4*n bytes)
 * optRand: optional randomness (n bytes), if null uses pkSeed (deterministic)
 *
 * Returns signature as Uint8Array
 */
function slhSign(msg, sk, params, optRand) {
  const n = params.n;
  const hashSuite = createHashSuite(params);

  // Parse secret key
  const skSeed = sk.slice(0, n);
  const skPrf = sk.slice(n, 2 * n);
  const pkSeed = sk.slice(2 * n, 3 * n);
  const pkRoot = sk.slice(3 * n, 4 * n);

  // Generate randomizer
  if (!optRand) {
    optRand = pkSeed; // deterministic variant
  }
  const R = hashSuite.PRFMsg(skPrf, optRand, msg);

  // Compute message digest
  const digest = hashSuite.HMsg(R, pkSeed, pkRoot, msg);

  // Parse digest into FORS message, tree index, leaf index
  const { mdBytes, treeIdxBytes, leafIdxBytes, k, a, forsMsgBits, treeIdxBits, leafIdxBits } = params;

  const mdBuf = digest.slice(0, mdBytes);
  const treeIdxBuf = digest.slice(mdBytes, mdBytes + treeIdxBytes);
  const leafIdxBuf = digest.slice(mdBytes + treeIdxBytes);

  // FORS message: k values, each a bits
  const md = base2b(mdBuf, a, k);

  // Tree and leaf indices
  let idxTree = toBigInt(treeIdxBuf, treeIdxBytes);
  // Mask to treeIdxBits
  const treeMask = (1n << BigInt(treeIdxBits)) - 1n;
  idxTree &= treeMask;

  let idxLeaf = toInt(leafIdxBuf, leafIdxBytes);
  // Mask to leafIdxBits
  idxLeaf &= (1 << leafIdxBits) - 1;

  // FORS signature
  const adrs = new ADRS();
  adrs.setTreeAddress(idxTree);
  adrs.setType(ADDR_TYPE.FORS_TREE);
  adrs.setKeyPairAddress(idxLeaf);

  const sigFors = forsSign(md, skSeed, pkSeed, adrs, params, hashSuite);

  // Compute FORS public key
  const pkFors = forsPkFromSig(sigFors, md, pkSeed, adrs, params, hashSuite);

  // Hypertree signature on FORS public key
  const sigHt = htSign(pkFors, skSeed, pkSeed, idxTree, idxLeaf, params, hashSuite);

  // Return R || sigFors || sigHt
  return concat(R, sigFors, sigHt);
}

/**
 * slhVerify(msg, sig, pk, params) - Algorithm 20
 * Verify an SLH-DSA signature
 *
 * Returns true if valid, false otherwise
 */
function slhVerify(msg, sig, pk, params) {
  const n = params.n;
  const hashSuite = createHashSuite(params);

  // Check signature length
  if (sig.length !== params.sig) {
    return false;
  }

  // Parse public key
  const pkSeed = pk.slice(0, n);
  const pkRoot = pk.slice(n, 2 * n);

  // Parse signature
  const R = sig.slice(0, n);
  const forsSigLen = params.k * (1 + params.a) * n;
  const sigFors = sig.slice(n, n + forsSigLen);
  const sigHt = sig.slice(n + forsSigLen);

  // Compute message digest
  const digest = hashSuite.HMsg(R, pkSeed, pkRoot, msg);

  const { mdBytes, treeIdxBytes, leafIdxBytes, k, a, treeIdxBits, leafIdxBits } = params;

  const mdBuf = digest.slice(0, mdBytes);
  const treeIdxBuf = digest.slice(mdBytes, mdBytes + treeIdxBytes);
  const leafIdxBuf = digest.slice(mdBytes + treeIdxBytes);

  const md = base2b(mdBuf, a, k);

  let idxTree = toBigInt(treeIdxBuf, treeIdxBytes);
  const treeMask = (1n << BigInt(treeIdxBits)) - 1n;
  idxTree &= treeMask;

  let idxLeaf = toInt(leafIdxBuf, leafIdxBytes);
  idxLeaf &= (1 << leafIdxBits) - 1;

  // Compute FORS public key from signature
  const adrs = new ADRS();
  adrs.setTreeAddress(idxTree);
  adrs.setType(ADDR_TYPE.FORS_TREE);
  adrs.setKeyPairAddress(idxLeaf);

  const pkFors = forsPkFromSig(sigFors, md, pkSeed, adrs, params, hashSuite);

  // Verify hypertree signature
  return htVerify(pkFors, sigHt, pkSeed, idxTree, idxLeaf, pkRoot, params, hashSuite);
}

export { slhKeyGen, slhSign, slhVerify };
