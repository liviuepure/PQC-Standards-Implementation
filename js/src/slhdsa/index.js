import * as params from './params.js';
import { ADRS, ADDR_TYPE } from './address.js';
import { createHashSuite } from './hash.js';
import { toInt, toBigInt, toByte, toByteBigInt, base2b, concat } from './utils.js';
import { chain, wotsPkgen, wotsSign, wotsPkFromSig } from './wots.js';
import { xmssNode, xmssSign, xmssPkFromSig } from './xmss.js';
import { forsSkgen, forsNode, forsSign, forsPkFromSig } from './fors.js';
import { htSign, htVerify } from './hypertree.js';
import { slhKeyGen, slhSign, slhVerify } from './slhdsa.js';

// Re-export top-level API
export const keyGen = slhKeyGen;
export const sign = slhSign;
export const verify = slhVerify;

// Re-export parameter sets
export const {
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
} = params;

// Re-export internals (for advanced usage / testing)
export {
  ADRS,
  ADDR_TYPE,
  createHashSuite,
  toInt,
  toBigInt,
  toByte,
  toByteBigInt,
  base2b,
  concat,
  chain,
  wotsPkgen,
  wotsSign,
  wotsPkFromSig,
  xmssNode,
  xmssSign,
  xmssPkFromSig,
  forsSkgen,
  forsNode,
  forsSign,
  forsPkFromSig,
  htSign,
  htVerify,
};
