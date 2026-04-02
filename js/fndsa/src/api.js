/**
 * FN-DSA public API.
 */
import { webcrypto } from 'crypto';
import { Q } from './params.js';
import { ntruKeygen } from './ntru.js';
import { encodePk, encodeSk } from './encode.js';
import { polyMulNtt, polyInvNtt } from './ntt.js';
import { signInternal } from './sign.js';
import { verify as _verify } from './verify.js';

function defaultRng(n) {
  const buf = new Uint8Array(n);
  webcrypto.getRandomValues(buf);
  return buf;
}

export function keyGen(params, rng = null) {
  const rngFn = rng || defaultRng;

  const { f, g, F } = ntruKeygen(params, rngFn);

  // Compute h = g * f^{-1} mod q via NTT
  const n = params.n;
  const fModQ = Array.from(f).map(v => ((v % Q) + Q) % Q);
  const gModQ = Array.from(g).map(v => ((v % Q) + Q) % Q);

  const fInv = polyInvNtt(fModQ, n);
  const h = polyMulNtt(gModQ, Array.from(fInv), n);

  const pk = encodePk(h, params);
  const sk = encodeSk(f, g, F, params);
  return [pk, sk];
}

export function sign(sk, msg, params, rng = null) {
  const rngFn = rng || defaultRng;
  return signInternal(sk, msg, params, rngFn);
}

export function verify(pk, msg, sig, params) {
  return _verify(pk, msg, sig, params);
}
