/**
 * FN-DSA verification (FIPS 206 Algorithm 4).
 * Port of Python verify.py.
 */
import { Q } from './params.js';
import { decodePk, decodeSig } from './encode.js';
import { polyMulNtt } from './ntt.js';
import { hashToPoint } from './sign.js';

function centerModQ(v) {
  v = ((v % Q) + Q) % Q;
  if (v > (Q >> 1)) v -= Q;
  return v;
}

function normSq(s1, s2) {
  let sum = 0;
  for (const v of s1) sum += v * v;
  for (const v of s2) sum += v * v;
  return sum;
}

export function verify(pk, msg, sig, params) {
  // 1. Decode and validate public key
  const pkData = pk instanceof Uint8Array ? pk : new Uint8Array(pk);
  const h = decodePk(pkData, params);
  if (h === null) return false;

  // 2. Decode and validate signature
  const sigData = sig instanceof Uint8Array ? sig : new Uint8Array(sig);
  const decoded = decodeSig(sigData, params);
  if (decoded === null) return false;
  const { salt, s1 } = decoded;

  // 3. Recompute c = HashToPoint(salt || msg)
  const msgBuf = msg instanceof Uint8Array ? msg : Buffer.from(msg);
  const hashInput = new Uint8Array(40 + msgBuf.length);
  hashInput.set(salt, 0);
  hashInput.set(msgBuf, 40);
  const c = hashToPoint(hashInput, params);

  // 4. Compute s2 = c - s1*h (mod q), centered in (-Q/2, Q/2]
  const n = params.n;
  const s1ModQ = Array.from(s1).map(v => ((v % Q) + Q) % Q);
  const s1h = polyMulNtt(s1ModQ, Array.from(h), n);
  const s2 = new Array(n);
  for (let i = 0; i < n; i++) {
    s2[i] = centerModQ(c[i] - s1h[i]);
  }

  // 5. Norm check: ||(s1, s2)||^2 <= beta^2
  return normSq(Array.from(s1), s2) <= params.betaSq;
}
