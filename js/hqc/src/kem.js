/**
 * HQC KEM: KeyGen, Encapsulation, Decapsulation.
 *
 * Uses SHAKE-256 (via Node.js crypto) for hashing and seed expansion.
 * Implements Fujisaki-Okeyama transform for CCA security.
 */

import { createHash, randomBytes } from 'crypto';
import {
  vectAdd, vectMul, vectResize, vectToBytes, vectFromBytes,
  vectSetBit, vectEqual, vectAlloc,
} from './gf2.js';
import { tensorEncode, tensorDecode } from './tensor.js';
import {
  SEED_BYTES, SHARED_SECRET_BYTES,
  G_FCT_DOMAIN, H_FCT_DOMAIN, K_FCT_DOMAIN,
} from './params.js';

/**
 * SHAKE-256 seed expander.
 * Wraps a SHAKE-256 instance for sequential reads.
 */
class SeedExpander {
  constructor(seed) {
    this._hash = createHash('shake256', { outputLength: 1 << 20 });
    this._hash.update(seed);
    this._buf = this._hash.digest();
    this._pos = 0;
  }

  /**
   * Read n bytes from the expander.
   * @param {number} n
   * @returns {Uint8Array}
   */
  read(n) {
    if (this._pos + n > this._buf.length) {
      // Need to extend - create a new expander with more output
      // This should never happen in practice with 1MB buffer
      throw new Error('SeedExpander: buffer exhausted');
    }
    const out = new Uint8Array(this._buf.buffer, this._buf.byteOffset + this._pos, n);
    this._pos += n;
    return out;
  }
}

/**
 * SHAKE-256 hash function.
 * @param {Uint8Array[]} inputs - data to hash
 * @param {number} outputLen - desired output length
 * @returns {Uint8Array}
 */
function shake256(inputs, outputLen) {
  const h = createHash('shake256', { outputLength: outputLen });
  for (const input of inputs) {
    h.update(input);
  }
  return new Uint8Array(h.digest());
}

/**
 * Generate a random vector of n bits using the seed expander.
 * @param {SeedExpander} se
 * @param {number} n
 * @returns {Uint32Array}
 */
function vectSetRandom(se, n) {
  const nWords = Math.ceil(n / 32);
  const nBytes = nWords * 4;
  const buf = se.read(nBytes);
  const v = vectFromBytes(buf, nWords);
  const rem = n & 31;
  if (rem !== 0) {
    v[nWords - 1] &= (1 << rem) - 1;
  }
  return v;
}

/**
 * Generate a random vector of n bits with exactly 'weight' bits set.
 * Uses rejection sampling from the seed expander.
 * @param {SeedExpander} se
 * @param {number} n
 * @param {number} weight
 * @returns {Uint32Array}
 */
function vectSetRandomFixedWeight(se, n, weight) {
  const nWords = Math.ceil(n / 32);
  const v = new Uint32Array(nWords);
  const positions = new Uint32Array(weight);

  for (let i = 0; i < weight; i++) {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const buf = se.read(4);
      let pos = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
      pos = (pos >>> 0) % n;

      // Check for duplicates (rejection sampling)
      let duplicate = false;
      for (let j = 0; j < i; j++) {
        if (positions[j] === pos) {
          duplicate = true;
          break;
        }
      }
      if (!duplicate) {
        positions[i] = pos;
        break;
      }
    }
  }

  for (let i = 0; i < weight; i++) {
    vectSetBit(v, positions[i]);
  }

  return v;
}

/**
 * Compute d = SHAKE256(H_domain || m), 64 bytes.
 * @param {Uint8Array} m
 * @returns {Uint8Array}
 */
function computeD(m) {
  return shake256([new Uint8Array([H_FCT_DOMAIN]), m], SHARED_SECRET_BYTES);
}

/**
 * Compute theta = SHAKE256(G_domain || m || pk || d), SEED_BYTES bytes.
 * @param {Uint8Array} m
 * @param {Uint8Array} pk
 * @param {Uint8Array} d
 * @returns {Uint8Array}
 */
function computeTheta(m, pk, d) {
  return shake256(
    [new Uint8Array([G_FCT_DOMAIN]), m, pk, d],
    SEED_BYTES,
  );
}

/**
 * Compute ss = SHAKE256(K_domain || m || u_bytes || v_bytes), 64 bytes.
 * @param {Uint8Array} m
 * @param {Uint32Array} u
 * @param {Uint32Array} v
 * @param {import('./params.js').HQCParams} p
 * @returns {Uint8Array}
 */
function computeSS(m, u, v, p) {
  return shake256(
    [
      new Uint8Array([K_FCT_DOMAIN]),
      m,
      vectToBytes(u, p.vecNSizeBytes),
      vectToBytes(v, p.vecN1N2SizeBytes),
    ],
    SHARED_SECRET_BYTES,
  );
}

/**
 * PKE Encrypt.
 * @param {Uint8Array} m - message
 * @param {Uint8Array} theta - randomness seed
 * @param {Uint8Array} pk - public key
 * @param {import('./params.js').HQCParams} p
 * @returns {[Uint32Array, Uint32Array]} [u, v]
 */
function pkeEncrypt(m, theta, pk, p) {
  // Parse public key
  const pkSeed = pk.subarray(0, SEED_BYTES);
  const s = vectFromBytes(pk.subarray(SEED_BYTES), p.vecNSize64);

  // Generate h from pk_seed
  const pkExpander = new SeedExpander(pkSeed);
  const h = vectSetRandom(pkExpander, p.n);

  // Generate r1, r2 with weight WR and e with weight WE from theta
  const thetaExpander = new SeedExpander(theta);
  const r1 = vectSetRandomFixedWeight(thetaExpander, p.n, p.wr);
  const r2 = vectSetRandomFixedWeight(thetaExpander, p.n, p.wr);
  const e = vectSetRandomFixedWeight(thetaExpander, p.n, p.we);

  // u = r1 + h * r2 mod (x^n - 1)
  const hr2 = vectMul(h, r2, p.n);
  let u = vectAdd(hr2, r1);
  u = vectResize(u, p.n);

  // v = encode(m) + s * r2 + e (in GF(2)^{n1*n2})
  const encoded = tensorEncode(m, p);

  // s * r2 in the ring, then truncate to n1*n2 bits
  const sr2 = vectMul(s, r2, p.n);
  const sr2Trunc = new Uint32Array(p.vecN1N2Size64);
  const copyLen = Math.min(sr2.length, p.vecN1N2Size64);
  for (let i = 0; i < copyLen; i++) sr2Trunc[i] = sr2[i];
  if (p.n1n2 % 32 !== 0 && p.vecN1N2Size64 > 0) {
    sr2Trunc[p.vecN1N2Size64 - 1] &= (1 << (p.n1n2 % 32)) - 1;
  }

  // Resize e to n1*n2
  const eResized = new Uint32Array(p.vecN1N2Size64);
  const copyE = Math.min(e.length, p.vecN1N2Size64);
  for (let i = 0; i < copyE; i++) eResized[i] = e[i];
  if (p.n1n2 % 32 !== 0 && p.vecN1N2Size64 > 0) {
    eResized[p.vecN1N2Size64 - 1] &= (1 << (p.n1n2 % 32)) - 1;
  }

  let v = vectAdd(encoded, sr2Trunc);
  v = vectAdd(v, eResized);
  v = vectResize(v, p.n1n2);

  return [u, v];
}

/**
 * Generate an HQC key pair.
 * @param {import('./params.js').HQCParams} p
 * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
 */
export function keyGen(p) {
  // Generate random seeds
  const skSeed = randomBytes(SEED_BYTES);
  const pkSeed = randomBytes(SEED_BYTES);

  // Generate secret vectors x, y from sk_seed
  const skExpander = new SeedExpander(skSeed);
  const x = vectSetRandomFixedWeight(skExpander, p.n, p.w);
  const y = vectSetRandomFixedWeight(skExpander, p.n, p.w);

  // Generate random vector h from pk_seed
  const pkExpander = new SeedExpander(pkSeed);
  const h = vectSetRandom(pkExpander, p.n);

  // Compute s = x + h * y mod (x^n - 1)
  const hy = vectMul(h, y, p.n);
  let s = vectAdd(hy, x);
  s = vectResize(s, p.n);

  // Serialize public key: [pk_seed (40 bytes)] [s (VecNSizeBytes bytes)]
  const pk = new Uint8Array(p.pkSize);
  pk.set(skSeed.subarray(0, 0)); // no-op, just showing structure
  pk.set(new Uint8Array(pkSeed), 0);
  pk.set(vectToBytes(s, p.vecNSizeBytes), SEED_BYTES);

  // Serialize secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
  const sk = new Uint8Array(p.skSize);
  sk.set(new Uint8Array(skSeed));
  sk.set(pk, SEED_BYTES);

  return { publicKey: pk, secretKey: sk };
}

/**
 * Encapsulate a shared secret using the public key.
 * @param {Uint8Array} pk
 * @param {import('./params.js').HQCParams} p
 * @returns {{ciphertext: Uint8Array, sharedSecret: Uint8Array}}
 */
export function encaps(pk, p) {
  // Generate random message m
  const m = randomBytes(p.vecKSizeBytes);

  // Compute d = H(m)
  const d = computeD(new Uint8Array(m));

  // Compute theta
  const theta = computeTheta(new Uint8Array(m), pk, d);

  // PKE Encrypt
  const [u, v] = pkeEncrypt(new Uint8Array(m), theta, pk, p);

  // Compute shared secret
  const ss = computeSS(new Uint8Array(m), u, v, p);

  // Serialize ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
  const ct = new Uint8Array(p.ctSize);
  ct.set(vectToBytes(u, p.vecNSizeBytes));
  ct.set(vectToBytes(v, p.vecN1N2SizeBytes), p.vecNSizeBytes);
  ct.set(d, p.vecNSizeBytes + p.vecN1N2SizeBytes);

  return { ciphertext: ct, sharedSecret: ss };
}

/**
 * Decapsulate a shared secret from a ciphertext using the secret key.
 * @param {Uint8Array} sk
 * @param {Uint8Array} ct
 * @param {import('./params.js').HQCParams} p
 * @returns {Uint8Array} sharedSecret (64 bytes)
 */
export function decaps(sk, ct, p) {
  // Parse secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
  const skSeed = sk.subarray(0, SEED_BYTES);
  const pk = sk.subarray(SEED_BYTES);

  // Parse ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
  const u = vectFromBytes(ct.subarray(0, p.vecNSizeBytes), p.vecNSize64);
  const v = vectFromBytes(
    ct.subarray(p.vecNSizeBytes, p.vecNSizeBytes + p.vecN1N2SizeBytes),
    p.vecN1N2Size64,
  );
  const d = ct.subarray(p.vecNSizeBytes + p.vecN1N2SizeBytes);

  // Regenerate secret vectors x, y and sigma from sk_seed
  const skExpander = new SeedExpander(skSeed);
  /* x = */ vectSetRandomFixedWeight(skExpander, p.n, p.w); // consume x
  const y = vectSetRandomFixedWeight(skExpander, p.n, p.w);
  // Generate sigma (rejection secret)
  const sigma = skExpander.read(p.vecKSizeBytes);

  // Compute v - u * y (which is v XOR u*y since we are in GF(2))
  const uy = vectMul(u, y, p.n);

  // Truncate uy to n1*n2 bits
  const uyTrunc = new Uint32Array(p.vecN1N2Size64);
  const copyLen = Math.min(uy.length, p.vecN1N2Size64);
  for (let i = 0; i < copyLen; i++) uyTrunc[i] = uy[i];
  if (p.n1n2 % 32 !== 0 && p.vecN1N2Size64 > 0) {
    uyTrunc[p.vecN1N2Size64 - 1] &= (1 << (p.n1n2 % 32)) - 1;
  }

  const vMinusUY = vectAdd(v, uyTrunc);

  // Decode using tensor product code
  let [mPrime, ok] = tensorDecode(vMinusUY, p);
  if (!ok) {
    // Decoding failed - use sigma as rejection value
    mPrime = new Uint8Array(p.vecKSizeBytes);
    mPrime.set(sigma);
  }

  // Re-encrypt to verify
  const thetaPrime = computeTheta(mPrime, pk, d);
  const [u2, v2] = pkeEncrypt(mPrime, thetaPrime, pk, p);

  // Constant-time comparison
  const u2Trunc = vectResize(u2, p.n);
  const uOrig = vectResize(u, p.n);
  const uMatch = vectEqual(u2Trunc, uOrig);

  const v2Trunc = vectResize(v2, p.n1n2);
  const vOrig = vectResize(v, p.n1n2);
  const vMatch = vectEqual(v2Trunc, vOrig);

  const match = uMatch & vMatch;

  // Constant-time selection of message or sigma
  const mc = new Uint8Array(p.vecKSizeBytes);
  const maskOK = (0 - match) & 0xFF;     // 0xFF if match, 0x00 otherwise
  const maskFail = (0 - (1 - match)) & 0xFF; // 0x00 if match, 0xFF otherwise
  for (let i = 0; i < p.vecKSizeBytes; i++) {
    mc[i] = (mPrime[i] & maskOK) | (sigma[i] & maskFail);
  }

  // Compute shared secret
  return computeSS(mc, u, v, p);
}
