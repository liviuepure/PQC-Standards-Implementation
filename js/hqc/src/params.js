/**
 * HQC parameter sets.
 *
 * HQC is a code-based key encapsulation mechanism selected by NIST for
 * post-quantum cryptography standardization.
 */

/** Seed size for key generation (bytes). */
export const SEED_BYTES = 40;

/** Size of d = H(m) included in ciphertext (SHAKE-256 output, bytes). */
export const HASH_BYTES = 64;

/** Shared secret size (SHAKE-256 output, bytes). */
export const SHARED_SECRET_BYTES = 64;

/** Domain separation bytes for SHAKE-256 hashing. */
export const G_FCT_DOMAIN = 3; // theta = G(m || pk || salt)
export const H_FCT_DOMAIN = 4; // d = H(m)
export const K_FCT_DOMAIN = 5; // ss = K(m || ct)

/**
 * @typedef {Object} HQCParams
 * @property {string} name
 * @property {number} n       - ring dimension
 * @property {number} n1      - RS codeword length
 * @property {number} n2      - RM codeword length (with repetitions)
 * @property {number} n1n2    - concatenated code length in bits = n1 * n2
 * @property {number} k       - message size in bytes (RS information symbols)
 * @property {number} delta   - RS error correction capability
 * @property {number} g       - RS generator polynomial degree = 2*delta + 1
 * @property {number} w       - weight of secret key vectors x, y
 * @property {number} wr      - weight of encryption vectors r1, r2
 * @property {number} we      - weight of ephemeral error vector e
 * @property {number} pkSize  - public key size in bytes
 * @property {number} skSize  - secret key size in bytes
 * @property {number} ctSize  - ciphertext size in bytes
 * @property {number} ssSize  - shared secret size in bytes
 * @property {number} vecNSize64      - ceil(n / 32) -- Uint32Array word count
 * @property {number} vecNSizeBytes   - ceil(n / 8)
 * @property {number} vecN1N2Size64   - ceil(n1n2 / 32) -- Uint32Array word count
 * @property {number} vecN1N2SizeBytes
 * @property {number} vecKSizeBytes
 * @property {number} gfPoly     - irreducible polynomial for GF(2^8)
 * @property {number} gfMulOrder - multiplicative order = 255
 * @property {number} rmOrder    - RM(1, rmOrder)
 * @property {number} multiplicity - number of repetitions: n2 / 128
 */

/** @type {HQCParams} */
export const HQC128 = Object.freeze({
  name: 'HQC-128',
  n: 17669,
  n1: 46,
  n2: 384,
  n1n2: 17664,
  k: 16,
  delta: 15,
  g: 31,
  w: 66,
  wr: 77,
  we: 77,
  pkSize: 2249,
  skSize: 2289,
  ctSize: 4481,
  ssSize: SHARED_SECRET_BYTES,
  vecNSize64: 554,      // ceil(17669/32) -- 32-bit words
  vecNSizeBytes: 2209,
  vecN1N2Size64: 552,   // ceil(17664/32)
  vecN1N2SizeBytes: 2208,
  vecKSizeBytes: 16,
  gfPoly: 0x11D,
  gfMulOrder: 255,
  rmOrder: 7,
  multiplicity: 3,
});

/** @type {HQCParams} */
export const HQC192 = Object.freeze({
  name: 'HQC-192',
  n: 35851,
  n1: 56,
  n2: 640,
  n1n2: 35840,
  k: 24,
  delta: 16,
  g: 33,
  w: 100,
  wr: 117,
  we: 117,
  pkSize: 4522,
  skSize: 4562,
  ctSize: 9026,
  ssSize: SHARED_SECRET_BYTES,
  vecNSize64: 1122,     // ceil(35851/32)
  vecNSizeBytes: 4482,
  vecN1N2Size64: 1120,  // ceil(35840/32)
  vecN1N2SizeBytes: 4480,
  vecKSizeBytes: 24,
  gfPoly: 0x11D,
  gfMulOrder: 255,
  rmOrder: 7,
  multiplicity: 5,
});

/** @type {HQCParams} */
export const HQC256 = Object.freeze({
  name: 'HQC-256',
  n: 57637,
  n1: 90,
  n2: 640,
  n1n2: 57600,
  k: 32,
  delta: 29,
  g: 59,
  w: 131,
  wr: 153,
  we: 153,
  pkSize: 7245,
  skSize: 7285,
  ctSize: 14469,
  ssSize: SHARED_SECRET_BYTES,
  vecNSize64: 1802,     // ceil(57637/32)
  vecNSizeBytes: 7205,
  vecN1N2Size64: 1800,  // ceil(57600/32)
  vecN1N2SizeBytes: 7200,
  vecKSizeBytes: 32,
  gfPoly: 0x11D,
  gfMulOrder: 255,
  rmOrder: 7,
  multiplicity: 5,
});

/** All supported parameter sets. */
export const ALL_PARAMS = [HQC128, HQC192, HQC256];
