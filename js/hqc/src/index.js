/**
 * HQC (Hamming Quasi-Cyclic) KEM - JavaScript implementation.
 *
 * A code-based key encapsulation mechanism selected by NIST for
 * post-quantum cryptography standardization.
 */

export { keyGen, encaps, decaps } from './kem.js';
export { HQC128, HQC192, HQC256, ALL_PARAMS } from './params.js';
