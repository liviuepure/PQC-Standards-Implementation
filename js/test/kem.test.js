/**
 * ML-KEM (FIPS 203) Tests
 * Uses Node.js built-in test runner and assertion library.
 */

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { keyGen, encaps, decaps, ML_KEM_512, ML_KEM_768, ML_KEM_1024 } from '../src/index.js';

const paramSets = [
  { name: 'ML-KEM-512', params: ML_KEM_512 },
  { name: 'ML-KEM-768', params: ML_KEM_768 },
  { name: 'ML-KEM-1024', params: ML_KEM_1024 },
];

describe('ML-KEM round-trip', () => {
  for (const { name, params } of paramSets) {
    it(`${name}: encaps/decaps produce matching shared secrets`, () => {
      const { ek, dk } = keyGen(params);
      const { K: K1, c } = encaps(ek, params);
      const K2 = decaps(dk, c, params);

      assert.equal(K1.length, 32, 'encaps shared secret should be 32 bytes');
      assert.equal(K2.length, 32, 'decaps shared secret should be 32 bytes');
      assert.deepStrictEqual(K2, K1, 'shared secrets must match');
    });
  }
});

describe('ML-KEM implicit rejection', () => {
  for (const { name, params } of paramSets) {
    it(`${name}: wrong ciphertext yields different key (implicit rejection)`, () => {
      const { ek, dk } = keyGen(params);
      const { K: K1, c } = encaps(ek, params);

      // Tamper with ciphertext
      const cBad = new Uint8Array(c);
      cBad[0] ^= 0xFF;
      cBad[1] ^= 0xFF;
      cBad[c.length - 1] ^= 0xFF;

      const K2 = decaps(dk, cBad, params);
      assert.equal(K2.length, 32, 'rejection key should be 32 bytes');

      // The key should differ from the real shared secret
      let same = true;
      for (let i = 0; i < 32; i++) {
        if (K1[i] !== K2[i]) { same = false; break; }
      }
      assert.equal(same, false, 'tampered ciphertext must produce a different key');
    });
  }
});

describe('ML-KEM encapsulation key validation', () => {
  for (const { name, params } of paramSets) {
    it(`${name}: tampered ek is rejected or produces mismatched keys`, () => {
      const { ek, dk } = keyGen(params);

      // Tamper with the ek to make a coefficient >= Q
      // Byte-encode12: each coefficient is 12 bits. Set 12 bits to 0xFFF = 4095 > 3329
      const ekBad = new Uint8Array(ek);
      // Overwrite first 3 bytes (2 coefficients in 12-bit encoding)
      // to create values >= Q. Setting bytes to 0xFF makes both 12-bit values = 4095.
      ekBad[0] = 0xFF;
      ekBad[1] = 0xFF;
      ekBad[2] = 0xFF;

      let rejected = false;
      try {
        encaps(ekBad, params);
      } catch (e) {
        rejected = true;
        assert.match(e.message, /invalid/, 'should mention invalid key');
      }
      assert.equal(rejected, true, 'tampered ek should be rejected');
    });
  }
});

describe('ML-KEM consistency', () => {
  it('multiple round-trips with ML-KEM-768 all succeed', () => {
    const params = ML_KEM_768;
    const { ek, dk } = keyGen(params);
    for (let trial = 0; trial < 3; trial++) {
      const { K: K1, c } = encaps(ek, params);
      const K2 = decaps(dk, c, params);
      assert.deepStrictEqual(K2, K1, `trial ${trial}: shared secrets must match`);
    }
  });
});
