/**
 * HQC KEM tests.
 */

import { keyGen, encaps, decaps, HQC128, HQC192, HQC256, ALL_PARAMS } from '../src/index.js';

describe('HQC KEM', () => {
  describe('HQC-128 roundtrip', () => {
    test('encaps/decaps produces matching shared secret', () => {
      const p = HQC128;
      const { publicKey, secretKey } = keyGen(p);

      expect(publicKey.length).toBe(p.pkSize);
      expect(secretKey.length).toBe(p.skSize);

      const { ciphertext, sharedSecret: ss1 } = encaps(publicKey, p);

      expect(ciphertext.length).toBe(p.ctSize);
      expect(ss1.length).toBe(p.ssSize);

      const ss2 = decaps(secretKey, ciphertext, p);

      expect(ss2.length).toBe(p.ssSize);
      expect(Buffer.from(ss1).equals(Buffer.from(ss2))).toBe(true);
    });

    test('corrupted ciphertext yields different shared secret', () => {
      const p = HQC128;
      const { publicKey, secretKey } = keyGen(p);
      const { ciphertext, sharedSecret: ss1 } = encaps(publicKey, p);

      // Corrupt the ciphertext
      const badCt = new Uint8Array(ciphertext);
      badCt[0] ^= 0xFF;
      badCt[1] ^= 0xFF;

      const ss2 = decaps(secretKey, badCt, p);

      expect(Buffer.from(ss1).equals(Buffer.from(ss2))).toBe(false);
    });

    test('multiple roundtrips all succeed', () => {
      const p = HQC128;
      for (let trial = 0; trial < 5; trial++) {
        const { publicKey, secretKey } = keyGen(p);
        const { ciphertext, sharedSecret: ss1 } = encaps(publicKey, p);
        const ss2 = decaps(secretKey, ciphertext, p);

        expect(Buffer.from(ss1).equals(Buffer.from(ss2))).toBe(true);
      }
    });
  });

  // Optional: HQC-192 and HQC-256 (slower due to larger parameters)
  describe.each([
    ['HQC-192', HQC192],
    ['HQC-256', HQC256],
  ])('%s roundtrip', (name, p) => {
    test('encaps/decaps produces matching shared secret', () => {
      const { publicKey, secretKey } = keyGen(p);

      expect(publicKey.length).toBe(p.pkSize);
      expect(secretKey.length).toBe(p.skSize);

      const { ciphertext, sharedSecret: ss1 } = encaps(publicKey, p);

      expect(ciphertext.length).toBe(p.ctSize);
      expect(ss1.length).toBe(p.ssSize);

      const ss2 = decaps(secretKey, ciphertext, p);

      expect(Buffer.from(ss1).equals(Buffer.from(ss2))).toBe(true);
    });
  });
});
