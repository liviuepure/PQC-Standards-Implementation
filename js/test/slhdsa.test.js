import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import * as slhdsa from '../src/slhdsa/index.js';

describe('SLH-DSA (FIPS 205)', () => {
  const params = slhdsa.SLH_DSA_SHAKE_128f;

  describe('Key Generation', () => {
    it('should generate keys of correct length', () => {
      const { sk, pk } = slhdsa.keyGen(params);
      assert.equal(sk.length, params.skLen, `SK should be ${params.skLen} bytes`);
      assert.equal(pk.length, params.pkLen, `PK should be ${params.pkLen} bytes`);
    });
  });

  describe('Sign and Verify (roundtrip)', () => {
    it('should sign and verify a message correctly', () => {
      const { sk, pk } = slhdsa.keyGen(params);
      const msg = new Uint8Array(Buffer.from('Hello, SLH-DSA!'));
      const sig = slhdsa.sign(msg, sk, params);

      assert.equal(sig.length, params.sig, `Signature should be ${params.sig} bytes`);

      const valid = slhdsa.verify(msg, sig, pk, params);
      assert.equal(valid, true, 'Signature should verify successfully');
    });

    it('should produce correct signature size', () => {
      const { sk } = slhdsa.keyGen(params);
      const msg = new Uint8Array([1, 2, 3, 4, 5]);
      const sig = slhdsa.sign(msg, sk, params);
      assert.equal(sig.length, 17088, 'SHAKE-128f signature should be 17088 bytes');
    });
  });

  describe('Reject tampered signatures', () => {
    it('should reject a tampered signature', () => {
      const { sk, pk } = slhdsa.keyGen(params);
      const msg = new Uint8Array(Buffer.from('Test message'));
      const sig = slhdsa.sign(msg, sk, params);

      const tampered = new Uint8Array(sig);
      tampered[100] ^= 0xff;

      const valid = slhdsa.verify(msg, tampered, pk, params);
      assert.equal(valid, false, 'Tampered signature should be rejected');
    });

    it('should reject a signature for wrong message', () => {
      const { sk, pk } = slhdsa.keyGen(params);
      const msg1 = new Uint8Array(Buffer.from('Original message'));
      const msg2 = new Uint8Array(Buffer.from('Different message'));
      const sig = slhdsa.sign(msg1, sk, params);

      const valid = slhdsa.verify(msg2, sig, pk, params);
      assert.equal(valid, false, 'Signature for wrong message should be rejected');
    });

    it('should reject a signature with wrong public key', () => {
      const kp1 = slhdsa.keyGen(params);
      const kp2 = slhdsa.keyGen(params);
      const msg = new Uint8Array(Buffer.from('Test'));
      const sig = slhdsa.sign(msg, kp1.sk, params);

      const valid = slhdsa.verify(msg, sig, kp2.pk, params);
      assert.equal(valid, false, 'Signature with wrong PK should be rejected');
    });
  });

  describe('Parameter sets', () => {
    it('should have all 12 parameter sets defined', () => {
      const names = Object.keys(slhdsa.PARAMS);
      assert.equal(names.length, 12, 'Should have 12 parameter sets');
    });

    it('should have correct SHAKE-128f parameters', () => {
      const p = slhdsa.PARAMS['SLH-DSA-SHAKE-128f'];
      assert.equal(p.n, 16);
      assert.equal(p.h, 66);
      assert.equal(p.d, 22);
      assert.equal(p.hp, 3);
      assert.equal(p.a, 6);
      assert.equal(p.k, 33);
      assert.equal(p.w, 16);
      assert.equal(p.len, 35);
      assert.equal(p.sig, 17088);
    });
  });

  describe('Deterministic signing', () => {
    it('should produce the same signature with same inputs (deterministic mode)', () => {
      const { sk } = slhdsa.keyGen(params);
      const msg = new Uint8Array(Buffer.from('Deterministic test'));

      const sig1 = slhdsa.sign(msg, sk, params, null);
      const sig2 = slhdsa.sign(msg, sk, params, null);

      assert.deepEqual(sig1, sig2, 'Deterministic signatures should be identical');
    });
  });
});
