/**
 * Tests for ML-DSA (FIPS 204) implementation
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { Q, modQ, fieldAdd, fieldSub, fieldMul } from '../src/mldsa/field.js';
import { ntt, invNtt, pointwiseMul, ZETAS } from '../src/mldsa/ntt.js';
import { power2Round, decompose, highBits, lowBits, makeHint, useHint } from '../src/mldsa/decompose.js';
import { keyGen, sign, verify, ML_DSA_44, ML_DSA_65, ML_DSA_87 } from '../src/mldsa/index.js';

describe('ML-DSA Field Arithmetic', () => {
  it('modQ produces values in [0, Q)', () => {
    assert.equal(modQ(0), 0);
    assert.equal(modQ(Q), 0);
    assert.equal(modQ(-1), Q - 1);
    assert.equal(modQ(Q + 5), 5);
  });

  it('fieldAdd is correct', () => {
    assert.equal(fieldAdd(Q - 1, 1), 0);
    assert.equal(fieldAdd(100, 200), 300);
  });

  it('fieldSub is correct', () => {
    assert.equal(fieldSub(0, 1), Q - 1);
    assert.equal(fieldSub(200, 100), 100);
  });

  it('fieldMul is correct', () => {
    assert.equal(fieldMul(0, 1234), 0);
    assert.equal(fieldMul(1, 5678), 5678);
    // Check product stays in range
    const a = Q - 1;
    const b = Q - 1;
    const result = fieldMul(a, b);
    assert.ok(result >= 0 && result < Q);
    assert.equal(result, (a * b) % Q);
  });
});

describe('ML-DSA NTT', () => {
  it('ZETAS[0] is 1 (zeta^0 = 1)', () => {
    assert.equal(ZETAS[0], 1);
  });

  it('NTT round-trip preserves polynomial', () => {
    const poly = new Int32Array(256);
    for (let i = 0; i < 256; i++) {
      poly[i] = i % Q;
    }
    const original = Int32Array.from(poly);

    ntt(poly);
    invNtt(poly);

    for (let i = 0; i < 256; i++) {
      assert.equal(poly[i], original[i], `Mismatch at index ${i}`);
    }
  });

  it('NTT round-trip with random-ish values', () => {
    const poly = new Int32Array(256);
    let seed = 12345;
    for (let i = 0; i < 256; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
      poly[i] = seed % Q;
    }
    const original = Int32Array.from(poly);

    ntt(poly);
    invNtt(poly);

    for (let i = 0; i < 256; i++) {
      assert.equal(poly[i], original[i], `Mismatch at index ${i}`);
    }
  });

  it('pointwiseMul is element-wise', () => {
    const a = new Int32Array(256).fill(2);
    const b = new Int32Array(256).fill(3);
    const c = pointwiseMul(a, b);
    for (let i = 0; i < 256; i++) {
      assert.equal(c[i], 6);
    }
  });
});

describe('ML-DSA Decompose', () => {
  it('power2Round identity: r1*2^d + r0 = r mod Q', () => {
    const d = 13;
    const testValues = [0, 1, Q - 1, 4096, 8191, 100000, Q / 2 | 0];
    for (const r of testValues) {
      const rMod = modQ(r);
      const [r1, r0] = power2Round(rMod);
      const reconstructed = modQ(r1 * (1 << d) + r0);
      assert.equal(reconstructed, rMod, `power2Round failed for r=${rMod}`);
    }
  });

  it('decompose identity for gamma2=95232', () => {
    const alpha = 2 * 95232;
    const testValues = [0, 1, Q - 1, 100000, Q / 2 | 0];
    for (const r of testValues) {
      const rMod = modQ(r);
      const [r1, r0] = decompose(rMod, alpha);
      const reconstructed = modQ(r1 * alpha + r0);
      assert.equal(reconstructed, rMod, `decompose failed for r=${rMod}`);
    }
  });

  it('decompose identity for gamma2=261888', () => {
    const alpha = 2 * 261888;
    const testValues = [0, 1, Q - 1, 300000, Q / 2 | 0];
    for (const r of testValues) {
      const rMod = modQ(r);
      const [r1, r0] = decompose(rMod, alpha);
      const reconstructed = modQ(r1 * alpha + r0);
      assert.equal(reconstructed, rMod, `decompose failed for r=${rMod}`);
    }
  });

  it('hint round-trip: useHint recovers correct highBits', () => {
    const alpha = 2 * 95232;
    const testValues = [0, 1, Q - 1, 100000, alpha, alpha + 1];
    for (const r of testValues) {
      const rMod = modQ(r);
      const z = 1000;
      const rPlusZ = modQ(rMod + z);
      const hint = makeHint(z, rMod, alpha);
      const recovered = useHint(hint, rMod, alpha);
      const expected = highBits(rPlusZ, alpha);
      assert.equal(recovered, expected, `hint round-trip failed for r=${rMod}, z=${z}`);
    }
  });
});

describe('ML-DSA KeyGen', () => {
  it('ML-DSA-44 produces correct key sizes', () => {
    const { pk, sk } = keyGen(ML_DSA_44);
    assert.equal(pk.length, ML_DSA_44.pkSize, `PK size: expected ${ML_DSA_44.pkSize}, got ${pk.length}`);
    assert.equal(sk.length, ML_DSA_44.skSize, `SK size: expected ${ML_DSA_44.skSize}, got ${sk.length}`);
  });

  it('ML-DSA-65 produces correct key sizes', () => {
    const { pk, sk } = keyGen(ML_DSA_65);
    assert.equal(pk.length, ML_DSA_65.pkSize, `PK size: expected ${ML_DSA_65.pkSize}, got ${pk.length}`);
    assert.equal(sk.length, ML_DSA_65.skSize, `SK size: expected ${ML_DSA_65.skSize}, got ${sk.length}`);
  });

  it('ML-DSA-87 produces correct key sizes', () => {
    const { pk, sk } = keyGen(ML_DSA_87);
    assert.equal(pk.length, ML_DSA_87.pkSize, `PK size: expected ${ML_DSA_87.pkSize}, got ${pk.length}`);
    assert.equal(sk.length, ML_DSA_87.skSize, `SK size: expected ${ML_DSA_87.skSize}, got ${sk.length}`);
  });
});

describe('ML-DSA Sign/Verify', () => {
  it('ML-DSA-44 sign/verify round-trip', () => {
    const { pk, sk } = keyGen(ML_DSA_44);
    const msg = new TextEncoder().encode('Hello, ML-DSA-44!');
    const sig = sign(sk, msg, ML_DSA_44);
    assert.ok(sig.length <= ML_DSA_44.sigSize, `Sig too large: ${sig.length} > ${ML_DSA_44.sigSize}`);
    const valid = verify(pk, msg, sig, ML_DSA_44);
    assert.ok(valid, 'Signature should be valid');
  });

  it('ML-DSA-65 sign/verify round-trip', () => {
    const { pk, sk } = keyGen(ML_DSA_65);
    const msg = new TextEncoder().encode('Hello, ML-DSA-65!');
    const sig = sign(sk, msg, ML_DSA_65);
    assert.ok(sig.length <= ML_DSA_65.sigSize, `Sig too large: ${sig.length} > ${ML_DSA_65.sigSize}`);
    const valid = verify(pk, msg, sig, ML_DSA_65);
    assert.ok(valid, 'Signature should be valid');
  });

  it('ML-DSA-87 sign/verify round-trip', () => {
    const { pk, sk } = keyGen(ML_DSA_87);
    const msg = new TextEncoder().encode('Hello, ML-DSA-87!');
    const sig = sign(sk, msg, ML_DSA_87);
    assert.ok(sig.length <= ML_DSA_87.sigSize, `Sig too large: ${sig.length} > ${ML_DSA_87.sigSize}`);
    const valid = verify(pk, msg, sig, ML_DSA_87);
    assert.ok(valid, 'Signature should be valid');
  });
});

describe('ML-DSA Verification Rejects Invalid', () => {
  it('rejects tampered signature', () => {
    const { pk, sk } = keyGen(ML_DSA_44);
    const msg = new TextEncoder().encode('Test message');
    const sig = sign(sk, msg, ML_DSA_44);

    // Tamper with signature
    const tampered = Uint8Array.from(sig);
    tampered[10] ^= 0xFF;
    const valid = verify(pk, msg, tampered, ML_DSA_44);
    assert.ok(!valid, 'Tampered signature should be rejected');
  });

  it('rejects wrong message', () => {
    const { pk, sk } = keyGen(ML_DSA_44);
    const msg = new TextEncoder().encode('Original message');
    const sig = sign(sk, msg, ML_DSA_44);

    const wrongMsg = new TextEncoder().encode('Wrong message');
    const valid = verify(pk, wrongMsg, sig, ML_DSA_44);
    assert.ok(!valid, 'Wrong message should be rejected');
  });

  it('rejects signature from wrong key', () => {
    const keys1 = keyGen(ML_DSA_44);
    const keys2 = keyGen(ML_DSA_44);
    const msg = new TextEncoder().encode('Test');
    const sig = sign(keys1.sk, msg, ML_DSA_44);
    const valid = verify(keys2.pk, msg, sig, ML_DSA_44);
    assert.ok(!valid, 'Signature from wrong key should be rejected');
  });
});

describe('ML-DSA Deterministic Signing', () => {
  it('deterministic signing produces same signature', () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = i;
    const { pk, sk } = keyGen(ML_DSA_44, seed);

    const msg = new TextEncoder().encode('Deterministic test');
    const rnd = new Uint8Array(32); // zeros for deterministic

    const sig1 = sign(sk, msg, ML_DSA_44, rnd);
    const sig2 = sign(sk, msg, ML_DSA_44, rnd);

    assert.deepEqual(sig1, sig2, 'Deterministic signatures should match');
    assert.ok(verify(pk, msg, sig1, ML_DSA_44), 'Signature should verify');
  });
});
