import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  Q, mod, fieldAdd, fieldSub, fieldMul, fieldPow,
} from '../src/field.js';

import {
  bitRev7, ZETAS, ntt, nttInverse, multiplyNTTs,
} from '../src/ntt.js';

import { byteEncode, byteDecode } from '../src/encode.js';

import {
  compress, decompress, compressPoly, decompressPoly,
} from '../src/compress.js';

import { ML_KEM_512, ML_KEM_768, ML_KEM_1024 } from '../src/params.js';

// ---------------------------------------------------------------------------
// Field arithmetic
// ---------------------------------------------------------------------------
describe('Field arithmetic', () => {
  it('fieldAdd: basic addition mod Q', () => {
    assert.equal(fieldAdd(0, 0), 0);
    assert.equal(fieldAdd(1, 2), 3);
    assert.equal(fieldAdd(Q - 1, 1), 0);
    assert.equal(fieldAdd(Q - 1, Q - 1), Q - 2);
  });

  it('fieldSub: subtraction is always non-negative', () => {
    assert.equal(fieldSub(5, 3), 2);
    assert.equal(fieldSub(0, 1), Q - 1);
    assert.equal(fieldSub(0, 0), 0);
    assert.equal(fieldSub(1, Q - 1), 2);
  });

  it('fieldMul: multiplication mod Q', () => {
    assert.equal(fieldMul(0, 1000), 0);
    assert.equal(fieldMul(1, 42), 42);
    assert.equal(fieldMul(17, 17), (17 * 17) % Q);
    // Check larger product stays correct
    assert.equal(fieldMul(3328, 3328), (3328 * 3328) % Q);
  });

  it('fieldPow: modular exponentiation', () => {
    assert.equal(fieldPow(17, 0), 1);
    assert.equal(fieldPow(17, 1), 17);
    assert.equal(fieldPow(17, 2), (17 * 17) % Q);
    // Fermat's little theorem: a^(Q-1) = 1 mod Q for a != 0
    assert.equal(fieldPow(17, Q - 1), 1);
    assert.equal(fieldPow(42, Q - 1), 1);
    // 17^128 mod Q should be 3329-1 = 3328 (since 17 is a 256th root of unity,
    // 17^128 = -1 mod Q)
    assert.equal(fieldPow(17, 128), Q - 1);
  });

  it('mod: always positive result', () => {
    assert.equal(mod(-1, Q), Q - 1);
    assert.equal(mod(-Q, Q), 0);
    assert.equal(mod(Q, Q), 0);
    assert.equal(mod(5, Q), 5);
  });
});

// ---------------------------------------------------------------------------
// NTT
// ---------------------------------------------------------------------------
describe('NTT', () => {
  it('ZETAS are all in range [0, Q)', () => {
    for (let i = 0; i < 128; i++) {
      assert.ok(ZETAS[i] >= 0, `ZETAS[${i}] = ${ZETAS[i]} < 0`);
      assert.ok(ZETAS[i] < Q, `ZETAS[${i}] = ${ZETAS[i]} >= Q`);
    }
  });

  it('ZETAS[0] = 17^0 = 1', () => {
    assert.equal(ZETAS[0], 1);
  });

  it('bitRev7 is its own inverse', () => {
    for (let i = 0; i < 128; i++) {
      assert.equal(bitRev7(bitRev7(i)), i);
    }
  });

  it('NTT round-trip: nttInverse(ntt(f)) == f', () => {
    // Use a simple polynomial
    const f = new Array(256).fill(0);
    for (let i = 0; i < 256; i++) f[i] = i % Q;

    const fHat = ntt(f);
    const recovered = nttInverse(fHat);

    for (let i = 0; i < 256; i++) {
      assert.equal(recovered[i], f[i], `mismatch at index ${i}`);
    }
  });

  it('NTT round-trip with random-ish polynomial', () => {
    const f = new Array(256);
    // Deterministic pseudo-random using simple LCG
    let seed = 12345;
    for (let i = 0; i < 256; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      f[i] = seed % Q;
    }

    const recovered = nttInverse(ntt(f));
    for (let i = 0; i < 256; i++) {
      assert.equal(recovered[i], f[i], `mismatch at index ${i}`);
    }
  });

  it('multiplyNTTs: commutativity f*g == g*f', () => {
    const f = new Array(256);
    const g = new Array(256);
    let seed = 99999;
    for (let i = 0; i < 256; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      f[i] = seed % Q;
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      g[i] = seed % Q;
    }

    const fHat = ntt(f);
    const gHat = ntt(g);

    const fg = multiplyNTTs(fHat, gHat);
    const gf = multiplyNTTs(gHat, fHat);

    for (let i = 0; i < 256; i++) {
      assert.equal(fg[i], gf[i], `commutativity failed at index ${i}`);
    }
  });
});

// ---------------------------------------------------------------------------
// Encode / Decode
// ---------------------------------------------------------------------------
describe('Encode / Decode', () => {
  for (const d of [1, 4, 10, 12]) {
    it(`round-trip for d=${d}`, () => {
      const F = new Array(256);
      const maxVal = d === 12 ? Q - 1 : (1 << d) - 1;
      let seed = 42 + d;
      for (let i = 0; i < 256; i++) {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        F[i] = seed % (maxVal + 1);
      }

      const encoded = byteEncode(d, F);
      assert.equal(encoded.length, 32 * d);

      const decoded = byteDecode(d, encoded);
      assert.equal(decoded.length, 256);

      for (let i = 0; i < 256; i++) {
        const expected = d === 12 ? F[i] % Q : F[i];
        assert.equal(decoded[i], expected, `d=${d}, index ${i}`);
      }
    });
  }

  it('d=1 encodes bits correctly', () => {
    const F = new Array(256).fill(0);
    F[0] = 1;
    F[7] = 1;
    const encoded = byteEncode(1, F);
    // Bit 0 and bit 7 should be set in the first byte
    assert.equal(encoded[0], 0b10000001);
  });
});

// ---------------------------------------------------------------------------
// Compress / Decompress
// ---------------------------------------------------------------------------
describe('Compress / Decompress', () => {
  it('compressed values are in range [0, 2^d)', () => {
    for (const d of [1, 4, 5, 10, 11]) {
      const twoD = 1 << d;
      for (let x = 0; x < Q; x += 100) {
        const c = compress(d, x);
        assert.ok(c >= 0 && c < twoD, `compress(${d}, ${x}) = ${c} out of range`);
      }
    }
  });

  it('round-trip error bound: |decompress(compress(x)) - x| <= Q/(2^(d+1))', () => {
    for (const d of [1, 4, 10, 11]) {
      const maxError = Math.ceil(Q / (1 << (d + 1)));
      for (let x = 0; x < Q; x++) {
        const c = compress(d, x);
        const y = decompress(d, c);
        // Error measured modulo Q
        let err = Math.abs(y - x);
        if (err > Q / 2) err = Q - err;
        assert.ok(
          err <= maxError,
          `d=${d}, x=${x}: error ${err} > ${maxError}`
        );
      }
    }
  });

  it('compressPoly / decompressPoly work on arrays', () => {
    const poly = new Array(256);
    for (let i = 0; i < 256; i++) poly[i] = (i * 13) % Q;

    const compressed = compressPoly(10, poly);
    assert.equal(compressed.length, 256);

    const decompressed = decompressPoly(10, compressed);
    assert.equal(decompressed.length, 256);

    for (let i = 0; i < 256; i++) {
      let err = Math.abs(decompressed[i] - poly[i]);
      if (err > Q / 2) err = Q - err;
      assert.ok(err <= Math.ceil(Q / 2048), `index ${i}: error too large`);
    }
  });
});

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------
describe('Parameters', () => {
  const paramSets = [ML_KEM_512, ML_KEM_768, ML_KEM_1024];

  for (const p of paramSets) {
    describe(p.name, () => {
      it('ekSize = 384*k + 32', () => {
        assert.equal(p.ekSize, 384 * p.k + 32);
      });

      it('dkSize = 768*k + 96', () => {
        assert.equal(p.dkSize, 768 * p.k + 96);
      });

      it('ctSize = 32*(du*k + dv)', () => {
        assert.equal(p.ctSize, 32 * (p.du * p.k + p.dv));
      });

      it('has all required fields', () => {
        for (const field of ['name', 'k', 'eta1', 'eta2', 'du', 'dv', 'ekSize', 'dkSize', 'ctSize']) {
          assert.ok(field in p, `missing field: ${field}`);
        }
      });
    });
  }
});
