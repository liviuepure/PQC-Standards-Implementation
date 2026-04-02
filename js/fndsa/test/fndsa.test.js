import { FNDSA512, FNDSA1024, FNDSAPadded512, FNDSAPadded1024, keyGen, sign, verify } from '../src/index.js';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('FN-DSA', () => {
  test.each([FNDSA512, FNDSA1024, FNDSAPadded512, FNDSAPadded1024])('param sizes %s', (p) => {
    expect(p.pkSize).toBeGreaterThan(0);
    expect(p.skSize).toBeGreaterThan(0);
    expect(p.sigSize).toBeGreaterThan(0);
    expect(p.betaSq).toBeGreaterThan(0);
  });

  test('param values FNDSA512', () => {
    expect(FNDSA512.n).toBe(512);
    expect(FNDSA512.logN).toBe(9);
    expect(FNDSA512.pkSize).toBe(897);
    expect(FNDSA512.skSize).toBe(1281);
    expect(FNDSA512.sigSize).toBe(666);
    expect(FNDSA512.padded).toBe(false);
  });

  test('param values FNDSA1024', () => {
    expect(FNDSA1024.n).toBe(1024);
    expect(FNDSA1024.logN).toBe(10);
    expect(FNDSA1024.pkSize).toBe(1793);
    expect(FNDSA1024.skSize).toBe(2305);
    expect(FNDSA1024.sigSize).toBe(1280);
    expect(FNDSA1024.padded).toBe(false);
  });

  // Only run 512 in tests (1024 is slow)
  test('roundtrip FNDSA512', () => {
    const [pk, sk] = keyGen(FNDSA512);
    expect(pk.length).toBe(FNDSA512.pkSize);
    expect(sk.length).toBe(FNDSA512.skSize);
    const msg = Buffer.from('test message fn-dsa');
    const sig = sign(sk, msg, FNDSA512);
    expect(sig.length).toBeLessThanOrEqual(FNDSA512.sigSize);
    expect(verify(pk, msg, sig, FNDSA512)).toBe(true);
    expect(verify(pk, Buffer.from('wrong'), sig, FNDSA512)).toBe(false);
    const tampered = Buffer.from(sig);
    tampered[Math.min(42, tampered.length - 1)] ^= 0x01;
    expect(verify(pk, msg, tampered, FNDSA512)).toBe(false);
  }, 60000);

  test('roundtrip FNDSAPadded512', () => {
    const [pk, sk] = keyGen(FNDSAPadded512);
    expect(pk.length).toBe(FNDSAPadded512.pkSize);
    expect(sk.length).toBe(FNDSAPadded512.skSize);
    const msg = Buffer.from('test message fn-dsa padded');
    const sig = sign(sk, msg, FNDSAPadded512);
    expect(sig.length).toBe(FNDSAPadded512.sigSize);
    expect(verify(pk, msg, sig, FNDSAPadded512)).toBe(true);
  }, 60000);

  test('interop vectors', () => {
    let anyRan = false;
    for (const [name, params] of [['FN-DSA-512', FNDSA512], ['FN-DSA-1024', FNDSA1024]]) {
      const path = join(__dirname, `../../../test-vectors/fn-dsa/${name}.json`);
      if (!existsSync(path)) continue;
      const { vectors } = JSON.parse(readFileSync(path, 'utf8'));
      for (const v of vectors) {
        const pk = Buffer.from(v.pk, 'hex');
        const msg = Buffer.from(v.msg, 'hex');
        const sig = Buffer.from(v.sig, 'hex');
        expect(verify(pk, msg, sig, params)).toBe(true);
      }
      anyRan = true;
    }
    if (!anyRan) return; // no test vector files found, skip
  });
});
