/**
 * RCDT Gaussian sampler for FN-DSA (FIPS 206).
 * Port of Python gaussian.py / Go gaussian.go.
 */

const SIGMA0 = 1.8205;

// RCDT table: 18 entries, each a 72-bit threshold.
// Stored as [hi32, lo32_hi, lo32_lo] for efficient comparison without full BigInt.
// Actually: store as [hi8, hi32, lo32] where hi8 is top byte, remaining 8 bytes are lo64.
// Full 72-bit = (hi8 << 64) | lo64
// Compare: if hi8 > sHi8: z++; else if hi8 == sHi8 && lo64 > sLo64: z++
// lo64 stored as two 32-bit numbers [lo64Hi, lo64Lo] for JS number comparison.

// Values from Go reference (gaussian.go), same as Python.
// Each entry: [hi8, lo64] where hi8 is the top byte and lo64 is BigInt for the lower 64 bits.
// We convert lo64 to two Uint32 for faster JS comparison.

// RCDT entries as [hiU8, hiU32, loU32] where:
//   full value = (hiU8 * 2^64) | ((hiU32 << 32) | loU32)
const _RCDT = (() => {
  const raw = [
    [199n, 16610441552002023424n],
    [103n, 7624082642567692288n],
    [42n,  919243735747002368n],
    [13n,  3484267233246674944n],
    [3n,   2772878652510347264n],
    [0n,   10479598105528201216n],
    [0n,   1418221736465465344n],
    [0n,   143439473028577328n],
    [0n,   10810581864167812n],
    [0n,   605874652027744n],
    [0n,   25212870589170n],
    [0n,   778215157694n],
    [0n,   17802250993n],
    [0n,   301647562n],
    [0n,   3784361n],
    [0n,   35141n],
    [0n,   241n],
    [0n,   1n],
  ];
  return raw.map(([hi, lo]) => {
    // Store as [hi (number), loHigh (upper 32 bits), loLow (lower 32 bits)]
    const loHigh = Number(lo >> 32n);
    const loLow = Number(lo & 0xFFFFFFFFn);
    return [Number(hi), loHigh, loLow];
  });
})();

/**
 * Compare sample (9 bytes LE) against RCDT entry [hiU8, loHigh, loLow].
 * Returns true if sample < threshold.
 * sample: Uint8Array[9] (little-endian 72-bit)
 * threshold: [hi8, lo64hi, lo64lo]
 */
function sampleLessThan(buf, tHi, tLoH, tLoL) {
  // buf is 9-byte LE: byte 8 is highest
  const sHi = buf[8];
  if (sHi < tHi) return true;
  if (sHi > tHi) return false;
  // hi bytes equal, compare lo64
  // lo64 is bytes 0..7 LE: reconstruct as two 32-bit values
  // lo bits 32..63: bytes 4..7
  const sLoH = (buf[7] * 0x1000000 + buf[6] * 0x10000 + buf[5] * 0x100 + buf[4]) >>> 0;
  if (sLoH < tLoH) return true;
  if (sLoH > tLoH) return false;
  // compare lo bits 0..31: bytes 0..3
  const sLoL = (buf[3] * 0x1000000 + buf[2] * 0x10000 + buf[1] * 0x100 + buf[0]) >>> 0;
  return sLoL < tLoL;
}

/**
 * Sample from D_{Z, sigma0} using the RCDT table.
 * rng: function(nBytes) -> Uint8Array
 */
function sampleBaseGaussian(rng) {
  // Read 9 bytes (72 bits)
  const buf = rng(9);

  // Count how many RCDT entries are strictly greater than sample
  let z = 0;
  for (const [tHi, tLoH, tLoL] of _RCDT) {
    if (sampleLessThan(buf, tHi, tLoH, tLoL)) z++;
  }

  // Read 1 byte for the sign
  const signBuf = rng(1);
  const signBit = signBuf[0] & 1;
  // Apply sign: if signBit=1, negate z
  const mask = -signBit; // 0 if sign=0, -1 if sign=1
  return (z ^ mask) - mask;
}

/**
 * Sample from discrete Gaussian D_{Z, sigma}.
 * rng: function(nBytes) -> Uint8Array
 */
export function sampleGaussian(sigma, rng) {
  const sigma2 = sigma * sigma;
  const sigma02 = SIGMA0 * SIGMA0;
  const c = (sigma2 - sigma02) / (2.0 * sigma2 * sigma02);

  while (true) {
    const z = sampleBaseGaussian(rng);

    // Rejection step: accept with probability exp(-z^2 * c)
    const logProb = -z * z * c;

    // Sample u in [0,1) using 53 random bits
    const uBuf = rng(8);
    // Read as little-endian, shift right 11 to get 53 bits
    // Use a DataView to read 8 bytes LE, then form a 53-bit uniform value.
    // hi32 contributes the top 32 bits, shifted left by 21 (= 2^21), and
    // lo32 contributes the top 21 bits (lo32 >>> 11), giving a 53-bit integer
    // in [0, 2^53) which is then divided by 2^53 to land in [0, 1).
    const dv = new DataView(uBuf.buffer, uBuf.byteOffset, 8);
    const lo32 = dv.getUint32(0, true);
    const hi32 = dv.getUint32(4, true);
    // 53-bit value from upper 53 bits: hi32 (32 bits) + top 21 bits of lo32
    const u = (hi32 * 2097152 + (lo32 >>> 11)) / (2 ** 53);

    if (u < Math.exp(logProb)) {
      return z;
    }
  }
}

export { SIGMA0 };
