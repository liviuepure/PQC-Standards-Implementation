/**
 * Utility functions for SLH-DSA (FIPS 205)
 */

/**
 * toInt(X, n) - Convert n-byte big-endian byte string to integer
 * FIPS 205 Algorithm 1
 */
function toInt(X, n) {
  if (n === undefined) n = X.length;
  let total = 0;
  for (let i = 0; i < n; i++) {
    total = total * 256 + X[i];
  }
  return total;
}

/**
 * toBigInt(X, n) - Convert n-byte big-endian byte string to BigInt
 */
function toBigInt(X, n) {
  if (n === undefined) n = X.length;
  let total = 0n;
  for (let i = 0; i < n; i++) {
    total = (total << 8n) | BigInt(X[i]);
  }
  return total;
}

/**
 * toByte(x, n) - Convert integer x to n-byte big-endian byte string
 * FIPS 205 Algorithm 2
 */
function toByte(x, n) {
  const out = new Uint8Array(n);
  let val = x;
  for (let i = n - 1; i >= 0; i--) {
    out[i] = val & 0xff;
    val = Math.floor(val / 256);
  }
  return out;
}

/**
 * toByteBigInt(x, n) - Convert BigInt to n-byte big-endian byte string
 */
function toByteBigInt(x, n) {
  const out = new Uint8Array(n);
  let val = BigInt(x);
  for (let i = n - 1; i >= 0; i--) {
    out[i] = Number(val & 0xFFn);
    val >>= 8n;
  }
  return out;
}

/**
 * base2b(X, b, outLen) - Convert byte string X to base-2^b representation
 * FIPS 205 Algorithm 3
 *
 * Returns array of outLen integers, each in range [0, 2^b - 1]
 */
function base2b(X, b, outLen) {
  const out = new Array(outLen);
  let inIdx = 0;
  let bits = 0;
  let total = 0;
  const mask = (1 << b) - 1;

  for (let i = 0; i < outLen; i++) {
    while (bits < b) {
      total = (total << 8) | X[inIdx];
      inIdx++;
      bits += 8;
    }
    bits -= b;
    out[i] = (total >> bits) & mask;
  }
  return out;
}

/**
 * Concatenate multiple Uint8Arrays
 */
function concat(...arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export { toInt, toBigInt, toByte, toByteBigInt, base2b, concat };
