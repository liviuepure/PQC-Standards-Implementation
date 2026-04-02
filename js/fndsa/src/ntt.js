import { Q } from './params.js';

function powMod(base, exp, mod) {
  let result = 1n;
  base = BigInt(base) % BigInt(mod);
  exp = BigInt(exp);
  mod = BigInt(mod);
  while (exp > 0n) {
    if (exp & 1n) result = result * base % mod;
    base = base * base % mod;
    exp >>= 1n;
  }
  return Number(result);
}

function bitRev(x, bits) {
  let r = 0;
  for (let i = 0; i < bits; i++) { r = (r << 1) | (x & 1); x >>= 1; }
  return r;
}

function buildZetas(n) {
  const logN = Math.log2(n) | 0;
  const psi = powMod(11, (Q - 1) / (2 * n), Q);
  const zetas = new Int32Array(n + 1);
  for (let i = 0; i <= n; i++) {
    zetas[i] = powMod(psi, bitRev(i, logN), Q);
  }
  return zetas;
}

function buildZetasInv(n) {
  const logN = Math.log2(n) | 0;
  const psi = powMod(11, (Q - 1) / (2 * n), Q);
  const psiInv = powMod(psi, Q - 2, Q);
  const zetasInv = new Int32Array(n + 1);
  for (let i = 0; i <= n; i++) {
    zetasInv[i] = powMod(psiInv, bitRev(i, logN), Q);
  }
  return zetasInv;
}

// Cache built zeta tables
const _zetasCache = new Map();
const _zetasInvCache = new Map();

function getZetas(n) {
  if (!_zetasCache.has(n)) _zetasCache.set(n, buildZetas(n));
  return _zetasCache.get(n);
}

function getZetasInv(n) {
  if (!_zetasInvCache.has(n)) _zetasInvCache.set(n, buildZetasInv(n));
  return _zetasInvCache.get(n);
}

export function ntt(a, n) {
  const zetas = getZetas(n);
  const out = new Int32Array(n);
  for (let i = 0; i < n; i++) out[i] = a[i];
  let k = 0;
  let length = n >> 1;
  while (length >= 1) {
    for (let start = 0; start < n; start += 2 * length) {
      k++;
      const zeta = zetas[k];
      for (let j = start; j < start + length; j++) {
        const t = (zeta * out[j + length]) % Q;
        out[j + length] = (out[j] - t + Q) % Q;
        out[j] = (out[j] + t) % Q;
      }
    }
    length >>= 1;
  }
  return out;
}

export function intt(a, n) {
  const zetasInv = getZetasInv(n);
  const out = new Int32Array(n);
  for (let i = 0; i < n; i++) out[i] = a[i];
  let k = n;
  let length = 1;
  while (length < n) {
    // Process starts in reverse order (matching Python/Go: start from n-2*length down to 0)
    for (let start = n - 2 * length; start >= 0; start -= 2 * length) {
      k--;
      const zetaInv = zetasInv[k];
      for (let j = start; j < start + length; j++) {
        const t = out[j];
        out[j] = (t + out[j + length]) % Q;
        out[j + length] = (zetaInv * ((t - out[j + length] + Q) % Q)) % Q;
      }
    }
    length <<= 1;
  }
  const nInv = powMod(n, Q - 2, Q);
  for (let i = 0; i < n; i++) out[i] = (out[i] * nInv) % Q;
  return out;
}

export function polyMulNtt(a, b, n) {
  const fa = ntt(a, n), fb = ntt(b, n);
  const fc = new Int32Array(n);
  for (let i = 0; i < n; i++) fc[i] = (fa[i] * fb[i]) % Q;
  return intt(fc, n);
}

export function polyInvNtt(f, n) {
  const ff = ntt(f, n);
  const ffInv = new Int32Array(n);
  for (let i = 0; i < n; i++) ffInv[i] = powMod(ff[i], Q - 2, Q);
  return intt(ffInv, n);
}
