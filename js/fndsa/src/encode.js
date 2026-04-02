/**
 * FN-DSA (FIPS 206) key and signature encoding/decoding.
 * Port of Python encode.py.
 * All bit-packing is LSB-first.
 */
import { Q } from './params.js';

// ─────────────────────────────────────────────────────────────────────────────
// Public-key encoding (14 bits per NTT coefficient, LSB-first)
// ─────────────────────────────────────────────────────────────────────────────

export function encodePk(h, params) {
  const out = new Uint8Array(params.pkSize);
  out[0] = 0x00 | params.logN;
  packBits14(out, 1, h, params.n);
  return out;
}

export function decodePk(data, params) {
  if (data.length !== params.pkSize) return null;
  if (data[0] !== (0x00 | params.logN)) return null;
  return unpackBits14(data, 1, params.n);
}

// ─────────────────────────────────────────────────────────────────────────────
// Secret-key encoding
// ─────────────────────────────────────────────────────────────────────────────

export function encodeSk(f, g, F, params) {
  const out = new Uint8Array(params.skSize);
  out[0] = 0x50 | params.logN;
  const fgBits = params.fgBits;
  const n = params.n;
  let offset = 1;
  packSignedBits(out, offset, f, n, fgBits);
  offset += (n * fgBits) >> 3;
  packSignedBits(out, offset, g, n, fgBits);
  offset += (n * fgBits) >> 3;
  packSignedBits(out, offset, F, n, 8);
  return out;
}

export function decodeSk(data, params) {
  if (data.length !== params.skSize) return null;
  if (data[0] !== (0x50 | params.logN)) return null;
  const fgBits = params.fgBits;
  const n = params.n;
  let offset = 1;
  const f = unpackSignedBits(data, offset, n, fgBits);
  offset += (n * fgBits) >> 3;
  const g = unpackSignedBits(data, offset, n, fgBits);
  offset += (n * fgBits) >> 3;
  const F = unpackSignedBits(data, offset, n, 8);
  return { f, g, F };
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature encoding
// ─────────────────────────────────────────────────────────────────────────────

function loBitsFor(params) {
  return params.n === 1024 ? 7 : 6;
}

export function encodeSig(salt, s1, params) {
  const capacity = params.sigSize - 41;
  const [compressed, used] = compressS1(s1, params.n, loBitsFor(params), capacity);
  if (compressed === null) return null;

  let out;
  if (params.padded) {
    out = new Uint8Array(params.sigSize);
  } else {
    out = new Uint8Array(1 + 40 + used);
  }
  out[0] = 0x30 | params.logN;
  out.set(salt, 1);
  out.set(compressed.subarray(0, used), 41);
  return out;
}

export function decodeSig(data, params) {
  if (data.length < 41) return null;
  if (data[0] !== (0x30 | params.logN)) return null;
  if (params.padded) {
    if (data.length !== params.sigSize) return null;
  } else {
    if (data.length > params.sigSize) return null;
  }
  const salt = data.slice(1, 41);
  const s1 = decompressS1(data.subarray(41), params.n, loBitsFor(params));
  if (s1 === null) return null;
  return { salt, s1 };
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

function packBits14(dst, offset, src, n) {
  let cursor = 0;
  for (let i = 0; i < n; i++) {
    const v = src[i] & 0x3FFF; // 14 bits
    const byteIdx = offset + (cursor >> 3);
    const bitIdx = cursor & 7;
    dst[byteIdx] |= (v << bitIdx) & 0xFF;
    if (bitIdx === 0) {
      dst[byteIdx + 1] |= (v >> 8) & 0xFF;
    } else {
      dst[byteIdx + 1] |= (v >> (8 - bitIdx)) & 0xFF;
      if (bitIdx > 2) {
        dst[byteIdx + 2] |= (v >> (16 - bitIdx)) & 0xFF;
      }
    }
    cursor += 14;
  }
}

function unpackBits14(src, offset, n) {
  const out = new Int32Array(n);
  let cursor = 0;
  for (let i = 0; i < n; i++) {
    const byteIdx = offset + (cursor >> 3);
    const bitIdx = cursor & 7;
    let v;
    if (bitIdx === 0) {
      v = src[byteIdx] | (src[byteIdx + 1] << 8);
    } else {
      v = src[byteIdx] >> bitIdx;
      v |= src[byteIdx + 1] << (8 - bitIdx);
      if (bitIdx > 2) {
        v |= src[byteIdx + 2] << (16 - bitIdx);
      }
    }
    out[i] = v & 0x3FFF;
    cursor += 14;
  }
  return out;
}

function packSignedBits(dst, offset, src, n, bits) {
  const mask = (1 << bits) - 1;
  let cursor = 0;
  for (let i = 0; i < n; i++) {
    let v = src[i] & mask; // Two's complement truncation
    let rem = bits;
    let cur = cursor;
    while (rem > 0) {
      const byteIdx = offset + (cur >> 3);
      const bitIdx = cur & 7;
      const avail = 8 - bitIdx;
      const chunk = Math.min(rem, avail);
      dst[byteIdx] |= ((v & ((1 << chunk) - 1)) << bitIdx) & 0xFF;
      v >>= chunk;
      cur += chunk;
      rem -= chunk;
    }
    cursor += bits;
  }
}

function unpackSignedBits(src, offset, n, bits) {
  const out = new Int32Array(n);
  const mask = (1 << bits) - 1;
  const signBit = 1 << (bits - 1);
  let cursor = 0;
  for (let i = 0; i < n; i++) {
    let v = 0;
    let rem = bits;
    let cur = cursor;
    let shift = 0;
    while (rem > 0) {
      const byteIdx = offset + (cur >> 3);
      const bitIdx = cur & 7;
      const avail = 8 - bitIdx;
      const chunk = Math.min(rem, avail);
      const b = (src[byteIdx] >> bitIdx) & ((1 << chunk) - 1);
      v |= b << shift;
      shift += chunk;
      cur += chunk;
      rem -= chunk;
    }
    v &= mask;
    if (v & signBit) {
      out[i] = v - (1 << bits);
    } else {
      out[i] = v;
    }
    cursor += bits;
  }
  return out;
}

function compressS1(s1, n, lo, capacity) {
  const loMask = (1 << lo) - 1;
  const dst = new Uint8Array(capacity);
  let cursor = 0;
  const capacityBits = capacity * 8;

  for (let i = 0; i < n; i++) {
    const s = s1[i];
    const v = Math.abs(s);
    const low = v & loMask;
    const high = v >> lo;

    // Emit lo bits of low, LSB-first
    for (let b = 0; b < lo; b++) {
      if (cursor >= capacityBits) return [null, 0];
      if ((low >> b) & 1) {
        dst[cursor >> 3] |= 1 << (cursor & 7);
      }
      cursor++;
    }

    // Emit high 1-bits (unary)
    for (let h = 0; h < high; h++) {
      if (cursor >= capacityBits) return [null, 0];
      dst[cursor >> 3] |= 1 << (cursor & 7);
      cursor++;
    }

    // Emit terminating 0-bit
    if (cursor >= capacityBits) return [null, 0];
    // bit is 0, no action needed (Uint8Array is zero-initialized)
    cursor++;

    // Emit sign bit (1 if negative)
    if (cursor >= capacityBits) return [null, 0];
    if (s < 0) {
      dst[cursor >> 3] |= 1 << (cursor & 7);
    }
    cursor++;
  }

  const bytesUsed = (cursor + 7) >> 3;
  return [dst, bytesUsed];
}

function decompressS1(src, n, lo) {
  const totalBits = src.length * 8;
  let cursor = 0;
  const out = new Int32Array(n);

  for (let i = 0; i < n; i++) {
    // Read lo bits of low, LSB-first
    let low = 0;
    for (let b = 0; b < lo; b++) {
      if (cursor >= totalBits) return null;
      const bit = (src[cursor >> 3] >> (cursor & 7)) & 1;
      low |= bit << b;
      cursor++;
    }

    // Read unary-coded high (count 1-bits until 0-bit)
    let high = 0;
    while (true) {
      if (cursor >= totalBits) return null;
      const bit = (src[cursor >> 3] >> (cursor & 7)) & 1;
      cursor++;
      if (bit === 0) break;
      high++;
    }

    // Read sign bit
    if (cursor >= totalBits) return null;
    const signBit = (src[cursor >> 3] >> (cursor & 7)) & 1;
    cursor++;

    let v = (high << lo) | low;
    if (signBit === 1) {
      if (v === 0) return null; // Non-canonical: zero with sign bit 1
      v = -v;
    }
    out[i] = v;
  }

  return out;
}
