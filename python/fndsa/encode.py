"""FN-DSA (FIPS 206) key and signature encoding/decoding.

All bit-packing is LSB-first: bit 0 of coefficient 0 goes to bit 0 of byte 0.
Mirrors Go encode.go exactly.
"""
from __future__ import annotations

from .params import Params, Q


# ─────────────────────────────────────────────────────────────────────────────
# Public-key encoding  (14 bits per NTT coefficient, LSB-first)
# ─────────────────────────────────────────────────────────────────────────────

def encode_pk(h: list[int], params: Params) -> bytes:
    """Encode NTT public-key polynomial h into FIPS 206 format.

    Format:
      byte 0     : 0x00 | log_n
      bytes 1..  : h coefficients packed at 14 bits each, LSB-first
    """
    out = bytearray(params.pk_size)
    out[0] = 0x00 | params.log_n
    _pack_bits14(out, 1, h, params.n)
    return bytes(out)


def decode_pk(data: bytes, params: Params) -> list[int] | None:
    """Decode FIPS 206 public key. Returns None if length or header is invalid."""
    if len(data) != params.pk_size:
        return None
    if data[0] != (0x00 | params.log_n):
        return None
    return _unpack_bits14(data, 1, params.n)


# ─────────────────────────────────────────────────────────────────────────────
# Secret-key encoding  (f, g at fg_bits bits; F at 8 bits — two's complement)
# ─────────────────────────────────────────────────────────────────────────────

def encode_sk(f: list[int], g: list[int], F: list[int], params: Params) -> bytes:
    """Encode (f, g, F) into FIPS 206 secret-key format.

    Format:
      byte 0             : 0x50 | log_n
      next fg_bits*n/8   : f (signed two's complement)
      next fg_bits*n/8   : g (signed two's complement)
      next 8*n/8         : F (signed 8-bit two's complement)

    G is NOT stored (recovered via NTRU equation at signing time).
    """
    out = bytearray(params.sk_size)
    out[0] = 0x50 | params.log_n
    fg_bits = params.fg_bits
    n = params.n
    offset = 1
    _pack_signed_bits(out, offset, f, n, fg_bits)
    offset += (n * fg_bits) // 8
    _pack_signed_bits(out, offset, g, n, fg_bits)
    offset += (n * fg_bits) // 8
    _pack_signed_bits(out, offset, F, n, 8)
    return bytes(out)


def decode_sk(data: bytes, params: Params) -> tuple | None:
    """Decode FIPS 206 secret key. Returns (f, g, F) or None on error."""
    if len(data) != params.sk_size:
        return None
    if data[0] != (0x50 | params.log_n):
        return None
    fg_bits = params.fg_bits
    n = params.n
    offset = 1
    f = _unpack_signed_bits(data, offset, n, fg_bits)
    offset += (n * fg_bits) // 8
    g = _unpack_signed_bits(data, offset, n, fg_bits)
    offset += (n * fg_bits) // 8
    F = _unpack_signed_bits(data, offset, n, 8)
    return f, g, F


# ─────────────────────────────────────────────────────────────────────────────
# Signature encoding  (variable-length compressed s1)
# ─────────────────────────────────────────────────────────────────────────────

def _lo_bits_for(params: Params) -> int:
    """Return lo parameter for s1 compression: 7 for n=1024, 6 for n=512."""
    return 7 if params.n == 1024 else 6


def encode_sig(salt: bytes, s1: list[int], params: Params) -> bytes | None:
    """Encode signature into FIPS 206 format.

    Format:
      byte 0     : 0x30 | log_n
      bytes 1-40 : salt (40 bytes)
      bytes 41.. : compressed s1

    For PADDED params: result is exactly params.sig_size bytes (zero-padded).
    For non-PADDED params: result is exactly 1+40+actual_compressed_bytes (variable).

    Returns None if compressed s1 would exceed the capacity.
    """
    capacity = params.sig_size - 41  # bytes available for compressed s1
    compressed, used = _compress_s1(s1, params.n, _lo_bits_for(params), capacity)
    if compressed is None:
        return None

    if params.padded:
        out = bytearray(params.sig_size)
    else:
        out = bytearray(1 + 40 + used)

    out[0] = 0x30 | params.log_n
    out[1:41] = salt
    out[41:41 + used] = compressed[:used]
    return bytes(out)


def decode_sig(data: bytes, params: Params) -> tuple | None:
    """Decode FIPS 206 signature. Returns (salt, s1) or None on error."""
    if len(data) < 41:
        return None
    if data[0] != (0x30 | params.log_n):
        return None

    if params.padded:
        if len(data) != params.sig_size:
            return None
    else:
        if len(data) > params.sig_size:
            return None

    salt = bytes(data[1:41])
    s1 = _decompress_s1(data[41:], params.n, _lo_bits_for(params))
    if s1 is None:
        return None

    return salt, s1


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _pack_bits14(dst: bytearray, offset: int, src: list[int], n: int) -> None:
    """Pack n coefficients (each 14 bits) LSB-first into dst starting at offset."""
    cursor = 0
    for i in range(n):
        v = src[i] & 0x3FFF  # 14 bits
        byte_idx = offset + (cursor >> 3)
        bit_idx = cursor & 7
        # Byte 0 of the window gets low bits
        dst[byte_idx] |= (v << bit_idx) & 0xFF
        # Byte 1: middle bits (always needed because 14 > 8)
        if bit_idx == 0:
            dst[byte_idx + 1] |= (v >> 8) & 0xFF
        else:
            dst[byte_idx + 1] |= (v >> (8 - bit_idx)) & 0xFF
            # Byte 2: only when 14 bits overflow into a third byte
            if bit_idx > 2:  # (8-bit_idx) + 8 < 14 => bit_idx > 2
                dst[byte_idx + 2] |= (v >> (16 - bit_idx)) & 0xFF
        cursor += 14


def _unpack_bits14(src: bytes | bytearray, offset: int, n: int) -> list[int]:
    """Unpack n 14-bit coefficients LSB-first from src starting at offset."""
    out = [0] * n
    cursor = 0
    for i in range(n):
        byte_idx = offset + (cursor >> 3)
        bit_idx = cursor & 7
        if bit_idx == 0:
            v = src[byte_idx] | (src[byte_idx + 1] << 8)
        else:
            v = src[byte_idx] >> bit_idx
            v |= src[byte_idx + 1] << (8 - bit_idx)
            if bit_idx > 2:
                v |= src[byte_idx + 2] << (16 - bit_idx)
        out[i] = v & 0x3FFF
        cursor += 14
    return out


def _pack_signed_bits(dst: bytearray, offset: int, src: list[int], n: int, bits: int) -> None:
    """Pack n signed integers as `bits`-bit two's complement, LSB-first."""
    mask = (1 << bits) - 1
    cursor = 0
    for i in range(n):
        v = src[i] & mask  # Two's complement truncation
        rem = bits
        cur = cursor
        while rem > 0:
            byte_idx = offset + (cur >> 3)
            bit_idx = cur & 7
            avail = 8 - bit_idx
            chunk = min(rem, avail)
            dst[byte_idx] |= ((v & ((1 << chunk) - 1)) << bit_idx) & 0xFF
            v >>= chunk
            cur += chunk
            rem -= chunk
        cursor += bits


def _unpack_signed_bits(src: bytes | bytearray, offset: int, n: int, bits: int) -> list[int]:
    """Unpack n signed integers of `bits` bits each (two's complement, LSB-first)."""
    out = [0] * n
    mask = (1 << bits) - 1
    sign_bit = 1 << (bits - 1)
    cursor = 0
    for i in range(n):
        v = 0
        rem = bits
        cur = cursor
        shift = 0
        while rem > 0:
            byte_idx = offset + (cur >> 3)
            bit_idx = cur & 7
            avail = 8 - bit_idx
            chunk = min(rem, avail)
            b = (src[byte_idx] >> bit_idx) & ((1 << chunk) - 1)
            v |= b << shift
            shift += chunk
            cur += chunk
            rem -= chunk
        v &= mask
        # Sign-extend: if sign bit is set, convert to negative Python int
        if v & sign_bit:
            out[i] = v - (1 << bits)
        else:
            out[i] = v
        cursor += bits
    return out


def _compress_s1(s1: list[int], n: int, lo: int, capacity: int) -> tuple:
    """Encode s1 into bytes using FIPS 206 variable-length scheme with parameter lo.

    Encoding per coefficient s:
      v    = |s|
      low  = v & ((1<<lo)-1)   # lo LSBs
      high = v >> lo            # unary count
      emit lo bits of low (LSB-first)
      emit high 1-bits
      emit one 0-bit (unary terminator)
      emit 1 sign bit (0=non-negative, 1=negative; 0 for s==0)

    Returns (bytearray, bytes_used) on success, or (None, 0) if capacity exceeded.
    """
    lo_mask = (1 << lo) - 1
    dst = bytearray(capacity)
    cursor = 0
    capacity_bits = capacity * 8

    for i in range(n):
        s = s1[i]
        v = abs(s)
        low = v & lo_mask
        high = v >> lo

        # Emit lo bits of low, LSB-first
        for b in range(lo):
            if cursor >= capacity_bits:
                return None, 0
            if (low >> b) & 1:
                dst[cursor >> 3] |= 1 << (cursor & 7)
            cursor += 1

        # Emit high 1-bits
        for _ in range(high):
            if cursor >= capacity_bits:
                return None, 0
            dst[cursor >> 3] |= 1 << (cursor & 7)
            cursor += 1

        # Emit terminating 0-bit
        if cursor >= capacity_bits:
            return None, 0
        # bit is 0, no action needed (bytearray is zero-initialized)
        cursor += 1

        # Emit sign bit (1 if negative)
        if cursor >= capacity_bits:
            return None, 0
        if s < 0:
            dst[cursor >> 3] |= 1 << (cursor & 7)
        cursor += 1

    bytes_used = (cursor + 7) // 8
    return dst, bytes_used


def _decompress_s1(src: bytes | bytearray, n: int, lo: int) -> list[int] | None:
    """Decode n coefficients from src using FIPS 206 variable-length scheme.

    Returns s1 list on success, or None if malformed.
    Rejects non-canonical zero: s=0 with sign bit=1 is invalid (FIPS 206 §3.11.5).
    """
    total_bits = len(src) * 8
    cursor = 0

    out = [0] * n
    for i in range(n):
        # Read lo bits of low, LSB-first
        low = 0
        for b in range(lo):
            if cursor >= total_bits:
                return None
            bit = (src[cursor >> 3] >> (cursor & 7)) & 1
            low |= bit << b
            cursor += 1

        # Read unary-coded high (count 1-bits until 0-bit)
        high = 0
        while True:
            if cursor >= total_bits:
                return None
            bit = (src[cursor >> 3] >> (cursor & 7)) & 1
            cursor += 1
            if bit == 0:
                break
            high += 1

        # Read sign bit
        if cursor >= total_bits:
            return None
        sign_bit = (src[cursor >> 3] >> (cursor & 7)) & 1
        cursor += 1

        v = (high << lo) | low
        if sign_bit == 1:
            # Non-canonical: zero with sign bit 1 is invalid
            if v == 0:
                return None
            v = -v
        out[i] = v

    return out
