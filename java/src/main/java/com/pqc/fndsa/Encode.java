package com.pqc.fndsa;

/**
 * FIPS 206 key and signature encoding/decoding for FN-DSA.
 *
 * All bit-packing is LSB-first: bit 0 of coefficient 0 goes to bit 0 of byte 0.
 */
final class Encode {

    private Encode() {}

    static final int Q = Params.Q;

    // =========================================================================
    // Public-key encoding (14 bits per coefficient, LSB-first)
    // =========================================================================

    /**
     * Encode NTT public-key polynomial h into FIPS 206 format.
     * byte 0: 0x00 | logN
     * bytes 1+: h coefficients packed at 14 bits each, LSB-first
     */
    static byte[] encodePk(int[] h, Params p) {
        byte[] out = new byte[p.pkSize];
        out[0] = (byte)(0x00 | p.logN);
        packBits14(out, 1, h, p.n);
        return out;
    }

    /**
     * Decode public key. Returns null if data is invalid.
     */
    static int[] decodePk(byte[] data, Params p) {
        if (data == null || data.length != p.pkSize) return null;
        if ((data[0] & 0xFF) != (0x00 | p.logN)) return null;
        return unpackBits14(data, 1, p.n);
    }

    // =========================================================================
    // Secret-key encoding (f, g at fgBits bits; F at 8 bits -- two's complement)
    // =========================================================================

    /**
     * Encode (f, g, F) into FIPS 206 secret-key format.
     * byte 0: 0x50 | logN
     * next fgBits*N/8 bytes: f (signed two's complement)
     * next fgBits*N/8 bytes: g (signed two's complement)
     * next 8*N/8 bytes: F (signed 8-bit)
     */
    static byte[] encodeSk(int[] f, int[] g, int[] F, Params p) {
        byte[] out = new byte[p.skSize];
        out[0] = (byte)(0x50 | p.logN);
        int fgBits = p.fgBits;
        int offset = 1;
        packSignedBits(out, offset, f, p.n, fgBits);
        offset += (p.n * fgBits) / 8;
        packSignedBits(out, offset, g, p.n, fgBits);
        offset += (p.n * fgBits) / 8;
        packSignedBits(out, offset, F, p.n, 8);
        return out;
    }

    /**
     * Decode secret key. Returns [f, g, F] or null if invalid.
     */
    static int[][] decodeSk(byte[] data, Params p) {
        if (data == null || data.length != p.skSize) return null;
        if ((data[0] & 0xFF) != (0x50 | p.logN)) return null;
        int fgBits = p.fgBits;
        int offset = 1;
        int[] f = unpackSignedBits(data, offset, p.n, fgBits);
        offset += (p.n * fgBits) / 8;
        int[] g = unpackSignedBits(data, offset, p.n, fgBits);
        offset += (p.n * fgBits) / 8;
        int[] F = unpackSignedBits(data, offset, p.n, 8);
        return new int[][] {f, g, F};
    }

    // =========================================================================
    // Signature encoding (variable-length compressed s1)
    // =========================================================================

    /**
     * Encode signature into FIPS 206 format.
     * byte 0: 0x30 | logN
     * bytes 1-40: salt (40 bytes)
     * bytes 41+: compressed s1
     *
     * For PADDED: always p.sigSize bytes (zero-padded).
     * For non-PADDED: 1+40+used bytes (variable, <= sigMaxLen).
     * Returns null if compressed s1 exceeds available capacity.
     */
    static byte[] encodeSig(byte[] salt, int[] s1, Params p) {
        int capacity = p.sigMaxLen - 41;
        byte[] compBuf = new byte[capacity];
        int used = compressS1(compBuf, s1, p.n, loBitsFor(p));
        if (used < 0) return null;

        byte[] out;
        if (p.padded) {
            out = new byte[p.sigSize];
        } else {
            out = new byte[1 + 40 + used];
        }
        out[0] = (byte)(0x30 | p.logN);
        System.arraycopy(salt, 0, out, 1, 40);
        System.arraycopy(compBuf, 0, out, 41, used);
        return out;
    }

    /**
     * Decode signature. Returns [salt_bytes, s1_as_int_encoded] or null if invalid.
     * Actually returns {salt (byte[40]), s1 (int[n])} via a helper class, but
     * we'll use Object[] {byte[], int[]}.
     */
    static Object[] decodeSig(byte[] data, Params p) {
        if (data == null || data.length < 41) return null;
        if ((data[0] & 0xFF) != (0x30 | p.logN)) return null;
        if (p.padded) {
            if (data.length != p.sigSize) return null;
        } else {
            if (data.length > p.sigMaxLen) return null;
        }

        byte[] salt = new byte[40];
        System.arraycopy(data, 1, salt, 0, 40);

        // Compressed s1 is everything from byte 41 onward
        byte[] compressed = new byte[data.length - 41];
        System.arraycopy(data, 41, compressed, 0, compressed.length);

        int[] s1 = decompressS1(compressed, p.n, loBitsFor(p));
        if (s1 == null) return null;

        return new Object[] {salt, s1};
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /** lo bits for s1 compression: 7 for n=1024, 6 for n=512. */
    private static int loBitsFor(Params p) {
        return (p.n == 1024) ? 7 : 6;
    }

    /** Pack n 14-bit coefficients LSB-first into dst starting at dstOffset. */
    private static void packBits14(byte[] dst, int dstOffset, int[] src, int n) {
        int cursor = 0;
        for (int i = 0; i < n; i++) {
            int v = src[i] & 0x3FFF; // 14 bits
            int byteIdx = dstOffset + (cursor >> 3);
            int bitIdx = cursor & 7;
            dst[byteIdx] |= (byte)(v << bitIdx);
            if (bitIdx == 0) {
                dst[byteIdx + 1] |= (byte)(v >> 8);
            } else {
                dst[byteIdx + 1] |= (byte)(v >> (8 - bitIdx));
                if (bitIdx > 2) {
                    dst[byteIdx + 2] |= (byte)(v >> (16 - bitIdx));
                }
            }
            cursor += 14;
        }
    }

    /** Unpack n 14-bit coefficients LSB-first from src starting at srcOffset. */
    private static int[] unpackBits14(byte[] src, int srcOffset, int n) {
        int[] out = new int[n];
        int cursor = 0;
        for (int i = 0; i < n; i++) {
            int byteIdx = srcOffset + (cursor >> 3);
            int bitIdx = cursor & 7;
            int v;
            if (bitIdx == 0) {
                v = (src[byteIdx] & 0xFF) | ((src[byteIdx + 1] & 0xFF) << 8);
            } else {
                v = (src[byteIdx] & 0xFF) >>> bitIdx;
                v |= (src[byteIdx + 1] & 0xFF) << (8 - bitIdx);
                if (bitIdx > 2) {
                    v |= (src[byteIdx + 2] & 0xFF) << (16 - bitIdx);
                }
            }
            out[i] = v & 0x3FFF;
            cursor += 14;
        }
        return out;
    }

    /** Pack n signed integers of `bits` bits (two's complement) LSB-first. */
    private static void packSignedBits(byte[] dst, int dstOffset, int[] src, int n, int bits) {
        int mask = (1 << bits) - 1;
        int cursor = 0;
        for (int i = 0; i < n; i++) {
            int v = src[i] & mask;
            int rem = bits;
            int cur = cursor;
            while (rem > 0) {
                int byteIdx = dstOffset + (cur >> 3);
                int bitIdx = cur & 7;
                int avail = 8 - bitIdx;
                int chunk = Math.min(rem, avail);
                dst[byteIdx] |= (byte)((v & ((1 << chunk) - 1)) << bitIdx);
                v >>>= chunk;
                cur += chunk;
                rem -= chunk;
            }
            cursor += bits;
        }
    }

    /** Unpack n signed integers of `bits` bits (two's complement, LSB-first), sign-extended. */
    private static int[] unpackSignedBits(byte[] src, int srcOffset, int n, int bits) {
        int[] out = new int[n];
        int mask = (1 << bits) - 1;
        int signBit = 1 << (bits - 1);
        int cursor = 0;
        for (int i = 0; i < n; i++) {
            int v = 0;
            int rem = bits;
            int cur = cursor;
            int shift = 0;
            while (rem > 0) {
                int byteIdx = srcOffset + (cur >> 3);
                int bitIdx = cur & 7;
                int avail = 8 - bitIdx;
                int chunk = Math.min(rem, avail);
                int b = (src[byteIdx] & 0xFF) >>> bitIdx;
                b &= (1 << chunk) - 1;
                v |= b << shift;
                shift += chunk;
                cur += chunk;
                rem -= chunk;
            }
            v &= mask;
            if ((v & signBit) != 0) v |= ~mask; // sign-extend
            out[i] = v;
            cursor += bits;
        }
        return out;
    }

    /**
     * Compress s1 using FIPS 206 variable-length scheme.
     * Returns bytes used, or -1 if encoding exceeds dst length.
     *
     * Encoding per coefficient s:
     *   v    = |s|
     *   low  = v & ((1<<lo)-1)   -- lo LSBs
     *   high = v >> lo           -- unary count
     *   emit lo bits of low (LSB-first)
     *   emit high 1-bits
     *   emit one 0-bit (terminator)
     *   emit 1 sign bit (0=non-negative, 1=negative; 0 for s==0)
     */
    private static int compressS1(byte[] dst, int[] s1, int n, int lo) {
        int loMask = (1 << lo) - 1;
        int cursor = 0;
        int capacity = dst.length * 8;

        for (int i = 0; i < n; i++) {
            int s = s1[i];
            int v = (s < 0) ? -s : s;
            int low = v & loMask;
            int high = v >> lo;

            // Emit lo bits of low, LSB-first
            for (int b = 0; b < lo; b++) {
                if (cursor >= capacity) return -1;
                if (((low >> b) & 1) != 0) {
                    dst[cursor >> 3] |= (byte)(1 << (cursor & 7));
                }
                cursor++;
            }
            // Emit high 1-bits
            for (int h = 0; h < high; h++) {
                if (cursor >= capacity) return -1;
                dst[cursor >> 3] |= (byte)(1 << (cursor & 7));
                cursor++;
            }
            // Emit terminating 0-bit
            if (cursor >= capacity) return -1;
            cursor++; // bit is already 0 (dst is zero-initialized)

            // Emit sign bit
            if (cursor >= capacity) return -1;
            if (s < 0) {
                dst[cursor >> 3] |= (byte)(1 << (cursor & 7));
            }
            cursor++;
        }

        return (cursor + 7) / 8;
    }

    /**
     * Decompress s1 from src. Returns null if malformed.
     * Rejects non-canonical: zero with sign bit=1 (FIPS 206 §3.11.5).
     */
    private static int[] decompressS1(byte[] src, int n, int lo) {
        int totalBits = src.length * 8;
        int cursor = 0;
        int[] out = new int[n];

        for (int i = 0; i < n; i++) {
            // Read lo bits (LSB-first)
            int low = 0;
            for (int b = 0; b < lo; b++) {
                if (cursor >= totalBits) return null;
                int bit = (src[cursor >> 3] >> (cursor & 7)) & 1;
                low |= bit << b;
                cursor++;
            }
            // Read unary high (count 1-bits until 0)
            int high = 0;
            while (true) {
                if (cursor >= totalBits) return null;
                int bit = (src[cursor >> 3] >> (cursor & 7)) & 1;
                cursor++;
                if (bit == 0) break;
                high++;
            }
            // Read sign bit
            if (cursor >= totalBits) return null;
            int signBit = (src[cursor >> 3] >> (cursor & 7)) & 1;
            cursor++;

            int v = (high << lo) | low;
            if (signBit == 1) {
                if (v == 0) return null; // non-canonical zero
                v = -v;
            }
            out[i] = v;
        }
        return out;
    }
}
