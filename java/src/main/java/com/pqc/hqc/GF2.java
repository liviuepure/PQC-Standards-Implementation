package com.pqc.hqc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * GF(2) polynomial arithmetic: polynomials over GF(2) packed into long[] words.
 * Each polynomial has at most n bits. Arithmetic is in GF(2)[x]/(x^n - 1).
 */
final class GF2 {

    private GF2() {}

    /** Polynomial addition in GF(2): out = a XOR b. */
    static long[] vectAdd(long[] a, long[] b) {
        int n = a.length;
        long[] out = new long[n];
        for (int i = 0; i < n; i++) {
            out[i] = a[i] ^ b[i];
        }
        return out;
    }

    /** In-place addition: a ^= b. */
    static void vectAddInPlace(long[] a, long[] b) {
        for (int i = 0; i < b.length; i++) {
            a[i] ^= b[i];
        }
    }

    /** Sets bit at position pos in the vector v. */
    static void vectSetBit(long[] v, int pos) {
        v[pos / 64] |= 1L << (pos % 64);
    }

    /** Returns the bit at position pos in the vector v (0 or 1). */
    static long vectGetBit(long[] v, int pos) {
        return (v[pos / 64] >>> (pos % 64)) & 1L;
    }

    /** Returns the Hamming weight of a GF(2) vector. */
    static int vectWeight(long[] v) {
        int w = 0;
        for (long word : v) {
            w += Long.bitCount(word);
        }
        return w;
    }

    /** Converts a long[] vector to bytes (little-endian). */
    static byte[] vectToBytes(long[] v, int nBytes) {
        byte[] out = new byte[nBytes];
        for (int i = 0; i < v.length && i * 8 < nBytes; i++) {
            int remaining = nBytes - i * 8;
            if (remaining >= 8) {
                long val = v[i];
                int off = i * 8;
                out[off]     = (byte) val;
                out[off + 1] = (byte) (val >>> 8);
                out[off + 2] = (byte) (val >>> 16);
                out[off + 3] = (byte) (val >>> 24);
                out[off + 4] = (byte) (val >>> 32);
                out[off + 5] = (byte) (val >>> 40);
                out[off + 6] = (byte) (val >>> 48);
                out[off + 7] = (byte) (val >>> 56);
            } else {
                long val = v[i];
                int off = i * 8;
                for (int j = 0; j < remaining; j++) {
                    out[off + j] = (byte) (val >>> (j * 8));
                }
            }
        }
        return out;
    }

    /** Converts bytes to a long[] vector (little-endian). */
    static long[] vectFromBytes(byte[] data, int nWords) {
        long[] v = new long[nWords];
        for (int i = 0; i < nWords; i++) {
            int start = i * 8;
            if (start >= data.length) break;
            int end = start + 8;
            if (end <= data.length) {
                v[i] = (data[start] & 0xFFL)
                     | ((data[start + 1] & 0xFFL) << 8)
                     | ((data[start + 2] & 0xFFL) << 16)
                     | ((data[start + 3] & 0xFFL) << 24)
                     | ((data[start + 4] & 0xFFL) << 32)
                     | ((data[start + 5] & 0xFFL) << 40)
                     | ((data[start + 6] & 0xFFL) << 48)
                     | ((data[start + 7] & 0xFFL) << 56);
            } else {
                long val = 0;
                for (int j = 0; j < data.length - start; j++) {
                    val |= (data[start + j] & 0xFFL) << (j * 8);
                }
                v[i] = val;
            }
        }
        return v;
    }

    /** Returns a copy of v truncated/masked to exactly nBits bits. */
    static long[] vectResize(long[] v, int nBits) {
        int nWords = (nBits + 63) / 64;
        long[] out = new long[nWords];
        int copyLen = Math.min(v.length, nWords);
        System.arraycopy(v, 0, out, 0, copyLen);
        int rem = nBits % 64;
        if (rem != 0 && nWords > 0) {
            out[nWords - 1] &= (1L << rem) - 1;
        }
        return out;
    }

    /** Returns 1 if a == b (constant-time), 0 otherwise. */
    static int vectEqual(long[] a, long[] b) {
        long diff = 0;
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            diff |= a[i] ^ b[i];
        }
        for (int i = n; i < a.length; i++) {
            diff |= a[i];
        }
        for (int i = n; i < b.length; i++) {
            diff |= b[i];
        }
        long d = diff | (diff >>> 32);
        d |= d >>> 16;
        d |= d >>> 8;
        d |= d >>> 4;
        d |= d >>> 2;
        d |= d >>> 1;
        return 1 - (int) (d & 1);
    }

    /**
     * Carryless multiplication of two 64-bit words.
     * Returns [lo, hi] such that a * b = hi << 64 | lo in GF(2).
     */
    static long[] baseMul(long a, long b) {
        long lo = 0, hi = 0;
        for (int i = 0; i < 64; i++) {
            if (((a >>> i) & 1) == 0) continue;
            if (i == 0) {
                lo ^= b;
            } else {
                lo ^= b << i;
                hi ^= b >>> (64 - i);
            }
        }
        return new long[]{ lo, hi };
    }

    /**
     * Schoolbook polynomial multiplication of two GF(2) polynomials.
     * Result has sizeA + sizeB words.
     */
    static long[] schoolbookMul(long[] a, int sizeA, long[] b, int sizeB) {
        long[] out = new long[sizeA + sizeB];
        for (int i = 0; i < sizeA; i++) {
            if (a[i] == 0) continue;
            for (int j = 0; j < sizeB; j++) {
                if (b[j] == 0) continue;
                long[] lohi = baseMul(a[i], b[j]);
                out[i + j] ^= lohi[0];
                out[i + j + 1] ^= lohi[1];
            }
        }
        return out;
    }

    /** Computes out = a * b mod (x^n - 1) in GF(2)[x]. */
    static long[] vectMul(long[] a, long[] b, int n) {
        int nWords = (n + 63) / 64;

        long[] aPad = new long[nWords];
        long[] bPad = new long[nWords];
        System.arraycopy(a, 0, aPad, 0, Math.min(a.length, nWords));
        System.arraycopy(b, 0, bPad, 0, Math.min(b.length, nWords));

        int rem = n % 64;
        if (rem != 0) {
            aPad[nWords - 1] &= (1L << rem) - 1;
            bPad[nWords - 1] &= (1L << rem) - 1;
        }

        long[] prod = schoolbookMul(aPad, nWords, bPad, nWords);

        // Reduce mod (x^n - 1)
        long[] out = new long[nWords];
        System.arraycopy(prod, 0, out, 0, nWords);

        int wordOff = n / 64;

        if (rem == 0) {
            for (int i = 0; i < nWords; i++) {
                if (wordOff + i < 2 * nWords) {
                    out[i] ^= prod[wordOff + i];
                }
            }
        } else {
            for (int i = 0; i < nWords; i++) {
                int idx = wordOff + i;
                if (idx < 2 * nWords) {
                    out[i] ^= prod[idx] >>> rem;
                }
                if (idx + 1 < 2 * nWords) {
                    out[i] ^= prod[idx + 1] << (64 - rem);
                }
            }
        }

        if (rem != 0) {
            out[nWords - 1] &= (1L << rem) - 1;
        }

        return out;
    }
}
