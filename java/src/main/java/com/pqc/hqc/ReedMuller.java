package com.pqc.hqc;

/**
 * Reed-Muller code RM(1, 7) for HQC.
 * <p>
 * The first-order Reed-Muller code RM(1, 7) encodes 8 bits (1 byte)
 * into 128 bits (16 bytes). The encoding uses the generator matrix
 * of RM(1, 7), which consists of the all-ones word and the 7 rows
 * of the Walsh-Hadamard basis vectors.
 * <p>
 * For HQC, the RM codeword is then duplicated (multiplicity times)
 * to form an n2-bit codeword for additional error correction.
 */
final class ReedMuller {

    private ReedMuller() {}

    /** Base Reed-Muller codeword length = 2^7 = 128 bits. */
    static final int RM_BASE_LEN = 128;

    /**
     * Encodes a single byte (8 bits) into a 128-bit RM(1,7) codeword.
     * Returns [lo, hi] representing 128 bits.
     */
    static long[] encodeBase(int msg) {
        long lo = 0, hi = 0;

        // Bit 0: constant row (all-ones if set)
        long m0 = -((long) ((msg) & 1));
        lo ^= m0;
        hi ^= m0;

        // Bit 1: pattern 0xAAAAAAAAAAAAAAAA
        long m1 = -((long) ((msg >>> 1) & 1));
        lo ^= m1 & 0xAAAAAAAAAAAAAAAAL;
        hi ^= m1 & 0xAAAAAAAAAAAAAAAAL;

        // Bit 2: pattern 0xCCCCCCCCCCCCCCCC
        long m2 = -((long) ((msg >>> 2) & 1));
        lo ^= m2 & 0xCCCCCCCCCCCCCCCCL;
        hi ^= m2 & 0xCCCCCCCCCCCCCCCCL;

        // Bit 3: pattern 0xF0F0F0F0F0F0F0F0
        long m3 = -((long) ((msg >>> 3) & 1));
        lo ^= m3 & 0xF0F0F0F0F0F0F0F0L;
        hi ^= m3 & 0xF0F0F0F0F0F0F0F0L;

        // Bit 4: pattern 0xFF00FF00FF00FF00
        long m4 = -((long) ((msg >>> 4) & 1));
        lo ^= m4 & 0xFF00FF00FF00FF00L;
        hi ^= m4 & 0xFF00FF00FF00FF00L;

        // Bit 5: pattern 0xFFFF0000FFFF0000
        long m5 = -((long) ((msg >>> 5) & 1));
        lo ^= m5 & 0xFFFF0000FFFF0000L;
        hi ^= m5 & 0xFFFF0000FFFF0000L;

        // Bit 6: pattern 0xFFFFFFFF00000000
        long m6 = -((long) ((msg >>> 6) & 1));
        lo ^= m6 & 0xFFFFFFFF00000000L;
        hi ^= m6 & 0xFFFFFFFF00000000L;

        // Bit 7: (0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
        long m7 = -((long) ((msg >>> 7) & 1));
        hi ^= m7;

        return new long[]{ lo, hi };
    }

    /**
     * Decodes an n2-bit received codeword (with duplicated RM(1,7))
     * to a single byte using Walsh-Hadamard transform.
     */
    static int decode(long[] src, int n2, int multiplicity) {
        // Step 1: Accumulate all copies into a signed sum array of 128 entries.
        int[] sums = new int[RM_BASE_LEN];

        int bitPos = 0;
        for (int rep = 0; rep < multiplicity; rep++) {
            for (int i = 0; i < RM_BASE_LEN; i++) {
                int wordIdx = bitPos / 64;
                int bitIdx = bitPos % 64;
                int bit = 0;
                if (wordIdx < src.length) {
                    bit = (int) ((src[wordIdx] >>> bitIdx) & 1);
                }
                // Convert 0/1 to +1/-1 (0 -> +1, 1 -> -1)
                sums[i] += 1 - 2 * bit;
                bitPos++;
            }
        }

        // Step 2: Fast Walsh-Hadamard Transform (in-place, 7 passes)
        for (int pass = 0; pass < 7; pass++) {
            int step = 1 << pass;
            for (int i = 0; i < RM_BASE_LEN; i += 2 * step) {
                for (int j = i; j < i + step; j++) {
                    int a = sums[j];
                    int b = sums[j + step];
                    sums[j] = a + b;
                    sums[j + step] = a - b;
                }
            }
        }

        // Step 3: Find the position with maximum absolute value
        int maxAbs = 0;
        int maxPos = 0;
        int sign = 1;

        for (int i = 0; i < RM_BASE_LEN; i++) {
            int v = sums[i];
            int abs = (v < 0) ? -v : v;
            if (abs > maxAbs) {
                maxAbs = abs;
                maxPos = i;
                sign = (v > 0) ? 1 : -1;
            }
        }

        // Step 4: Recover the message byte.
        int msg = (maxPos << 1) & 0xFF;
        if (sign < 0) {
            msg |= 1;
        }
        return msg;
    }

    /**
     * Encodes a byte into the dst vector starting at bitOffset,
     * with the given number of repetitions.
     */
    static void encodeInto(long[] dst, int msg, int bitOffset, int multiplicity) {
        long[] base = encodeBase(msg);

        int bitPos = bitOffset;
        for (int rep = 0; rep < multiplicity; rep++) {
            for (int w = 0; w < 2; w++) {
                long word = base[w];
                int dstWord = bitPos / 64;
                int dstBit = bitPos % 64;

                if (dstBit == 0 && dstWord < dst.length) {
                    dst[dstWord] ^= word;
                    bitPos += 64;
                } else {
                    for (int bit = 0; bit < 64; bit++) {
                        if ((word & (1L << bit)) != 0) {
                            int idx = bitPos / 64;
                            int off = bitPos % 64;
                            if (idx < dst.length) {
                                dst[idx] ^= 1L << off;
                            }
                        }
                        bitPos++;
                    }
                }
            }
        }
    }
}
