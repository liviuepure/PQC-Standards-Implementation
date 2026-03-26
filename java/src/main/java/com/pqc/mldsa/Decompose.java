package com.pqc.mldsa;

import static com.pqc.mldsa.DsaField.*;

/**
 * Decomposition, rounding, and hint functions for ML-DSA (FIPS 204).
 * Based on the CRYSTALS-Dilithium reference implementation rounding.c.
 */
public final class Decompose {

    private Decompose() {}

    /**
     * Power2Round: decompose r into (r1, r0) such that r = r1 * 2^d + r0
     * with r0 in [-(2^(d-1)-1), 2^(d-1)].
     * d = 13 for ML-DSA.
     */
    public static int[] power2Round(int r) {
        int rPlus = ((r % Q) + Q) % Q;
        int r0 = centeredMod(rPlus, 1 << 13);
        int r1 = (rPlus - r0) >> 13;
        return new int[]{r1, r0};
    }

    /**
     * Decompose: decompose r into (r1, r0) such that r = r1 * 2 * gamma2 + r0.
     * Follows the reference implementation approach.
     * Returns [r1, r0] where r0 is in centered form.
     */
    public static int[] decompose(int r, int gamma2) {
        int rPlus = ((r % Q) + Q) % Q;

        // Reference implementation approach using fixed-point arithmetic
        int r1 = (rPlus + 127) >> 7;
        if (gamma2 == (Q - 1) / 32) {
            r1 = (int)(((long)r1 * 1025 + (1 << 21)) >> 22);
            r1 &= 15;
        } else { // gamma2 == (Q - 1) / 88
            r1 = (int)(((long)r1 * 11275 + (1 << 23)) >> 24);
            r1 ^= ((43 - r1) >> 31) & r1;
        }

        int r0 = rPlus - r1 * 2 * gamma2;
        // Centered reduction: if r0 > (Q-1)/2, subtract Q
        r0 -= (((Q - 1) / 2 - r0) >> 31) & Q;
        return new int[]{r1, r0};
    }

    /**
     * HighBits: extract high bits from r.
     */
    public static int highBits(int r, int gamma2) {
        return decompose(r, gamma2)[0];
    }

    /**
     * LowBits: extract low bits from r.
     */
    public static int lowBits(int r, int gamma2) {
        return decompose(r, gamma2)[1];
    }

    /**
     * MakeHint: compute hint bit.
     * Per the reference implementation: takes a0 (low bits) and a1 (high bits).
     * Returns 1 if |a0| > gamma2, or (a0 == -gamma2 and a1 != 0).
     */
    public static int makeHint(int a0, int a1, int gamma2) {
        if (a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0)) {
            return 1;
        }
        return 0;
    }

    /**
     * UseHint: use hint to recover high bits.
     * Per the reference implementation.
     */
    public static int useHint(int hint, int r, int gamma2) {
        int[] parts = decompose(r, gamma2);
        int r1 = parts[0];
        int r0 = parts[1];

        if (hint == 0) return r1;

        if (gamma2 == (Q - 1) / 32) {
            if (r0 > 0) return (r1 + 1) & 15;
            else return (r1 - 1) & 15;
        } else { // gamma2 == (Q - 1) / 88
            if (r0 > 0) return (r1 == 43) ? 0 : r1 + 1;
            else return (r1 == 0) ? 43 : r1 - 1;
        }
    }

    /**
     * Centered modular reduction: map a into [-(alpha/2)+1, alpha/2].
     */
    private static int centeredMod(int a, int alpha) {
        int r = a % alpha;
        if (r < 0) r += alpha;
        if (r > alpha / 2) r -= alpha;
        return r;
    }
}
