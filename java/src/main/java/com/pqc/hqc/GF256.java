package com.pqc.hqc;

/**
 * GF(2^8) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
 * <p>
 * This is the polynomial specified by the HQC specification for Reed-Solomon
 * encoding/decoding. The primitive element (generator) is alpha = 2.
 */
final class GF256 {

    private GF256() {}

    static final int GF_POLY = 0x11D;
    static final int GF_GEN = 2;
    static final int GF_MUL_ORDER = 255;

    static final int[] EXP = new int[512];
    static final int[] LOG = new int[256];

    static {
        initTables();
    }

    private static void initTables() {
        int x = 1;
        for (int i = 0; i < 255; i++) {
            EXP[i] = x;
            EXP[i + 255] = x;
            LOG[x] = i;
            x <<= 1;
            if (x >= 256) {
                x ^= GF_POLY;
            }
        }
        LOG[0] = 0; // convention: log(0) = 0 (never used for valid math)
        EXP[510] = EXP[0];
    }

    /** Addition in GF(2^8) = XOR. */
    static int add(int a, int b) {
        return (a ^ b) & 0xFF;
    }

    /** Multiplication in GF(2^8) via log/exp tables. */
    static int mul(int a, int b) {
        if (a == 0 || b == 0) return 0;
        return EXP[LOG[a & 0xFF] + LOG[b & 0xFF]];
    }

    /** Multiplicative inverse in GF(2^8). Returns 0 if a == 0. */
    static int inv(int a) {
        if (a == 0) return 0;
        return EXP[255 - LOG[a & 0xFF]];
    }

    /** a^n in GF(2^8). */
    static int pow(int a, int n) {
        if (a == 0) {
            return (n == 0) ? 1 : 0;
        }
        int logA = LOG[a & 0xFF];
        int logResult = (logA * n) % 255;
        if (logResult < 0) logResult += 255;
        return EXP[logResult];
    }

    /** Division a / b in GF(2^8). */
    static int div(int a, int b) {
        if (b == 0) throw new ArithmeticException("hqc: gf256 division by zero");
        if (a == 0) return 0;
        int logDiff = LOG[a & 0xFF] - LOG[b & 0xFF];
        if (logDiff < 0) logDiff += 255;
        return EXP[logDiff];
    }
}
