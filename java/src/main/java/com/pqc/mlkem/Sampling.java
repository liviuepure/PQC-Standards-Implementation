package com.pqc.mlkem;

import static com.pqc.mlkem.Field.Q;

/**
 * Sampling algorithms for ML-KEM (FIPS 203 Algorithms 7 and 8).
 */
public final class Sampling {

    private Sampling() {}

    /**
     * Algorithm 7: SampleNTT.
     * Rejection sampling from XOF bytes to produce a polynomial in NTT domain.
     * Input: at least 672 bytes (sufficient with overwhelming probability).
     */
    public static int[] sampleNTT(byte[] xofBytes) {
        int[] a = new int[256];
        int j = 0;
        int i = 0;
        while (j < 256) {
            int d1 = (xofBytes[i] & 0xFF) | (((xofBytes[i + 1] & 0xFF) & 0x0F) << 8);
            int d2 = ((xofBytes[i + 1] & 0xFF) >> 4) | ((xofBytes[i + 2] & 0xFF) << 4);
            if (d1 < Q) {
                a[j++] = d1;
            }
            if (d2 < Q && j < 256) {
                a[j++] = d2;
            }
            i += 3;
        }
        return a;
    }

    /**
     * Algorithm 8: SamplePolyCBD.
     * Sample from centered binomial distribution with parameter eta.
     * Input: 64*eta bytes.
     */
    public static int[] samplePolyCBD(byte[] bytes, int eta) {
        int[] f = new int[256];
        // Convert bytes to bits
        int[] bits = new int[bytes.length * 8];
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                bits[8 * i + j] = (bytes[i] >> j) & 1;
            }
        }

        for (int i = 0; i < 256; i++) {
            int x = 0;
            int y = 0;
            for (int j = 0; j < eta; j++) {
                x += bits[2 * i * eta + j];
                y += bits[2 * i * eta + eta + j];
            }
            f[i] = Field.mod(x - y, Q);
        }
        return f;
    }
}
