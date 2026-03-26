package com.pqc.mlkem;

import static com.pqc.mlkem.Field.Q;

/**
 * Compression and decompression for ML-KEM (FIPS 203 Section 4.2.1).
 */
public final class Compress {

    private Compress() {}

    /**
     * Compress_d: rounds x * 2^d / Q to nearest integer mod 2^d.
     */
    public static int compress(int d, int x) {
        // compress_d(x) = round(2^d / q * x) mod 2^d
        long twoPowD = 1L << d;
        // Use (2^d * x + q/2) / q to get rounding
        long val = (twoPowD * x + Q / 2) / Q;
        return (int) (val % twoPowD);
    }

    /**
     * Decompress_d: y * Q / 2^d, rounded.
     */
    public static int decompress(int d, int y) {
        long twoPowD = 1L << d;
        // decompress_d(y) = round(q / 2^d * y)
        return (int) ((Q * (long) y + twoPowD / 2) / twoPowD);
    }

    /**
     * Apply compress to each coefficient of a polynomial.
     */
    public static int[] compressPoly(int d, int[] poly) {
        int[] result = new int[poly.length];
        for (int i = 0; i < poly.length; i++) {
            result[i] = compress(d, poly[i]);
        }
        return result;
    }

    /**
     * Apply decompress to each coefficient of a polynomial.
     */
    public static int[] decompressPoly(int d, int[] poly) {
        int[] result = new int[poly.length];
        for (int i = 0; i < poly.length; i++) {
            result[i] = decompress(d, poly[i]);
        }
        return result;
    }
}
