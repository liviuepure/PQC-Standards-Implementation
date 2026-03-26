package com.pqc.mlkem;

/**
 * Byte encoding/decoding for ML-KEM (FIPS 203 Algorithms 4 and 5).
 */
public final class Encode {

    private Encode() {}

    /**
     * Algorithm 4: ByteEncode_d.
     * Encodes an array of 256 integers (each in [0, 2^d)) into 32*d bytes.
     */
    public static byte[] byteEncode(int d, int[] F) {
        int m = (d == 12) ? (1 << 12) : ((1 << d)); // modulus for masking
        byte[] B = new byte[32 * d];
        for (int i = 0; i < 256; i++) {
            int a = F[i] % m;
            if (a < 0) a += m;
            for (int j = 0; j < d; j++) {
                int bitIndex = i * d + j;
                int byteIndex = bitIndex / 8;
                int bitOffset = bitIndex % 8;
                B[byteIndex] |= (byte) (((a >> j) & 1) << bitOffset);
            }
        }
        return B;
    }

    /**
     * Algorithm 5: ByteDecode_d.
     * Decodes 32*d bytes into an array of 256 integers.
     * For d < 12, reduce mod 2^d. For d = 12, do NOT reduce mod Q.
     */
    public static int[] byteDecode(int d, byte[] B) {
        int m = (1 << d);
        int[] F = new int[256];
        for (int i = 0; i < 256; i++) {
            int sum = 0;
            for (int j = 0; j < d; j++) {
                int bitIndex = i * d + j;
                int byteIndex = bitIndex / 8;
                int bitOffset = bitIndex % 8;
                int bit = (B[byteIndex] >> bitOffset) & 1;
                sum += bit << j;
            }
            if (d < 12) {
                F[i] = sum % m;
            } else {
                // For d=12, do NOT reduce mod Q
                F[i] = sum;
            }
        }
        return F;
    }
}
