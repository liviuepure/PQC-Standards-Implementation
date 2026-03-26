package com.pqc.mlkem;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Hash functions for ML-KEM (FIPS 203).
 * G = SHA3-512, H = SHA3-256, J = SHAKE-256(32 bytes).
 * XOF = SHAKE-128, PRF = SHAKE-256.
 *
 * Implements Keccak-f[1600] sponge for SHAKE-128/256 to support Java 17
 * without external dependencies.
 */
public final class HashFuncs {

    private HashFuncs() {}

    // ========================================================================
    // Keccak-f[1600] permutation and sponge construction
    // ========================================================================

    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
        0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[] ROTATION_OFFSETS = {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    };

    private static final int[] PI_LANE = {
        0, 10, 20, 5, 15,
        16, 1, 11, 21, 6,
        7, 17, 2, 12, 22,
        23, 8, 18, 3, 13,
        14, 24, 9, 19, 4
    };

    /**
     * Keccak-f[1600] permutation (24 rounds).
     */
    private static void keccakF1600(long[] state) {
        long[] c = new long[5];
        long[] d = new long[5];
        long[] b = new long[25];

        for (int round = 0; round < 24; round++) {
            // Theta
            for (int x = 0; x < 5; x++) {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                d[x] = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
            }
            for (int i = 0; i < 25; i++) {
                state[i] ^= d[i % 5];
            }

            // Rho and Pi
            for (int i = 0; i < 25; i++) {
                b[PI_LANE[i]] = Long.rotateLeft(state[i], ROTATION_OFFSETS[i]);
            }

            // Chi
            for (int y = 0; y < 5; y++) {
                for (int x = 0; x < 5; x++) {
                    state[y * 5 + x] = b[y * 5 + x] ^ (~b[y * 5 + (x + 1) % 5] & b[y * 5 + (x + 2) % 5]);
                }
            }

            // Iota
            state[0] ^= RC[round];
        }
    }

    /**
     * Absorb data into the sponge state with given rate (in bytes) and domain separation byte.
     * Keccak pad10*1 padding: data || domainSep || 0x00...0x00 || 0x80
     * where the total length is a multiple of rateBytes.
     * If domainSep lands on the last byte of a block, it gets ORed with 0x80.
     */
    private static long[] keccakAbsorb(byte[] data, int rateBytes, byte domainSep) {
        long[] state = new long[25];

        // Compute padded length: must be a multiple of rateBytes and
        // have room for at least the domain separator byte.
        int minLen = data.length + 1;
        int totalLen;
        if (minLen % rateBytes == 0) {
            totalLen = minLen;
        } else {
            totalLen = minLen + (rateBytes - (minLen % rateBytes));
        }

        byte[] padded = new byte[totalLen];
        System.arraycopy(data, 0, padded, 0, data.length);
        padded[data.length] = domainSep;
        padded[totalLen - 1] |= (byte) 0x80;

        // Absorb blocks
        int rateLongs = rateBytes / 8;
        for (int offset = 0; offset < totalLen; offset += rateBytes) {
            for (int i = 0; i < rateLongs; i++) {
                long val = 0;
                for (int j = 0; j < 8; j++) {
                    val |= ((long)(padded[offset + i * 8 + j] & 0xFF)) << (8 * j);
                }
                state[i] ^= val;
            }
            keccakF1600(state);
        }
        return state;
    }

    /**
     * Squeeze output from the sponge state.
     */
    private static byte[] keccakSqueeze(long[] state, int rateBytes, int outputLen) {
        byte[] output = new byte[outputLen];
        int rateLongs = rateBytes / 8;
        int offset = 0;

        while (offset < outputLen) {
            // Extract from current state
            for (int i = 0; i < rateLongs && offset < outputLen; i++) {
                long val = state[i];
                for (int j = 0; j < 8 && offset < outputLen; j++) {
                    output[offset++] = (byte) (val >> (8 * j));
                }
            }
            if (offset < outputLen) {
                keccakF1600(state);
            }
        }
        return output;
    }

    /**
     * SHAKE-128: XOF with 168-byte rate.
     */
    public static byte[] shake128(byte[] input, int outputLen) {
        long[] state = keccakAbsorb(input, 168, (byte) 0x1F);
        return keccakSqueeze(state, 168, outputLen);
    }

    /**
     * SHAKE-256: XOF with 136-byte rate.
     */
    public static byte[] shake256(byte[] input, int outputLen) {
        long[] state = keccakAbsorb(input, 136, (byte) 0x1F);
        return keccakSqueeze(state, 136, outputLen);
    }

    // ========================================================================
    // ML-KEM specific hash functions
    // ========================================================================

    /**
     * G: SHA3-512. Returns [rho (32 bytes), sigma (32 bytes)].
     */
    public static byte[][] G(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-512");
            byte[] hash = md.digest(input);
            byte[] rho = Arrays.copyOfRange(hash, 0, 32);
            byte[] sigma = Arrays.copyOfRange(hash, 32, 64);
            return new byte[][]{rho, sigma};
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA3-512 not available", e);
        }
    }

    /**
     * H: SHA3-256.
     */
    public static byte[] H(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA3-256 not available", e);
        }
    }

    /**
     * J: SHAKE-256 with 32-byte output.
     */
    public static byte[] J(byte[] input) {
        return shake256(input, 32);
    }

    /**
     * XOF: SHAKE-128. Input is rho || i || j; output 672 bytes (enough for SampleNTT).
     */
    public static byte[] xof(byte[] rho, int i, int j) {
        byte[] input = new byte[rho.length + 2];
        System.arraycopy(rho, 0, input, 0, rho.length);
        input[rho.length] = (byte) i;
        input[rho.length + 1] = (byte) j;
        return shake128(input, 672);
    }

    /**
     * PRF: SHAKE-256. Input is s || b; output 'length' bytes.
     */
    public static byte[] prf(byte[] s, int b, int length) {
        byte[] input = new byte[s.length + 1];
        System.arraycopy(s, 0, input, 0, s.length);
        input[s.length] = (byte) b;
        return shake256(input, length);
    }
}
