package com.pqc.mldsa;

import com.pqc.common.Keccak;

import static com.pqc.mldsa.DsaField.Q;

/**
 * Hash and sampling functions for ML-DSA (FIPS 204).
 * Uses SHAKE-128/256 via the shared Keccak implementation.
 */
public final class DsaHash {

    private DsaHash() {}

    /** SHAKE-256 hash function H (variable output). */
    public static byte[] h(byte[] input, int outputLen) {
        return Keccak.shake256(input, outputLen);
    }

    /**
     * ExpandA: Generate the k x l matrix A in NTT domain from seed rho.
     * A[i][j] = SampleNTT(SHAKE-128(rho || j || i)).
     * Each element is a polynomial of 256 coefficients in Z_q.
     */
    public static int[][] expandA(byte[] rho, int k, int l) {
        int[][] aHat = new int[k * l][];
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < l; j++) {
                byte[] input = new byte[rho.length + 2];
                System.arraycopy(rho, 0, input, 0, rho.length);
                // FIPS 204: IntegerToBytes(s, 2) where s = 256*i + j => two bytes little-endian
                int s = 256 * i + j;
                input[rho.length] = (byte)(s & 0xFF);
                input[rho.length + 1] = (byte)((s >> 8) & 0xFF);
                aHat[i * l + j] = rejNttPoly(input);
            }
        }
        return aHat;
    }

    /**
     * Rejection sampling of NTT polynomial from XOF output (SHAKE-128).
     */
    private static int[] rejNttPoly(byte[] seed) {
        // Generate enough bytes - 3 bytes yield up to 2 candidates
        // Need 256 coefficients; generate plenty of bytes
        byte[] buf = Keccak.shake128(seed, 256 * 3);
        int[] a = new int[256];
        int j = 0;
        int pos = 0;
        while (j < 256) {
            if (pos + 3 > buf.length) {
                // Need more bytes (very unlikely)
                byte[] more = Keccak.shake128(seed, buf.length * 2);
                buf = more;
                // pos stays the same
            }
            // Extract 3 bytes -> 2 candidates (each < 2^23)
            int b0 = buf[pos] & 0xFF;
            int b1 = buf[pos + 1] & 0xFF;
            int b2 = buf[pos + 2] & 0xFF;
            int d1 = b0 | ((b1 & 0x0F) << 8) | (b2 << 12);
            // Correction: for Dilithium/ML-DSA, coefficients are mod q = 8380417 < 2^23
            // We use CoeffFromThreeBytes: extract 23-bit values
            int val = b0 | (b1 << 8) | ((b2 & 0x7F) << 16);
            if (val < Q) {
                a[j++] = val;
            }
            pos += 3;
        }
        return a;
    }

    /**
     * ExpandS: Generate secret vectors s1 (l polynomials) and s2 (k polynomials)
     * from seed rhoPrime, with coefficients in [-eta, eta].
     * Uses SHAKE-256 with domain separation.
     */
    public static int[][] expandS(byte[] rhoPrime, int k, int l, int eta) {
        int[][] s = new int[k + l][];
        for (int r = 0; r < k + l; r++) {
            byte[] input = new byte[rhoPrime.length + 2];
            System.arraycopy(rhoPrime, 0, input, 0, rhoPrime.length);
            input[rhoPrime.length] = (byte)(r & 0xFF);
            input[rhoPrime.length + 1] = (byte)((r >> 8) & 0xFF);
            s[r] = rejBoundedPoly(input, eta);
        }
        return s;
    }

    /**
     * Rejection bounded polynomial: sample coefficients in [-eta, eta].
     */
    private static int[] rejBoundedPoly(byte[] seed, int eta) {
        int[] a = new int[256];
        byte[] buf = Keccak.shake256(seed, 256 * 2); // plenty of bytes
        int j = 0;
        int pos = 0;
        while (j < 256) {
            if (pos >= buf.length) {
                buf = Keccak.shake256(seed, buf.length * 2);
            }
            int z = buf[pos] & 0xFF;
            int z0 = z & 0x0F;
            int z1 = z >> 4;
            pos++;

            if (eta == 2) {
                if (z0 < 15) {
                    // z0 mod 5 gives value in [0,4], map to [-2,2] by subtracting eta
                    a[j++] = DsaField.modQ(2 - (z0 % 5));
                    if (j >= 256) break;
                }
                if (z1 < 15) {
                    a[j++] = DsaField.modQ(2 - (z1 % 5));
                }
            } else { // eta == 4
                if (z0 < 9) {
                    a[j++] = DsaField.modQ(4 - z0);
                    if (j >= 256) break;
                }
                if (z1 < 9) {
                    a[j++] = DsaField.modQ(4 - z1);
                }
            }
        }
        return a;
    }

    /**
     * ExpandMask: Generate masking vector y from seed and nonce.
     * Each polynomial has coefficients in [-(gamma1-1), gamma1-1].
     */
    public static int[][] expandMask(byte[] rhoPrime, int kappa, int l, int gamma1) {
        int[][] y = new int[l][];
        int gamma1Bits = (gamma1 == 131072) ? 17 : 19; // 2^17 or 2^19
        int polyBytes = 32 * gamma1Bits; // bytes per polynomial
        for (int r = 0; r < l; r++) {
            byte[] input = new byte[rhoPrime.length + 2];
            System.arraycopy(rhoPrime, 0, input, 0, rhoPrime.length);
            int idx = kappa + r;
            input[rhoPrime.length] = (byte)(idx & 0xFF);
            input[rhoPrime.length + 1] = (byte)((idx >> 8) & 0xFF);
            byte[] buf = Keccak.shake256(input, polyBytes);
            y[r] = bitUnpackGamma1(buf, gamma1, gamma1Bits);
        }
        return y;
    }

    /**
     * Unpack polynomial with coefficients in [-(gamma1-1), gamma1].
     */
    private static int[] bitUnpackGamma1(byte[] buf, int gamma1, int bits) {
        int[] r = new int[256];
        for (int i = 0; i < 256; i++) {
            long val = 0;
            int bitStart = i * bits;
            for (int b = 0; b < bits; b++) {
                int bitIdx = bitStart + b;
                int byteIdx = bitIdx / 8;
                int bitOff = bitIdx % 8;
                if (byteIdx < buf.length) {
                    val |= (long)((buf[byteIdx] >> bitOff) & 1) << b;
                }
            }
            // Value is gamma1 - coeff, so coeff = gamma1 - val
            r[i] = DsaField.modQ(gamma1 - (int)val);
        }
        return r;
    }

    /**
     * SampleInBall: Generate challenge polynomial c with exactly tau +/-1 coefficients.
     * Uses SHAKE-256(seed).
     */
    public static int[] sampleInBall(byte[] seed, int tau) {
        byte[] buf = Keccak.shake256(seed, 8 + 256); // 8 bytes for signs + enough for indices
        int[] c = new int[256];

        // First 8 bytes encode signs
        long signs = 0;
        for (int i = 0; i < 8; i++) {
            signs |= ((long)(buf[i] & 0xFF)) << (8 * i);
        }

        int pos = 8;
        for (int i = 256 - tau; i < 256; i++) {
            int j;
            // Sample j uniformly from [0, i]
            while (true) {
                if (pos >= buf.length) {
                    buf = Keccak.shake256(seed, buf.length * 2);
                }
                j = buf[pos++] & 0xFF;
                if (j <= i) break;
            }
            c[i] = c[j];
            c[j] = 1 - 2 * (int)(signs & 1);
            signs >>= 1;
        }
        return c;
    }
}
