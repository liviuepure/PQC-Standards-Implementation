package com.pqc.mlkem;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import static com.pqc.mlkem.Field.Q;

/**
 * ML-KEM public API (FIPS 203 Algorithms 16, 17, 18).
 */
public final class MLKEM {

    private MLKEM() {}

    public record KeyPair(byte[] ek, byte[] dk) {}

    public record EncapsResult(byte[] sharedSecret, byte[] ciphertext) {}

    /**
     * Algorithm 16: ML-KEM.KeyGen.
     */
    public static KeyPair keyGen(Params params) {
        SecureRandom rng = new SecureRandom();
        byte[] d = new byte[32];
        byte[] z = new byte[32];
        rng.nextBytes(d);
        rng.nextBytes(z);

        KPKE.KeyPair inner = KPKE.keyGen(d, params);
        byte[] ek = inner.ekPKE();
        byte[] h = HashFuncs.H(ek);

        // dk = dkPKE || ek || H(ek) || z
        byte[] dk = new byte[params.dkSize];
        System.arraycopy(inner.dkPKE(), 0, dk, 0, inner.dkPKE().length);
        System.arraycopy(ek, 0, dk, inner.dkPKE().length, ek.length);
        System.arraycopy(h, 0, dk, inner.dkPKE().length + ek.length, 32);
        System.arraycopy(z, 0, dk, inner.dkPKE().length + ek.length + 32, 32);

        return new KeyPair(ek, dk);
    }

    /**
     * Algorithm 17: ML-KEM.Encaps.
     * Validates ek, then encapsulates.
     */
    public static EncapsResult encaps(byte[] ek, Params params) {
        // Validate ek: check modulus
        validateEk(ek, params);

        SecureRandom rng = new SecureRandom();
        byte[] m = new byte[32];
        rng.nextBytes(m);

        byte[] hEk = HashFuncs.H(ek);
        byte[][] gResult = HashFuncs.G(concat(m, hEk));
        byte[] K = gResult[0];
        byte[] r = gResult[1];

        byte[] c = KPKE.encrypt(ek, m, r, params);
        return new EncapsResult(K, c);
    }

    /**
     * Algorithm 18: ML-KEM.Decaps.
     * Decapsulates with implicit rejection.
     */
    public static byte[] decaps(byte[] dk, byte[] c, Params params) {
        int k = params.k;
        int dkPKELen = 384 * k;
        int ekLen = 384 * k + 32;

        byte[] dkPKE = Arrays.copyOfRange(dk, 0, dkPKELen);
        byte[] ek = Arrays.copyOfRange(dk, dkPKELen, dkPKELen + ekLen);
        byte[] h = Arrays.copyOfRange(dk, dkPKELen + ekLen, dkPKELen + ekLen + 32);
        byte[] z = Arrays.copyOfRange(dk, dkPKELen + ekLen + 32, dkPKELen + ekLen + 64);

        byte[] mPrime = KPKE.decrypt(dkPKE, c, params);

        byte[][] gResult = HashFuncs.G(concat(mPrime, h));
        byte[] KPrime = gResult[0];
        byte[] rPrime = gResult[1];

        byte[] KBar = HashFuncs.J(concat(z, c));
        byte[] cPrime = KPKE.encrypt(ek, mPrime, rPrime, params);

        // Constant-time comparison
        boolean equal = MessageDigest.isEqual(c, cPrime);
        return equal ? KPrime : KBar;
    }

    /**
     * Validate encapsulation key per FIPS 203: re-encode each decoded polynomial
     * and check length.
     */
    static void validateEk(byte[] ek, Params params) {
        if (ek.length != params.ekSize) {
            throw new IllegalArgumentException("Invalid ek length: expected "
                    + params.ekSize + ", got " + ek.length);
        }
        int k = params.k;
        for (int i = 0; i < k; i++) {
            byte[] slice = Arrays.copyOfRange(ek, 384 * i, 384 * (i + 1));
            int[] decoded = Encode.byteDecode(12, slice);
            // Check each coefficient is in [0, Q)
            for (int c = 0; c < 256; c++) {
                if (decoded[c] < 0 || decoded[c] >= Q) {
                    throw new IllegalArgumentException("Invalid ek: coefficient out of range at poly "
                            + i + " index " + c + " value " + decoded[c]);
                }
            }
            // Re-encode and check match
            byte[] reencoded = Encode.byteEncode(12, decoded);
            if (!constantTimeEquals(slice, reencoded)) {
                throw new IllegalArgumentException("Invalid ek: re-encoding mismatch at poly " + i);
            }
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Constant-time byte array comparison.
     * Returns true iff a and b are equal in length and content.
     * Runs in O(n) time regardless of where the first difference occurs.
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }
}
