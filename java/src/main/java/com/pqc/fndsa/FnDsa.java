package com.pqc.fndsa;

import java.security.SecureRandom;

/**
 * FN-DSA public API (FIPS 206 / FALCON).
 *
 * Provides key generation, signing, and verification for all four parameter sets:
 *   - FNDSA512, FNDSA1024 (variable-length signatures)
 *   - FNDSA_PADDED_512, FNDSA_PADDED_1024 (fixed-length padded signatures)
 */
public final class FnDsa {

    private FnDsa() {}

    /**
     * Generate a key pair for the given parameter set.
     *
     * @param p   parameter set (e.g. Params.FNDSA512)
     * @param rng cryptographically secure random number generator
     * @return [pk, sk] -- public key and secret key as byte arrays
     */
    public static byte[][] keyGen(Params p, SecureRandom rng) {
        int[][] fgF = NTRUKeygen.ntruKeygen(p, rng);
        int[] f = fgF[0];
        int[] g = fgF[1];
        int[] F = fgF[2];

        // Compute public key h = g * f^{-1} mod (q, x^n+1)
        int n = p.n;
        int[] fNtt = new int[n];
        int[] gNtt = new int[n];
        for (int i = 0; i < n; i++) {
            fNtt[i] = ((f[i] % Params.Q) + Params.Q) % Params.Q;
            gNtt[i] = ((g[i] % Params.Q) + Params.Q) % Params.Q;
        }
        NTT.ntt(fNtt, n);
        NTT.ntt(gNtt, n);
        int[] fInvNtt = new int[n];
        for (int i = 0; i < n; i++) {
            fInvNtt[i] = (int) NTT.modPow(fNtt[i], Params.Q - 2);
        }
        int[] hNtt = new int[n];
        for (int i = 0; i < n; i++) {
            hNtt[i] = NTT.mulModQ(gNtt[i], fInvNtt[i]);
        }
        NTT.intt(hNtt, n);

        byte[] pk = Encode.encodePk(hNtt, p);
        byte[] sk = Encode.encodeSk(f, g, F, p);

        return new byte[][] {pk, sk};
    }

    /**
     * Sign a message using the secret key.
     *
     * @param sk  secret key bytes
     * @param msg message to sign
     * @param p   parameter set matching the secret key
     * @param rng cryptographically secure random number generator
     * @return signature bytes
     * @throws IllegalArgumentException if sk is invalid
     * @throws IllegalStateException    if signing fails (should be extremely rare)
     */
    public static byte[] sign(byte[] sk, byte[] msg, Params p, SecureRandom rng) {
        return Sign.signInternal(sk, msg, p, rng);
    }

    /**
     * Verify a signature.
     *
     * @param pk  public key bytes
     * @param msg message that was signed
     * @param sig signature bytes
     * @param p   parameter set matching the public key
     * @return true iff the signature is valid
     */
    public static boolean verify(byte[] pk, byte[] msg, byte[] sig, Params p) {
        return Verify.verify(pk, msg, sig, p);
    }
}
