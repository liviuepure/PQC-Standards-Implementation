package com.pqc.fndsa;

/**
 * FN-DSA verification (FIPS 206 Algorithm 4).
 */
final class Verify {

    private Verify() {}

    static final int Q = Params.Q;

    /**
     * Verify a FN-DSA signature.
     *
     * Returns true iff sig is a valid FN-DSA signature on msg under public key pk
     * for parameter set p.
     */
    static boolean verify(byte[] pk, byte[] msg, byte[] sig, Params p) {
        // 1. Decode public key
        int[] h = Encode.decodePk(pk, p);
        if (h == null) return false;

        // 2. Decode signature
        Object[] sigParts = Encode.decodeSig(sig, p);
        if (sigParts == null) return false;
        byte[] salt = (byte[]) sigParts[0];
        int[] s1 = (int[]) sigParts[1];

        // 3. Recompute c = HashToPoint(salt || msg)
        byte[] hashInput = new byte[40 + msg.length];
        System.arraycopy(salt, 0, hashInput, 0, 40);
        System.arraycopy(msg, 0, hashInput, 40, msg.length);
        int[] c = Sign.hashToPoint(hashInput, p);

        // 4. Compute s2 = c - s1*h (mod q), centered
        int n = p.n;
        int[] s1ModQ = new int[n];
        for (int i = 0; i < n; i++) {
            s1ModQ[i] = ((s1[i] % Q) + Q) % Q;
        }
        int[] s1h = NTT.polyMul(s1ModQ, h, n);
        int[] s2 = new int[n];
        for (int i = 0; i < n; i++) {
            s2[i] = NTT.centerModQ(c[i] - s1h[i]);
        }

        // 5. Norm check: ||(s1,s2)||^2 <= beta^2
        return Sign.normSq(s1, s2) <= p.betaSq;
    }
}
