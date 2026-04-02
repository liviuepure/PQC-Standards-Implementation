package com.pqc.fndsa;

/**
 * NTT/INTT for FN-DSA (FIPS 206 / FALCON) mod q = 12289.
 *
 * The ring is Z[x]/(x^n + 1) with q = 12289.
 * Primitive root g = 11 (order q-1 = 12288).
 * psi_n = 11^((q-1)/(2n)) mod q -- primitive 2n-th root of unity.
 *
 * Butterfly structure follows Cooley-Tukey with bit-reversed twiddle ordering.
 * Twiddle factors are computed on-the-fly (no precomputed tables needed).
 */
final class NTT {

    private NTT() {}

    static final int Q = Params.Q;

    // Precomputed twiddle tables
    private static final int[] ZETAS_512;
    private static final int[] ZETAS_INV_512;
    private static final int[] ZETAS_1024;
    private static final int[] ZETAS_INV_1024;

    static {
        ZETAS_512 = new int[512];
        ZETAS_INV_512 = new int[512];
        ZETAS_1024 = new int[1024];
        ZETAS_INV_1024 = new int[1024];

        // psi_512 = 11^((12289-1)/(2*512)) = 11^12 mod 12289
        long psi512 = modPow(11, (Q - 1) / (2 * 512));
        for (int k = 0; k < 512; k++) {
            int br = bitRev(k, 9);
            int z = (int) modPow(psi512, br);
            ZETAS_512[k] = z;
            ZETAS_INV_512[k] = (int) modPow(z, Q - 2);
        }

        // psi_1024 = 11^((12289-1)/(2*1024)) = 11^6 mod 12289
        long psi1024 = modPow(11, (Q - 1) / (2 * 1024));
        for (int k = 0; k < 1024; k++) {
            int br = bitRev(k, 10);
            int z = (int) modPow(psi1024, br);
            ZETAS_1024[k] = z;
            ZETAS_INV_1024[k] = (int) modPow(z, Q - 2);
        }
    }

    /** Modular exponentiation: base^exp mod Q. */
    static long modPow(long base, long exp) {
        long result = 1L;
        long b = ((base % Q) + Q) % Q;
        long e = exp;
        while (e > 0) {
            if ((e & 1) == 1) {
                result = result * b % Q;
            }
            e >>= 1;
            b = b * b % Q;
        }
        return result;
    }

    /** Reverse the low logn bits of k. */
    static int bitRev(int k, int logn) {
        int r = 0;
        for (int i = 0; i < logn; i++) {
            r = (r << 1) | (k & 1);
            k >>= 1;
        }
        return r;
    }

    static int addModQ(int a, int b) {
        int r = a + b;
        if (r >= Q) r -= Q;
        return r;
    }

    static int subModQ(int a, int b) {
        int r = a - b;
        if (r < 0) r += Q;
        return r;
    }

    static int mulModQ(long a, long b) {
        return (int) (a * b % Q);
    }

    /**
     * In-place forward NTT.
     * Input: coefficients in [0, Q). n must be 512 or 1024.
     */
    static void ntt(int[] f, int n) {
        int[] zetas = (n == 512) ? ZETAS_512 : ZETAS_1024;
        int k = 0;
        for (int length = n >> 1; length >= 1; length >>= 1) {
            for (int start = 0; start < n; start += 2 * length) {
                k++;
                long zeta = zetas[k];
                for (int j = start; j < start + length; j++) {
                    int t = mulModQ(zeta, f[j + length]);
                    f[j + length] = subModQ(f[j], t);
                    f[j] = addModQ(f[j], t);
                }
            }
        }
    }

    /**
     * In-place inverse NTT.
     * Input: NTT domain values. n must be 512 or 1024.
     * Scales by n^{-1} mod Q.
     */
    static void intt(int[] f, int n) {
        int[] zetasInv = (n == 512) ? ZETAS_INV_512 : ZETAS_INV_1024;
        long nInv = modPow(n, Q - 2);

        int k = n;
        for (int length = 1; length < n; length <<= 1) {
            for (int start = n - 2 * length; start >= 0; start -= 2 * length) {
                k--;
                long zetaInv = zetasInv[k];
                for (int j = start; j < start + length; j++) {
                    int t = f[j];
                    f[j] = addModQ(t, f[j + length]);
                    f[j + length] = mulModQ(zetaInv, subModQ(t, f[j + length]));
                }
            }
        }

        // Scale by n^{-1} mod Q
        for (int i = 0; i < n; i++) {
            f[i] = mulModQ(nInv, f[i]);
        }
    }

    /**
     * Multiply two polynomials mod (q, x^n+1) using NTT.
     * Inputs must have coefficients in [0, Q).
     */
    static int[] polyMul(int[] a, int[] b, int n) {
        int[] aNtt = a.clone();
        int[] bNtt = b.clone();
        ntt(aNtt, n);
        ntt(bNtt, n);
        int[] cNtt = new int[n];
        for (int i = 0; i < n; i++) {
            cNtt[i] = mulModQ(aNtt[i], bNtt[i]);
        }
        intt(cNtt, n);
        return cNtt;
    }

    /**
     * Compute the inverse of a polynomial mod (q, x^n+1) using NTT.
     * Returns null if f is not invertible (some NTT coeff is zero).
     */
    static int[] polyInv(int[] f, int n) {
        int[] fNtt = f.clone();
        ntt(fNtt, n);
        int[] fInvNtt = new int[n];
        for (int i = 0; i < n; i++) {
            if (fNtt[i] == 0) return null;
            fInvNtt[i] = (int) modPow(fNtt[i], Q - 2);
        }
        intt(fInvNtt, n);
        return fInvNtt;
    }

    /** Reduce v to [0, Q) then to (-Q/2, Q/2]. */
    static int centerModQ(int v) {
        v = ((v % Q) + Q) % Q;
        if (v > Q / 2) v -= Q;
        return v;
    }
}
