package com.pqc.hqc;

/**
 * Reed-Solomon encoding and decoding over GF(2^8) for HQC.
 * <p>
 * RS(n1, k) with minimum distance d = n1 - k + 1 = 2*delta + 1.
 * The generator polynomial g(x) = prod(x - alpha^i) for i = 1..2*delta.
 * alpha is the primitive element of GF(2^8) (alpha = 2, using polynomial 0x11D).
 * <p>
 * Decoding uses Berlekamp-Massey for error locator, Chien search for roots,
 * and Forney's algorithm (with X_j factor) for error values.
 */
final class ReedSolomon {

    private ReedSolomon() {}

    /**
     * Computes the generator polynomial of the RS code.
     * Returns coefficients [g0, g1, ..., g_{2*delta}] where g_{2*delta} = 1.
     */
    static int[] generatorPoly(int delta) {
        int deg = 2 * delta;
        int[] g = new int[deg + 1];
        g[0] = 1;

        for (int i = 1; i <= deg; i++) {
            int alphai = GF256.pow(GF256.GF_GEN, i);
            int prev = 0;
            for (int j = 0; j <= deg; j++) {
                int tmp = g[j];
                g[j] = GF256.mul(g[j], alphai) ^ prev;
                prev = tmp;
            }
        }

        return g;
    }

    /**
     * Systematic RS encoding.
     * Input: msg of length k bytes.
     * Output: codeword of length n1 bytes (parity || msg).
     */
    static int[] encode(int[] msg, HqcParams p) {
        int k = p.k;
        int n1 = p.n1;
        int delta = p.delta;
        int[] g = generatorPoly(delta);
        int parityLen = 2 * delta;

        int[] feedback = new int[parityLen];

        for (int i = k - 1; i >= 0; i--) {
            int coeff = GF256.add(msg[i], feedback[parityLen - 1]);
            for (int j = parityLen - 1; j > 0; j--) {
                feedback[j] = GF256.add(feedback[j - 1], GF256.mul(coeff, g[j]));
            }
            feedback[0] = GF256.mul(coeff, g[0]);
        }

        int[] codeword = new int[n1];
        System.arraycopy(feedback, 0, codeword, 0, parityLen);
        System.arraycopy(msg, 0, codeword, parityLen, k);

        return codeword;
    }

    /**
     * Decodes a received RS codeword.
     * Returns the decoded message (k ints) or null if too many errors.
     */
    static int[] decode(int[] received, HqcParams p) {
        int n1 = p.n1;
        int k = p.k;
        int delta = p.delta;

        int[] r = new int[n1];
        System.arraycopy(received, 0, r, 0, n1);

        // Step 1: Compute syndromes S[1..2*delta]
        int[] syndromes = new int[2 * delta + 1];
        boolean allZero = true;
        for (int i = 1; i <= 2 * delta; i++) {
            int alphai = GF256.pow(GF256.GF_GEN, i);
            int s = 0;
            for (int j = n1 - 1; j >= 0; j--) {
                s = GF256.add(GF256.mul(s, alphai), r[j]);
            }
            syndromes[i] = s;
            if (s != 0) allZero = false;
        }

        if (allZero) {
            int[] msg = new int[k];
            System.arraycopy(r, 2 * delta, msg, 0, k);
            return msg;
        }

        // Step 2: Berlekamp-Massey for error locator polynomial sigma
        int[] sigma = berlekampMassey(syndromes, delta);
        int sigDeg = 0;
        for (int i = delta; i >= 0; i--) {
            if (sigma[i] != 0) {
                sigDeg = i;
                break;
            }
        }
        if (sigDeg > delta) return null;

        // Step 3: Chien search for roots of sigma
        int[] errorPositions = new int[sigDeg];
        int numErrors = 0;
        for (int i = 0; i < n1; i++) {
            int alphaInv = GF256.pow(GF256.GF_GEN, 255 - i);
            int val = 0;
            int alphaPow = 1;
            for (int j = 0; j <= sigDeg; j++) {
                val ^= GF256.mul(sigma[j], alphaPow);
                alphaPow = GF256.mul(alphaPow, alphaInv);
            }
            if (val == 0) {
                if (numErrors >= sigDeg) return null;
                errorPositions[numErrors++] = i;
            }
        }

        if (numErrors != sigDeg) return null;

        // Step 4: Forney's algorithm - compute error values
        // omega(x) = S(x) * sigma(x) mod x^(2*delta+1)
        int[] omega = new int[2 * delta + 1];
        for (int i = 0; i < 2 * delta; i++) {
            for (int j = 0; j <= sigDeg && j <= i; j++) {
                omega[i + 1] ^= GF256.mul(sigma[j], syndromes[i + 1 - j]);
            }
        }

        // sigma'(x) = formal derivative of sigma
        int[] sigmaPrime = new int[delta + 1];
        for (int i = 1; i <= sigDeg; i += 2) {
            sigmaPrime[i - 1] = sigma[i];
        }

        // Correct errors
        for (int e = 0; e < numErrors; e++) {
            int pos = errorPositions[e];
            int alphaInvI = GF256.inv(GF256.pow(GF256.GF_GEN, pos));

            // Evaluate omega(alpha^(-pos))
            int omegaVal = 0;
            int alphaPow = 1;
            for (int j = 0; j <= 2 * delta; j++) {
                omegaVal ^= GF256.mul(omega[j], alphaPow);
                alphaPow = GF256.mul(alphaPow, alphaInvI);
            }

            // Evaluate sigma'(alpha^(-pos))
            int sigPrimeVal = 0;
            alphaPow = 1;
            for (int j = 0; j < sigmaPrime.length; j++) {
                sigPrimeVal ^= GF256.mul(sigmaPrime[j], alphaPow);
                alphaPow = GF256.mul(alphaPow, alphaInvI);
            }

            if (sigPrimeVal == 0) return null;

            // Forney's formula: e_j = X_j * omega(X_j^{-1}) / sigma'(X_j^{-1})
            // where X_j = alpha^pos
            int xj = GF256.pow(GF256.GF_GEN, pos);
            int errorVal = GF256.mul(GF256.mul(xj, omegaVal), GF256.inv(sigPrimeVal));
            r[pos] ^= errorVal;
        }

        int[] msg = new int[k];
        System.arraycopy(r, 2 * delta, msg, 0, k);
        return msg;
    }

    /**
     * Berlekamp-Massey algorithm.
     * Returns the error locator polynomial sigma[0..delta].
     */
    private static int[] berlekampMassey(int[] syndromes, int delta) {
        int n = 2 * delta;
        int[] sigma = new int[delta + 2];
        sigma[0] = 1;
        int[] b = new int[delta + 2];
        b[0] = 1;
        int L = 0;
        int m = 1;
        int deltaN = 1;

        for (int kk = 1; kk <= n; kk++) {
            int d = syndromes[kk];
            for (int i = 1; i <= L; i++) {
                d ^= GF256.mul(sigma[i], syndromes[kk - i]);
            }

            if (d == 0) {
                m++;
                continue;
            }

            int[] t = new int[delta + 2];
            System.arraycopy(sigma, 0, t, 0, delta + 2);
            int coeff = GF256.mul(d, GF256.inv(deltaN));
            for (int i = 0; i <= delta + 1 - m; i++) {
                if (i + m <= delta + 1) {
                    t[i + m] ^= GF256.mul(coeff, b[i]);
                }
            }

            if (2 * L < kk) {
                System.arraycopy(sigma, 0, b, 0, delta + 2);
                L = kk - L;
                deltaN = d;
                m = 1;
            } else {
                m++;
            }
            System.arraycopy(t, 0, sigma, 0, delta + 2);
        }

        int[] result = new int[delta + 1];
        System.arraycopy(sigma, 0, result, 0, delta + 1);
        return result;
    }
}
