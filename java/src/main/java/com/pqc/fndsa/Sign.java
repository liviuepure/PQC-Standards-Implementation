package com.pqc.fndsa;

import com.pqc.common.Keccak;
import java.security.SecureRandom;

/**
 * FN-DSA signing (FIPS 206).
 *
 * Implements:
 *   - hashToPoint: hash message to polynomial in Z_q[x]/(x^n+1)
 *   - ffSamplingBabai: Babai nearest-plane lattice sampler
 *   - signInternal: full signing with norm-bound retry loop
 */
final class Sign {

    private Sign() {}

    static final int Q = Params.Q;

    /**
     * Hash (salt || msg) to a polynomial c in Z_q[x]/(x^n+1).
     * Uses SHAKE-256, rejection-sampling 16-bit values mod Q.
     */
    static int[] hashToPoint(byte[] saltAndMsg, Params p) {
        int n = p.n;
        int[] out = new int[n];

        // We need potentially many output bytes; request generously
        // Each coefficient needs up to ~2 bytes, rejection factor ~(5Q)/(2^16) is low
        // Request 4*n bytes initially, then extend if needed
        int count = 0;
        int outputLen = 4 * n;
        // Use SHAKE-256 XOF: absorb and squeeze in chunks
        // We'll use a streaming approach with the Keccak sponge state
        long[] state = Keccak.keccakAbsorb(saltAndMsg, 136, (byte) 0x1F);
        byte[] buf = Keccak.keccakSqueeze(state, 136, outputLen);
        int pos = 0;

        while (count < n) {
            if (pos + 2 > buf.length) {
                // Need more bytes
                outputLen *= 2;
                byte[] newBuf = new byte[outputLen];
                System.arraycopy(buf, 0, newBuf, 0, buf.length);
                // Re-squeeze more from the state -- but our Keccak API doesn't support
                // streaming squeeze. Instead, re-absorb with extended output.
                buf = Keccak.shake256(saltAndMsg, outputLen);
                pos = 0;
                count = 0;
                // Reset and retry
                out = new int[n];
                continue;
            }
            int v = (buf[pos] & 0xFF) | ((buf[pos + 1] & 0xFF) << 8);
            pos += 2;
            // Rejection: discard values >= 5*Q to get near-uniform mod Q
            if (v < 5 * Q) {
                out[count] = v % Q;
                count++;
            }
        }
        return out;
    }

    /**
     * Recover G from (f, g, F) using fG - gF = Q mod q.
     * Returns null if f is not invertible mod q.
     */
    static int[] recoverG(int[] f, int[] g, int[] F, int n) {
        // Compute gF = g*F mod q via NTT
        int[] gModQ = new int[n];
        int[] FModQ = new int[n];
        for (int i = 0; i < n; i++) {
            gModQ[i] = ((g[i] % Q) + Q) % Q;
            FModQ[i] = ((F[i] % Q) + Q) % Q;
        }
        int[] gF = NTT.polyMul(gModQ, FModQ, n);

        // Compute f^{-1} mod q via NTT
        int[] fModQ = new int[n];
        for (int i = 0; i < n; i++) fModQ[i] = ((f[i] % Q) + Q) % Q;
        int[] fNtt = fModQ.clone();
        NTT.ntt(fNtt, n);
        for (int v : fNtt) {
            if (v == 0) return null; // f not invertible
        }
        int[] fInvNtt = new int[n];
        for (int i = 0; i < n; i++) {
            fInvNtt[i] = (int) NTT.modPow(fNtt[i], Q - 2);
        }
        NTT.intt(fInvNtt, n);

        // G = gF * f^{-1} mod q
        int[] G = NTT.polyMul(gF, fInvNtt, n);

        // Center coefficients in (-Q/2, Q/2]
        for (int i = 0; i < n; i++) {
            if (G[i] > Q / 2) G[i] -= Q;
        }
        return G;
    }

    /**
     * Compute h = g * f^{-1} mod (q, x^n+1).
     */
    static int[] computeH(int[] f, int[] g, int n) {
        int[] fNtt = new int[n];
        int[] gNtt = new int[n];
        for (int i = 0; i < n; i++) {
            fNtt[i] = ((f[i] % Q) + Q) % Q;
            gNtt[i] = ((g[i] % Q) + Q) % Q;
        }
        NTT.ntt(fNtt, n);
        NTT.ntt(gNtt, n);

        int[] fInvNtt = new int[n];
        for (int i = 0; i < n; i++) {
            fInvNtt[i] = (int) NTT.modPow(fNtt[i], Q - 2);
        }
        int[] hNtt = new int[n];
        for (int i = 0; i < n; i++) {
            hNtt[i] = NTT.mulModQ(gNtt[i], fInvNtt[i]);
        }
        NTT.intt(hNtt, n);
        return hNtt;
    }

    /**
     * Babai nearest-plane lattice sampler (two-step approximation).
     *
     * NOTE: This is the Babai nearest-plane approximation, not the full ffSampling
     * Gaussian sampler from FIPS 206 Algorithm 11. It is suitable for correctness
     * testing but does not provide side-channel security guarantees.
     *
     * The NTRU coset lattice L = {(a,b) : a + b*h = 0 mod q} has basis
     * B = [[g, -f], [G, -F]] with det(B) = f*G - g*F = q.
     *
     * Returns (s1, s2) centered mod q.
     */
    static int[][] ffSamplingBabai(int[] c, int[] f, int[] g, int[] F, int[] G, int n) {
        double[][] cFFT = FFT.toFFT(c, n);
        double[][] fFFT = FFT.toFFT(f, n);
        double[][] gFFT = FFT.toFFT(g, n);
        double[][] FFFT = FFT.toFFT(F, n);
        double[][] GFFT = FFT.toFFT(G, n);

        // Gram-Schmidt: compute b1* = b1 - mu10*b0*
        // b0 = (g, -f), b1 = (G, -F)
        // mu10_j = <b1_j, b0_j*> / ||b0_j*||^2
        //        = (G_j*conj(g_j) + F_j*conj(f_j)) / (|g_j|^2 + |f_j|^2)  [note: <(G,-F),(g,-f)> uses conjugate]
        // Actually: <(G,-F),(g,-f)> = G*conj(g) + F*conj(f)  [inner product includes both components]
        double[][] b1StarFFT0 = new double[n][2]; // first component of b1*
        double[][] b1StarFFT1 = new double[n][2]; // second component
        double[] b1StarNormSq = new double[n];

        for (int j = 0; j < n; j++) {
            double gre = gFFT[j][0], gim = gFFT[j][1];
            double fre = fFFT[j][0], fim = fFFT[j][1];
            double Gre = GFFT[j][0], Gim = GFFT[j][1];
            double Fre = FFFT[j][0], Fim = FFFT[j][1];

            double b0NormSq = gre*gre + gim*gim + fre*fre + fim*fim;
            double mu10Re = 0.0, mu10Im = 0.0;
            if (b0NormSq != 0.0) {
                // num = G*conj(g) + F*conj(f)
                double numRe = Gre*gre + Gim*gim + Fre*fre + Fim*fim;
                double numIm = Gim*gre - Gre*gim + Fim*fre - Fre*fim;
                mu10Re = numRe / b0NormSq;
                mu10Im = numIm / b0NormSq;
            }
            // b1* = (G - mu10*g, -F + mu10*f)
            double b1s0Re = Gre - (mu10Re*gre - mu10Im*gim);
            double b1s0Im = Gim - (mu10Re*gim + mu10Im*gre);
            double b1s1Re = -Fre + (mu10Re*fre - mu10Im*fim);
            double b1s1Im = -Fim + (mu10Re*fim + mu10Im*fre);

            b1StarFFT0[j][0] = b1s0Re; b1StarFFT0[j][1] = b1s0Im;
            b1StarFFT1[j][0] = b1s1Re; b1StarFFT1[j][1] = b1s1Im;
            b1StarNormSq[j] = b1s0Re*b1s0Re + b1s0Im*b1s0Im + b1s1Re*b1s1Re + b1s1Im*b1s1Im;
        }

        // Step 1: project (c_j, 0) along b1*_j
        // tau1_j = <(c_j, 0), conj(b1*_j)> / ||b1*||^2
        //        = c_j * conj(b1*0_j) / ||b1*||^2
        double[][] tau1FFT = new double[n][2];
        for (int j = 0; j < n; j++) {
            double b1sNorm = b1StarNormSq[j];
            if (b1sNorm != 0.0) {
                double b1s0Re = b1StarFFT0[j][0], b1s0Im = b1StarFFT0[j][1];
                // c_j * conj(b1s0) = (cRe*b1s0Re + cIm*b1s0Im, cIm*b1s0Re - cRe*b1s0Im)
                double cre = cFFT[j][0], cim = cFFT[j][1];
                tau1FFT[j][0] = (cre*b1s0Re + cim*b1s0Im) / b1sNorm;
                tau1FFT[j][1] = (cim*b1s0Re - cre*b1s0Im) / b1sNorm;
            }
        }
        int[] z1 = FFT.fromFFT(tau1FFT, n);
        double[][] z1FFT = FFT.toFFT(z1, n);

        // Update target: t'_j = (c_j, 0) - z1_j*(G_j, -F_j)
        double[][] cPrimeFFT = new double[n][2];
        double[][] xPrimeFFT = new double[n][2];
        for (int j = 0; j < n; j++) {
            // z1_j * G_j
            double z1re = z1FFT[j][0], z1im = z1FFT[j][1];
            double Gre = GFFT[j][0], Gim = GFFT[j][1];
            double Fre = FFFT[j][0], Fim = FFFT[j][1];
            cPrimeFFT[j][0] = cFFT[j][0] - (z1re*Gre - z1im*Gim);
            cPrimeFFT[j][1] = cFFT[j][1] - (z1re*Gim + z1im*Gre);
            // z1_j * F_j
            xPrimeFFT[j][0] = z1re*Fre - z1im*Fim;
            xPrimeFFT[j][1] = z1re*Fim + z1im*Fre;
        }

        // Step 2: project t'_j along b0*_j = (g_j, -f_j)
        // tau0_j = <(c'_j, x'_j), conj((g_j, -f_j))> / (|g_j|^2 + |f_j|^2)
        //        = (c'_j*conj(g_j) - x'_j*conj(f_j)) / (|g_j|^2 + |f_j|^2)
        double[][] tau0FFT = new double[n][2];
        for (int j = 0; j < n; j++) {
            double gre = gFFT[j][0], gim = gFFT[j][1];
            double fre = fFFT[j][0], fim = fFFT[j][1];
            double b0NormSq = gre*gre + gim*gim + fre*fre + fim*fim;
            if (b0NormSq != 0.0) {
                double cpre = cPrimeFFT[j][0], cpim = cPrimeFFT[j][1];
                double xpre = xPrimeFFT[j][0], xpim = xPrimeFFT[j][1];
                // c'*conj(g) = (cpre*gre + cpim*gim, cpim*gre - cpre*gim)
                // x'*conj(f) = (xpre*fre + xpim*fim, xpim*fre - xpre*fim)
                tau0FFT[j][0] = (cpre*gre + cpim*gim - (xpre*fre + xpim*fim)) / b0NormSq;
                tau0FFT[j][1] = (cpim*gre - cpre*gim - (xpim*fre - xpre*fim)) / b0NormSq;
            }
        }
        int[] z0 = FFT.fromFFT(tau0FFT, n);
        double[][] z0FFT = FFT.toFFT(z0, n);

        // Compute s1 = z0*f + z1*F, s2 = c - z0*g - z1*G
        double[][] s1FFT = new double[n][2];
        double[][] s2FFT = new double[n][2];
        for (int j = 0; j < n; j++) {
            double z0re = z0FFT[j][0], z0im = z0FFT[j][1];
            double z1re = z1FFT[j][0], z1im = z1FFT[j][1];
            double fre = fFFT[j][0], fim = fFFT[j][1];
            double gre = gFFT[j][0], gim = gFFT[j][1];
            double Fre = FFFT[j][0], Fim = FFFT[j][1];
            double Gre = GFFT[j][0], Gim = GFFT[j][1];

            // s1 = z0*f + z1*F
            s1FFT[j][0] = (z0re*fre - z0im*fim) + (z1re*Fre - z1im*Fim);
            s1FFT[j][1] = (z0re*fim + z0im*fre) + (z1re*Fim + z1im*Fre);
            // s2 = c - z0*g - z1*G
            s2FFT[j][0] = cFFT[j][0] - (z0re*gre - z0im*gim) - (z1re*Gre - z1im*Gim);
            s2FFT[j][1] = cFFT[j][1] - (z0re*gim + z0im*gre) - (z1re*Gim + z1im*Gre);
        }

        int[] s1Raw = FFT.fromFFT(s1FFT, n);
        int[] s2Raw = FFT.fromFFT(s2FFT, n);

        int[] s1 = new int[n];
        int[] s2 = new int[n];
        for (int i = 0; i < n; i++) {
            s1[i] = NTT.centerModQ(s1Raw[i]);
            s2[i] = NTT.centerModQ(s2Raw[i]);
        }
        return new int[][] {s1, s2};
    }

    /** Compute squared Euclidean norm of s1 and s2. */
    static long normSq(int[] s1, int[] s2) {
        long n = 0;
        for (int v : s1) n += (long) v * v;
        for (int v : s2) n += (long) v * v;
        return n;
    }

    /**
     * Sign msg using secret key sk under parameter set p.
     * Returns the signature bytes, or throws on failure.
     */
    static byte[] signInternal(byte[] sk, byte[] msg, Params p, SecureRandom rng) {
        int[][] skParts = Encode.decodeSk(sk, p);
        if (skParts == null) throw new IllegalArgumentException("FN-DSA: invalid secret key");

        int[] f = skParts[0];
        int[] g = skParts[1];
        int[] F = skParts[2];
        int n = p.n;

        int[] G = recoverG(f, g, F, n);
        if (G == null) throw new IllegalArgumentException("FN-DSA: invalid secret key: f not invertible mod q");

        int[] h = computeH(f, g, n);

        byte[] salt = new byte[40];
        for (int attempt = 0; attempt < 1000; attempt++) {
            rng.nextBytes(salt);

            // Compute c = HashToPoint(salt || msg)
            byte[] hashInput = new byte[40 + msg.length];
            System.arraycopy(salt, 0, hashInput, 0, 40);
            System.arraycopy(msg, 0, hashInput, 40, msg.length);
            int[] c = hashToPoint(hashInput, p);

            // Center c for FFT arithmetic
            int[] cCentered = new int[n];
            for (int i = 0; i < n; i++) {
                cCentered[i] = NTT.centerModQ(c[i]);
            }

            // Babai nearest-plane
            int[][] s1s2 = ffSamplingBabai(cCentered, f, g, F, G, n);
            int[] s1 = s1s2[0];
            int[] s2 = s1s2[1];

            // Verify s1*h + s2 = c (mod q)
            int[] s1ModQ = new int[n];
            for (int i = 0; i < n; i++) s1ModQ[i] = ((s1[i] % Q) + Q) % Q;
            int[] s1h = NTT.polyMul(s1ModQ, h, n);
            boolean valid = true;
            for (int i = 0; i < n; i++) {
                int sum = (int)(((long) s1h[i] + s2[i]) % Q);
                sum = ((sum % Q) + Q) % Q;
                if (sum != c[i]) { valid = false; break; }
            }
            if (!valid) continue;

            // Check norm bound
            long ns = normSq(s1, s2);
            if (ns > p.betaSq) continue;

            // Encode signature
            byte[] sig = Encode.encodeSig(salt, s1, p);
            if (sig == null) continue; // compressed s1 too large

            return sig;
        }

        throw new IllegalStateException("FN-DSA: signing failed after 1000 attempts");
    }
}
