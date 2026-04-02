package com.pqc.fndsa;

/**
 * Complex FFT/IFFT/SplitFFT/MergeFFT for FN-DSA (FIPS 206 / FALCON).
 *
 * Operates over C[x]/(x^n+1), evaluating polynomials at the 2n-th primitive
 * roots of unity: omega_j = exp(i*pi*(2j+1)/n) for j = 0..n-1.
 *
 * Output is in bit-reversed order (consistent with IFFT/SplitFFT/MergeFFT).
 * Complex numbers are stored as double[2] = {re, im}.
 */
final class FFT {

    private FFT() {}

    /** log2(n); n must be a power of 2. */
    static int logN(int n) {
        int logn = 0;
        for (int t = n; t > 1; t >>= 1) logn++;
        return logn;
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

    /**
     * In-place forward negacyclic complex FFT over C[x]/(x^n+1).
     * f is n complex numbers stored as double[n][2] = {{re,im},...}.
     * n must be a power of two (4 <= n <= 1024).
     */
    static void fft(double[][] f, int n) {
        int logn = logN(n);
        int k = 0;
        for (int length = n >> 1; length >= 1; length >>= 1) {
            for (int start = 0; start < n; start += 2 * length) {
                k++;
                int brk = bitRev(k, logn);
                double angle = Math.PI * brk / n;
                double wRe = Math.cos(angle);
                double wIm = Math.sin(angle);
                for (int j = start; j < start + length; j++) {
                    double tRe = wRe * f[j + length][0] - wIm * f[j + length][1];
                    double tIm = wRe * f[j + length][1] + wIm * f[j + length][0];
                    f[j + length][0] = f[j][0] - tRe;
                    f[j + length][1] = f[j][1] - tIm;
                    f[j][0] += tRe;
                    f[j][1] += tIm;
                }
            }
        }
    }

    /**
     * In-place inverse negacyclic complex FFT.
     * IFFT(FFT(f)) = f (within floating-point precision). Scales by 1/n.
     */
    static void ifft(double[][] f, int n) {
        int logn = logN(n);
        int k = n;
        for (int length = 1; length < n; length <<= 1) {
            for (int start = n - 2 * length; start >= 0; start -= 2 * length) {
                k--;
                int brk = bitRev(k, logn);
                double angle = -Math.PI * brk / n;
                double wRe = Math.cos(angle);
                double wIm = Math.sin(angle);
                for (int j = start; j < start + length; j++) {
                    double aRe = f[j][0], aIm = f[j][1];
                    double bRe = f[j + length][0], bIm = f[j + length][1];
                    f[j][0] = aRe + bRe;
                    f[j][1] = aIm + bIm;
                    double dRe = aRe - bRe, dIm = aIm - bIm;
                    f[j + length][0] = wRe * dRe - wIm * dIm;
                    f[j + length][1] = wRe * dIm + wIm * dRe;
                }
            }
        }
        double invN = 1.0 / n;
        for (int i = 0; i < n; i++) {
            f[i][0] *= invN;
            f[i][1] *= invN;
        }
    }

    /**
     * Convert int[] polynomial to FFT domain (n complex numbers).
     */
    static double[][] toFFT(int[] a, int n) {
        double[][] f = new double[n][2];
        for (int i = 0; i < n; i++) {
            f[i][0] = a[i];
            f[i][1] = 0.0;
        }
        fft(f, n);
        return f;
    }

    /**
     * Apply IFFT and round to nearest integer polynomial.
     */
    static int[] fromFFT(double[][] fftVals, int n) {
        double[][] tmp = new double[n][2];
        for (int i = 0; i < n; i++) {
            tmp[i][0] = fftVals[i][0];
            tmp[i][1] = fftVals[i][1];
        }
        ifft(tmp, n);
        int[] out = new int[n];
        for (int i = 0; i < n; i++) {
            out[i] = (int) Math.round(tmp[i][0]);
        }
        return out;
    }

    /**
     * SplitFFT decomposes f(x) = f0(x^2) + x*f1(x^2) in the FFT domain.
     * Returns [f0, f1] each of length n/2.
     */
    static double[][][] splitFFT(double[][] f, int n) {
        int logn = logN(n);
        int h = n / 2;
        double[][] f0 = new double[h][2];
        double[][] f1 = new double[h][2];
        for (int k = 0; k < h; k++) {
            int j = bitRev(k, logn - 1);
            double angle = Math.PI * (2 * j + 1) / n;
            double omRe = Math.cos(angle);
            double omIm = Math.sin(angle);
            double aRe = f[2 * k][0], aIm = f[2 * k][1];
            double bRe = f[2 * k + 1][0], bIm = f[2 * k + 1][1];
            f0[k][0] = (aRe + bRe) / 2.0;
            f0[k][1] = (aIm + bIm) / 2.0;
            double dRe = aRe - bRe, dIm = aIm - bIm;
            // (dRe + i*dIm) / (2*(omRe + i*omIm)) = (d * conj(om)) / (2*|om|^2)
            // |om|^2 = 1, so: (d * conj(om)) / 2
            f1[k][0] = (dRe * omRe + dIm * omIm) / 2.0;
            f1[k][1] = (dIm * omRe - dRe * omIm) / 2.0;
        }
        return new double[][][] {f0, f1};
    }

    /**
     * MergeFFT is the inverse of SplitFFT.
     * Reconstructs n-element FFT polynomial from two n/2-element polynomials.
     */
    static double[][] mergeFFT(double[][] f0, double[][] f1, int n) {
        int logn = logN(n);
        int h = n / 2;
        double[][] f = new double[n][2];
        for (int k = 0; k < h; k++) {
            int j = bitRev(k, logn - 1);
            double angle = Math.PI * (2 * j + 1) / n;
            double omRe = Math.cos(angle);
            double omIm = Math.sin(angle);
            // t = om * f1[k]
            double tRe = omRe * f1[k][0] - omIm * f1[k][1];
            double tIm = omRe * f1[k][1] + omIm * f1[k][0];
            f[2 * k][0] = f0[k][0] + tRe;
            f[2 * k][1] = f0[k][1] + tIm;
            f[2 * k + 1][0] = f0[k][0] - tRe;
            f[2 * k + 1][1] = f0[k][1] - tIm;
        }
        return f;
    }
}
