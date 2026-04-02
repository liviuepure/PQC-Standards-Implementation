package com.pqc.fndsa;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.security.SecureRandom;

/**
 * NTRU key generation for FN-DSA (FIPS 206 Algorithm 5 - NTRUGen).
 *
 * Generates (f, g, F, G) satisfying f*G - g*F = q over Z[x]/(x^n+1).
 * G is derived from the NTRU equation and not stored in the secret key.
 */
final class NTRUKeygen {

    private NTRUKeygen() {}

    static final int Q = Params.Q;

    /**
     * Generate NTRU key pair.
     * Returns [f, g, F] arrays (G is recomputed during signing).
     * Throws IllegalStateException if key generation fails after many attempts.
     */
    static int[][] ntruKeygen(Params p, SecureRandom rng) {
        int n = p.n;
        double sigma = 1.17 * Math.sqrt((double) Q / (2.0 * n));

        for (int attempt = 0; attempt < 1000; attempt++) {
            // Sample f and g from D_{Z, sigma}
            int[] f = new int[n];
            int[] g = new int[n];
            for (int i = 0; i < n; i++) {
                f[i] = Gaussian.sampleGaussian(rng, sigma);
                g[i] = Gaussian.sampleGaussian(rng, sigma);
            }

            // f must be invertible mod 2 (odd parity of coefficients)
            int xorSum = 0;
            for (int v : f) xorSum ^= (v & 1);
            if (xorSum == 0) continue;

            // f must be invertible mod q
            int[] fNtt = new int[n];
            for (int i = 0; i < n; i++) {
                fNtt[i] = ((f[i] % Q) + Q) % Q;
            }
            NTT.ntt(fNtt, n);
            boolean invertible = true;
            for (int v : fNtt) {
                if (v == 0) { invertible = false; break; }
            }
            if (!invertible) continue;

            // Gram-Schmidt norm bound: ||(f,g)||^2 <= 1.17^2 * Q * n
            double normSq = 0.0;
            for (int v : f) normSq += (double) v * v;
            for (int v : g) normSq += (double) v * v;
            if (normSq > 1.17 * 1.17 * Q * n) continue;

            // Solve the NTRU equation f*G - g*F = q
            try {
                BigInteger[] fBig = toBigInt(f);
                BigInteger[] gBig = toBigInt(g);
                BigInteger[][] FGBig = ntruSolveBig(n, fBig, gBig);
                if (FGBig == null) continue;

                // Convert to int[]
                int[] F = new int[n];
                int[] G = new int[n];
                boolean overflow = false;
                for (int i = 0; i < n; i++) {
                    if (FGBig[0][i].bitLength() > 31 || FGBig[1][i].bitLength() > 31) {
                        // Check sign: BigInteger.bitLength() doesn't include sign bit
                        long fv = FGBig[0][i].longValue();
                        long gv = FGBig[1][i].longValue();
                        if (fv > Integer.MAX_VALUE || fv < Integer.MIN_VALUE ||
                            gv > Integer.MAX_VALUE || gv < Integer.MIN_VALUE) {
                            overflow = true;
                            break;
                        }
                        F[i] = (int) fv;
                        G[i] = (int) gv;
                    } else {
                        F[i] = FGBig[0][i].intValue();
                        G[i] = FGBig[1][i].intValue();
                    }
                }
                if (overflow) continue;

                // Verify f*G - g*F = q exactly
                if (!verifyNTRU(f, g, F, G, n)) continue;

                return new int[][] {f, g, F};
            } catch (ArithmeticException e) {
                continue;
            }
        }
        throw new IllegalStateException("FN-DSA: NTRU key generation failed after 1000 attempts");
    }

    /** Verify f*G - g*F = q over Z[x]/(x^n+1). */
    private static boolean verifyNTRU(int[] f, int[] g, int[] F, int[] G, int n) {
        long[] fG = polyMulZ(f, G, n);
        long[] gF = polyMulZ(g, F, n);
        if (fG[0] - gF[0] != Q) return false;
        for (int i = 1; i < n; i++) {
            if (fG[i] - gF[i] != 0) return false;
        }
        return true;
    }

    /** Multiply two polynomials over Z[x]/(x^n+1) exactly using long arithmetic. */
    static long[] polyMulZ(int[] a, int[] b, int n) {
        long[] c = new long[n];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                int idx = i + j;
                long val = (long) a[i] * b[j];
                if (idx < n) c[idx] += val;
                else c[idx - n] -= val;
            }
        }
        return c;
    }

    /** Convert int[] to BigInteger[]. */
    static BigInteger[] toBigInt(int[] a) {
        BigInteger[] res = new BigInteger[a.length];
        for (int i = 0; i < a.length; i++) res[i] = BigInteger.valueOf(a[i]);
        return res;
    }

    /**
     * Recursive NTRU solver using exact BigInteger arithmetic.
     * Returns [F, G] as BigInteger arrays, or null on failure.
     */
    private static BigInteger[][] ntruSolveBig(int n, BigInteger[] f, BigInteger[] g) {
        if (n == 1) {
            // Base case: solve f[0]*G[0] - g[0]*F[0] = Q over Z
            BigInteger fVal = f[0];
            BigInteger gVal = g[0];
            BigInteger[] gcdResult = new BigInteger[3]; // [gcd, u, v]
            extGcd(fVal, gVal, gcdResult);
            BigInteger gcd = gcdResult[0];
            BigInteger u = gcdResult[1];
            BigInteger v = gcdResult[2];

            BigInteger qBig = BigInteger.valueOf(Q);
            if (!qBig.mod(gcd.abs()).equals(BigInteger.ZERO)) return null;

            BigInteger scale = qBig.divide(gcd);
            BigInteger GVal = u.multiply(scale);
            BigInteger FVal = v.multiply(scale).negate();
            return new BigInteger[][] { new BigInteger[] {FVal}, new BigInteger[] {GVal} };
        }

        // Field norm from Z[x]/(x^n+1) to Z[x]/(x^{n/2}+1)
        BigInteger[] fNorm = fieldNorm(f, n);
        BigInteger[] gNorm = fieldNorm(g, n);

        // Recurse
        BigInteger[][] FpGp = ntruSolveBig(n / 2, fNorm, gNorm);
        if (FpGp == null) return null;

        BigInteger[] Fp = FpGp[0];
        BigInteger[] Gp = FpGp[1];

        // Lift from n/2 to n
        BigInteger[] FLifted = new BigInteger[n];
        BigInteger[] GLifted = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            FLifted[i] = BigInteger.ZERO;
            GLifted[i] = BigInteger.ZERO;
        }
        for (int i = 0; i < n / 2; i++) {
            FLifted[2 * i] = Fp[i];
            GLifted[2 * i] = Gp[i];
        }
        BigInteger[] fConj = towerConjugate(f);
        BigInteger[] gConj = towerConjugate(g);
        FLifted = polyMulBig(gConj, FLifted, n);
        GLifted = polyMulBig(fConj, GLifted, n);

        // Babai reduction: run 2 rounds
        int maxBits = 0;
        for (BigInteger v2 : f) { int b = v2.bitLength(); if (b > maxBits) maxBits = b; }
        for (BigInteger v2 : g) { int b = v2.bitLength(); if (b > maxBits) maxBits = b; }

        for (int round = 0; round < 2; round++) {
            int maxFGBits = maxBits;
            for (BigInteger v2 : FLifted) { int b = v2.bitLength(); if (b > maxFGBits) maxFGBits = b; }
            for (BigInteger v2 : GLifted) { int b = v2.bitLength(); if (b > maxFGBits) maxFGBits = b; }

            BigInteger[] k;
            if (maxFGBits <= 53) {
                k = babaiFloat64(FLifted, GLifted, f, g, n);
            } else {
                // Use high-precision BigDecimal-based FFT
                int prec = maxFGBits * 2 + logN(n) * 64 + 256;
                k = babaiBigDecimal(FLifted, GLifted, f, g, n, prec);
            }

            BigInteger[] kf = polyMulBig(k, f, n);
            BigInteger[] kg = polyMulBig(k, g, n);
            for (int i = 0; i < n; i++) {
                FLifted[i] = FLifted[i].subtract(kf[i]);
                GLifted[i] = GLifted[i].subtract(kg[i]);
            }
        }

        return new BigInteger[][] {FLifted, GLifted};
    }

    /** Extended Euclidean algorithm. Sets result[0]=gcd, result[1]=u, result[2]=v s.t. a*u+b*v=gcd. */
    private static void extGcd(BigInteger a, BigInteger b, BigInteger[] result) {
        BigInteger[] r = new BigInteger[] {a, b};
        BigInteger[] s = new BigInteger[] {BigInteger.ONE, BigInteger.ZERO};
        BigInteger[] t = new BigInteger[] {BigInteger.ZERO, BigInteger.ONE};
        while (!r[1].equals(BigInteger.ZERO)) {
            BigInteger q = r[0].divide(r[1]);
            BigInteger tmp = r[0].subtract(q.multiply(r[1]));
            r[0] = r[1]; r[1] = tmp;
            tmp = s[0].subtract(q.multiply(s[1]));
            s[0] = s[1]; s[1] = tmp;
            tmp = t[0].subtract(q.multiply(t[1]));
            t[0] = t[1]; t[1] = tmp;
        }
        // Ensure gcd is positive
        if (r[0].signum() < 0) {
            r[0] = r[0].negate();
            s[0] = s[0].negate();
            t[0] = t[0].negate();
        }
        result[0] = r[0];
        result[1] = s[0];
        result[2] = t[0];
    }

    /**
     * Field norm: N(f)(y) = f0(y)^2 - y*f1(y)^2
     * where f(x) = f0(x^2) + x*f1(x^2).
     */
    private static BigInteger[] fieldNorm(BigInteger[] f, int n) {
        int h = n / 2;
        BigInteger[] f0 = new BigInteger[h];
        BigInteger[] f1 = new BigInteger[h];
        for (int i = 0; i < h; i++) {
            f0[i] = f[2 * i];
            f1[i] = f[2 * i + 1];
        }
        BigInteger[] f0sq = polyMulBig(f0, f0, h);
        BigInteger[] f1sq = polyMulBig(f1, f1, h);

        // N(f)[0] = f0sq[0] + f1sq[h-1]
        // N(f)[i] = f0sq[i] - f1sq[i-1] for i >= 1
        BigInteger[] result = new BigInteger[h];
        result[0] = f0sq[0].add(f1sq[h - 1]);
        for (int i = 1; i < h; i++) {
            result[i] = f0sq[i].subtract(f1sq[i - 1]);
        }
        return result;
    }

    /** Tower conjugate: negate odd-indexed coefficients. */
    private static BigInteger[] towerConjugate(BigInteger[] f) {
        BigInteger[] res = new BigInteger[f.length];
        for (int i = 0; i < f.length; i++) {
            res[i] = (i % 2 == 0) ? f[i] : f[i].negate();
        }
        return res;
    }

    /** Multiply two polynomials over Z[x]/(x^n+1) using BigInteger. */
    static BigInteger[] polyMulBig(BigInteger[] a, BigInteger[] b, int n) {
        BigInteger[] c = new BigInteger[n];
        for (int i = 0; i < n; i++) c[i] = BigInteger.ZERO;
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                int idx = i + j;
                BigInteger val = a[i].multiply(b[j]);
                if (idx < n) c[idx] = c[idx].add(val);
                else c[idx - n] = c[idx - n].subtract(val);
            }
        }
        return c;
    }

    /** log2(n) for power-of-two n. */
    static int logN(int n) {
        int logn = 0;
        for (int t = n; t > 1; t >>= 1) logn++;
        return logn;
    }

    /** Babai reduction using float64 FFT. */
    private static BigInteger[] babaiFloat64(BigInteger[] F, BigInteger[] G,
                                              BigInteger[] f, BigInteger[] g, int n) {
        double[][] FC = new double[n][2];
        double[][] GC = new double[n][2];
        double[][] fC = new double[n][2];
        double[][] gC = new double[n][2];
        for (int i = 0; i < n; i++) {
            FC[i][0] = F[i].doubleValue();
            GC[i][0] = G[i].doubleValue();
            fC[i][0] = f[i].doubleValue();
            gC[i][0] = g[i].doubleValue();
        }
        FFT.fft(FC, n); FFT.fft(GC, n);
        FFT.fft(fC, n); FFT.fft(gC, n);

        double[][] kC = new double[n][2];
        for (int i = 0; i < n; i++) {
            double fre = fC[i][0], fim = fC[i][1];
            double gre = gC[i][0], gim = gC[i][1];
            double Fre = FC[i][0], Fim = FC[i][1];
            double Gre = GC[i][0], Gim = GC[i][1];
            // num = F*conj(f) + G*conj(g)
            double numRe = Fre * fre + Fim * fim + Gre * gre + Gim * gim;
            double numIm = Fim * fre - Fre * fim + Gim * gre - Gre * gim;
            double denom = fre * fre + fim * fim + gre * gre + gim * gim;
            if (denom != 0.0) {
                kC[i][0] = numRe / denom;
                kC[i][1] = numIm / denom;
            }
        }
        FFT.ifft(kC, n);

        BigInteger[] k = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            k[i] = BigInteger.valueOf(Math.round(kC[i][0]));
        }
        return k;
    }

    /**
     * High-precision Babai reduction using BigDecimal-based complex FFT.
     * Used when coefficients exceed float64 precision (> 53 bits).
     *
     * Computes k = round(Re(IFFT((F*conj(f) + G*conj(g)) / (|f|^2 + |g|^2))))
     * with arbitrary precision.
     */
    private static BigInteger[] babaiBigDecimal(BigInteger[] F, BigInteger[] G,
                                                 BigInteger[] f, BigInteger[] g,
                                                 int n, int precBits) {
        // Convert precBits to decimal digits (approx)
        // Use enough decimal digits for the computation
        // precBits already accounts for coefficient size + FFT overhead
        int decimalDigits = (int)(precBits * Math.log10(2.0)) + 50;
        MathContext mc = new MathContext(decimalDigits);

        int logn = logN(n);

        // Complex number as BigDecimal[2] = {re, im}
        BigDecimal[][] FA = toComplexBD(F, n, mc);
        BigDecimal[][] GA = toComplexBD(G, n, mc);
        BigDecimal[][] fA = toComplexBD(f, n, mc);
        BigDecimal[][] gA = toComplexBD(g, n, mc);

        fftBD(fA, n, logn, mc);
        fftBD(gA, n, logn, mc);
        fftBD(FA, n, logn, mc);
        fftBD(GA, n, logn, mc);

        BigDecimal[][] kA = new BigDecimal[n][2];
        for (int i = 0; i < n; i++) {
            BigDecimal fre = fA[i][0], fim = fA[i][1];
            BigDecimal gre = gA[i][0], gim = gA[i][1];
            BigDecimal Fre = FA[i][0], Fim = FA[i][1];
            BigDecimal Gre = GA[i][0], Gim = GA[i][1];

            // num = F*conj(f) + G*conj(g)
            BigDecimal numRe = Fre.multiply(fre, mc).add(Fim.multiply(fim, mc), mc)
                               .add(Gre.multiply(gre, mc), mc).add(Gim.multiply(gim, mc), mc);
            BigDecimal numIm = Fim.multiply(fre, mc).subtract(Fre.multiply(fim, mc), mc)
                               .add(Gim.multiply(gre, mc), mc).subtract(Gre.multiply(gim, mc), mc);
            // denom = |f|^2 + |g|^2  (real)
            BigDecimal denom = fre.multiply(fre, mc).add(fim.multiply(fim, mc), mc)
                               .add(gre.multiply(gre, mc), mc).add(gim.multiply(gim, mc), mc);

            if (denom.compareTo(BigDecimal.ZERO) != 0) {
                kA[i][0] = numRe.divide(denom, mc);
                kA[i][1] = numIm.divide(denom, mc);
            } else {
                kA[i][0] = BigDecimal.ZERO;
                kA[i][1] = BigDecimal.ZERO;
            }
        }

        ifftBD(kA, n, logn, mc);

        BigDecimal half = new BigDecimal("0.5");
        BigInteger[] k = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            BigDecimal val = kA[i][0];
            // Round to nearest integer
            if (val.compareTo(BigDecimal.ZERO) >= 0) {
                k[i] = val.add(half).toBigInteger();
            } else {
                k[i] = val.subtract(half).toBigInteger();
            }
        }
        return k;
    }

    /** Convert BigInteger array to complex BigDecimal array (imaginary = 0). */
    private static BigDecimal[][] toComplexBD(BigInteger[] a, int n, MathContext mc) {
        BigDecimal[][] c = new BigDecimal[n][2];
        for (int i = 0; i < n; i++) {
            c[i][0] = new BigDecimal(a[i], mc);
            c[i][1] = BigDecimal.ZERO;
        }
        return c;
    }

    /** In-place forward FFT on BigDecimal complex array. */
    private static void fftBD(BigDecimal[][] f, int n, int logn, MathContext mc) {
        int k = 0;
        for (int length = n >> 1; length >= 1; length >>= 1) {
            for (int start = 0; start < n; start += 2 * length) {
                k++;
                int brk = FFT.bitRev(k, logn);
                // Twiddle: exp(i*pi*brk/n)
                BigDecimal[] twiddle = cosSinBD(brk, n, mc);
                BigDecimal wRe = twiddle[0], wIm = twiddle[1];
                for (int j = start; j < start + length; j++) {
                    // t = w * f[j+length]
                    BigDecimal tRe = wRe.multiply(f[j+length][0], mc).subtract(wIm.multiply(f[j+length][1], mc), mc);
                    BigDecimal tIm = wRe.multiply(f[j+length][1], mc).add(wIm.multiply(f[j+length][0], mc), mc);
                    f[j+length][0] = f[j][0].subtract(tRe, mc);
                    f[j+length][1] = f[j][1].subtract(tIm, mc);
                    f[j][0] = f[j][0].add(tRe, mc);
                    f[j][1] = f[j][1].add(tIm, mc);
                }
            }
        }
    }

    /** In-place inverse FFT on BigDecimal complex array. */
    private static void ifftBD(BigDecimal[][] f, int n, int logn, MathContext mc) {
        int k = n;
        for (int length = 1; length < n; length <<= 1) {
            for (int start = n - 2*length; start >= 0; start -= 2*length) {
                k--;
                int brk = FFT.bitRev(k, logn);
                // Inverse twiddle: exp(-i*pi*brk/n)
                BigDecimal[] twiddle = cosSinBD(brk, n, mc);
                BigDecimal wRe = twiddle[0];
                BigDecimal wIm = twiddle[1].negate();
                for (int j = start; j < start + length; j++) {
                    BigDecimal aRe = f[j][0], aIm = f[j][1];
                    BigDecimal bRe = f[j+length][0], bIm = f[j+length][1];
                    BigDecimal dRe = aRe.subtract(bRe, mc), dIm = aIm.subtract(bIm, mc);
                    f[j][0] = aRe.add(bRe, mc);
                    f[j][1] = aIm.add(bIm, mc);
                    f[j+length][0] = wRe.multiply(dRe, mc).subtract(wIm.multiply(dIm, mc), mc);
                    f[j+length][1] = wRe.multiply(dIm, mc).add(wIm.multiply(dRe, mc), mc);
                }
            }
        }
        BigDecimal invN = BigDecimal.ONE.divide(new BigDecimal(n), mc);
        for (int i = 0; i < n; i++) {
            f[i][0] = f[i][0].multiply(invN, mc);
            f[i][1] = f[i][1].multiply(invN, mc);
        }
    }

    /**
     * Compute cos(pi*num/den) and sin(pi*num/den) to arbitrary precision using
     * BigDecimal Taylor series.
     * Returns [cos, sin].
     */
    private static BigDecimal[] cosSinBD(int num, int den, MathContext mc) {
        if (num == 0) {
            return new BigDecimal[] {BigDecimal.ONE, BigDecimal.ZERO};
        }

        // Compute pi to the required precision
        BigDecimal pi = bigDecimalPi(mc);
        // angle = pi * num / den
        BigDecimal angle = pi.multiply(new BigDecimal(num), mc)
                             .divide(new BigDecimal(den), mc);

        // Taylor series: cos(x) = 1 - x^2/2! + x^4/4! - ...
        //                sin(x) = x - x^3/3! + x^5/5! - ...
        BigDecimal x2 = angle.multiply(angle, mc);
        BigDecimal cosSum = BigDecimal.ONE;
        BigDecimal sinSum = angle;
        BigDecimal cosTerm = BigDecimal.ONE;
        BigDecimal sinTerm = angle;

        for (int k = 1; k <= 200; k++) {
            // cosTerm *= -x^2 / ((2k-1) * 2k)
            BigDecimal denom = new BigDecimal((long)(2*k-1) * (2*k));
            cosTerm = cosTerm.multiply(x2, mc).divide(denom, mc).negate();
            cosSum = cosSum.add(cosTerm, mc);

            // sinTerm *= -x^2 / (2k * (2k+1))
            BigDecimal denom2 = new BigDecimal((long)(2*k) * (2*k+1));
            sinTerm = sinTerm.multiply(x2, mc).divide(denom2, mc).negate();
            sinSum = sinSum.add(sinTerm, mc);

            // Check convergence
            if (cosTerm.abs().compareTo(BigDecimal.ONE.scaleByPowerOfTen(-mc.getPrecision()+5)) < 0) {
                break;
            }
        }

        return new BigDecimal[] {cosSum, sinSum};
    }

    /** Compute pi to the precision specified by mc using Machin's formula. */
    private static BigDecimal bigDecimalPi(MathContext mc) {
        // pi/4 = 4*arctan(1/5) - arctan(1/239)
        // arctan(1/x) = 1/x - 1/(3x^3) + 1/(5x^5) - ...
        BigDecimal a5 = arctanRecip(5, mc);
        BigDecimal a239 = arctanRecip(239, mc);
        BigDecimal piOver4 = a5.multiply(new BigDecimal(4), mc).subtract(a239, mc);
        return piOver4.multiply(new BigDecimal(4), mc);
    }

    private static BigDecimal arctanRecip(int x, MathContext mc) {
        BigDecimal xBD = new BigDecimal(x);
        BigDecimal x2 = xBD.multiply(xBD);
        BigDecimal term = BigDecimal.ONE.divide(xBD, mc);
        BigDecimal sum = term;
        for (int k = 3; ; k += 2) {
            term = term.divide(x2, mc);
            BigDecimal addend = term.divide(new BigDecimal(k), mc);
            if (k % 4 == 3) {
                sum = sum.subtract(addend, mc);
            } else {
                sum = sum.add(addend, mc);
            }
            if (addend.abs().compareTo(BigDecimal.ONE.scaleByPowerOfTen(-mc.getPrecision()+2)) < 0) {
                break;
            }
        }
        return sum;
    }
}
