using System.Numerics;

namespace FnDsa;

// NTRU key generation for FN-DSA (FIPS 206 Algorithm 5 NTRUGen).
// Ported from Go reference implementation.
internal static class NtruKeygen
{
    private const int Q = Ntt.Q;

    private static double NtruSigma(int n) =>
        1.17 * Math.Sqrt((double)Q / (2 * n));

    // Generate (f, g, F, G) satisfying f*G - g*F = q over Z[x]/(x^n+1).
    internal static (int[] f, int[] g, int[] F, int[] G) KeyGen(Params p)
    {
        int n = p.N;
        double sigma = NtruSigma(n);

        for (int attempt = 0; attempt < 1000; attempt++)
        {
            int[] f = new int[n];
            int[] g = new int[n];
            for (int i = 0; i < n; i++)
            {
                f[i] = Gaussian.SampleGaussian(sigma);
                g[i] = Gaussian.SampleGaussian(sigma);
            }

            // f must be invertible mod 2.
            int xorSum = 0;
            for (int i = 0; i < n; i++)
                xorSum ^= f[i] & 1;
            if (xorSum == 0) continue;

            // f must be invertible mod q.
            int[] fNtt = new int[n];
            for (int i = 0; i < n; i++)
                fNtt[i] = ((f[i] % Q) + Q) % Q;
            Ntt.NTT(fNtt, n);
            bool ok = true;
            foreach (int v in fNtt)
                if (v == 0) { ok = false; break; }
            if (!ok) continue;

            // Gram-Schmidt norm bound.
            double normSq = 0.0;
            for (int i = 0; i < n; i++)
            {
                normSq += (double)f[i] * f[i];
                normSq += (double)g[i] * g[i];
            }
            if (normSq > 1.17 * 1.17 * Q * n) continue;

            // Solve NTRU equation.
            if (!NtruSolve(n, f, g, out int[]? F, out int[]? G))
                continue;

            // Verify.
            if (!VerifyNtru(f, g, F!, G!, n))
                continue;

            return (f, g, F!, G!);
        }

        throw new InvalidOperationException("FN-DSA: NTRU key generation failed after 1000 attempts");
    }

    // Verify f*G - g*F = q exactly over Z[x]/(x^n+1).
    private static bool VerifyNtru(int[] f, int[] g, int[] F, int[] G, int n)
    {
        long[] fG = PolyMulIntZ(f, G, n);
        long[] gF = PolyMulIntZ(g, F, n);
        if (fG[0] - gF[0] != Q) return false;
        for (int i = 1; i < n; i++)
            if (fG[i] - gF[i] != 0) return false;
        return true;
    }

    // Compute h = g * f^{-1} mod (q, x^n+1).
    internal static int[] NtruPublicKey(int[] f, int[] g, Params p)
    {
        int n = p.N;
        int[] fNtt = new int[n];
        int[] gNtt = new int[n];
        for (int i = 0; i < n; i++)
        {
            fNtt[i] = ((f[i] % Q) + Q) % Q;
            gNtt[i] = ((g[i] % Q) + Q) % Q;
        }
        Ntt.NTT(fNtt, n);
        Ntt.NTT(gNtt, n);

        int[] fInvNtt = new int[n];
        for (int i = 0; i < n; i++)
            fInvNtt[i] = Ntt.NttPow(fNtt[i], Q - 2);

        int[] hNtt = new int[n];
        for (int i = 0; i < n; i++)
            hNtt[i] = (int)((long)gNtt[i] * fInvNtt[i] % Q);
        Ntt.INTT(hNtt, n);
        return hNtt;
    }

    private static bool NtruSolve(int n, int[] f, int[] g, out int[]? F, out int[]? G)
    {
        BigInteger[] fBig = Int32ToBig(f);
        BigInteger[] gBig = Int32ToBig(g);

        if (!NtruSolveBig(n, fBig, gBig, out BigInteger[]? FBig, out BigInteger[]? GBig))
        {
            F = null; G = null;
            return false;
        }

        F = new int[n];
        G = new int[n];
        for (int i = 0; i < n; i++)
        {
            long vF = (long)FBig![i];
            long vG = (long)GBig![i];
            if (vF > int.MaxValue || vF < int.MinValue ||
                vG > int.MaxValue || vG < int.MinValue)
            {
                F = null; G = null;
                return false;
            }
            F[i] = (int)vF;
            G[i] = (int)vG;
        }
        return true;
    }

    private static bool NtruSolveBig(int n, BigInteger[] fBig, BigInteger[] gBig,
        out BigInteger[]? F, out BigInteger[]? G)
    {
        if (n == 1)
        {
            // Base case: solve f[0]*G[0] - g[0]*F[0] = Q over Z.
            BigInteger fVal = fBig[0];
            BigInteger gVal = gBig[0];

            BigInteger gcdVal = BigInteger.GreatestCommonDivisor(
                BigInteger.Abs(fVal), BigInteger.Abs(gVal));

            // Extended GCD: find u,v such that u*f + v*g = gcd
            (BigInteger u, BigInteger v) = ExtGcd(fVal, gVal);

            BigInteger qBig = Q;
            if (qBig % gcdVal != 0)
            {
                F = null; G = null;
                return false;
            }

            BigInteger scale = qBig / gcdVal;
            BigInteger GVal = u * scale;
            BigInteger FVal = -(v * scale);

            F = new[] { FVal };
            G = new[] { GVal };
            return true;
        }

        // Field norms.
        BigInteger[] fNorm = FieldNormBig(fBig, n);
        BigInteger[] gNorm = FieldNormBig(gBig, n);

        if (!NtruSolveBig(n / 2, fNorm, gNorm, out BigInteger[]? Fp, out BigInteger[]? Gp))
        {
            F = null; G = null;
            return false;
        }

        // Lift.
        (BigInteger[] FLifted, BigInteger[] GLifted) = LiftBig(Fp!, Gp!, fBig, gBig, n);

        // Determine max bits in f,g.
        int maxBits = 0;
        foreach (var v in fBig)
        {
            int b = (int)v.GetBitLength();
            if (b > maxBits) maxBits = b;
        }
        foreach (var v in gBig)
        {
            int b = (int)v.GetBitLength();
            if (b > maxBits) maxBits = b;
        }

        // Babai reduction (2 rounds).
        for (int round = 0; round < 2; round++)
        {
            int maxFGBits = maxBits;
            foreach (var v in FLifted)
            {
                int b = (int)v.GetBitLength();
                if (b > maxFGBits) maxFGBits = b;
            }
            foreach (var v in GLifted)
            {
                int b = (int)v.GetBitLength();
                if (b > maxFGBits) maxFGBits = b;
            }

            BigInteger[] k;
            if (maxFGBits <= 53)
            {
                double[] fSmall = new double[n];
                double[] gSmall = new double[n];
                for (int i = 0; i < n; i++)
                {
                    fSmall[i] = (double)fBig[i];
                    gSmall[i] = (double)gBig[i];
                }
                k = BabaiFloat64(FLifted, GLifted, fSmall, gSmall, n);
            }
            else
            {
                uint prec = (uint)(maxFGBits * 2 + FftLogN(n) * 64 + 256);
                k = BabaiBigFloat(FLifted, GLifted, fBig, gBig, n, prec);
            }

            BigInteger[] kf = PolyMulIntZBig(k, fBig, n);
            BigInteger[] kg = PolyMulIntZBig(k, gBig, n);
            for (int i = 0; i < n; i++)
            {
                FLifted[i] -= kf[i];
                GLifted[i] -= kg[i];
            }
        }

        F = FLifted;
        G = GLifted;
        return true;
    }

    // Extended GCD: returns (u, v) such that u*a + v*b = gcd(a,b).
    private static (BigInteger u, BigInteger v) ExtGcd(BigInteger a, BigInteger b)
    {
        BigInteger oldR = a, r = b;
        BigInteger oldS = BigInteger.One, s = BigInteger.Zero;
        BigInteger oldT = BigInteger.Zero, t = BigInteger.One;

        while (r != 0)
        {
            BigInteger quotient = FloorDiv(oldR, r);
            (oldR, r) = (r, oldR - quotient * r);
            (oldS, s) = (s, oldS - quotient * s);
            (oldT, t) = (t, oldT - quotient * t);
        }
        return (oldS, oldT);
    }

    // Floor division for BigInteger (rounds toward -infinity).
    private static BigInteger FloorDiv(BigInteger a, BigInteger b)
    {
        BigInteger q = BigInteger.DivRem(a, b, out BigInteger rem);
        if (rem != 0 && (rem < 0) != (b < 0))
            q -= 1;
        return q;
    }

    // Round a BigFloat value to nearest integer (round half away from zero).
    private static BigInteger RoundHalfAwayFromZero(BigFloat val)
    {
        return val.Round();
    }

    // Babai reduction using float64 FFT.
    private static BigInteger[] BabaiFloat64(
        BigInteger[] F, BigInteger[] G, double[] f, double[] g, int n)
    {
        System.Numerics.Complex[] FC = new System.Numerics.Complex[n];
        System.Numerics.Complex[] GC = new System.Numerics.Complex[n];
        System.Numerics.Complex[] fC = new System.Numerics.Complex[n];
        System.Numerics.Complex[] gC = new System.Numerics.Complex[n];

        for (int i = 0; i < n; i++)
        {
            FC[i] = new System.Numerics.Complex((double)F[i], 0);
            GC[i] = new System.Numerics.Complex((double)G[i], 0);
            fC[i] = new System.Numerics.Complex(f[i], 0);
            gC[i] = new System.Numerics.Complex(g[i], 0);
        }

        Fft.FFT(FC, n);
        Fft.FFT(GC, n);
        Fft.FFT(fC, n);
        Fft.FFT(gC, n);

        System.Numerics.Complex[] kC = new System.Numerics.Complex[n];
        for (int i = 0; i < n; i++)
        {
            var fi = fC[i];
            var gi = gC[i];
            var Fi = FC[i];
            var Gi = GC[i];
            var fiConj = System.Numerics.Complex.Conjugate(fi);
            var giConj = System.Numerics.Complex.Conjugate(gi);
            var num = Fi * fiConj + Gi * giConj;
            var denom = fi * fiConj + gi * giConj;
            if (denom.Real != 0)
                kC[i] = num / denom;
        }

        Fft.IFFT(kC, n);

        BigInteger[] k = new BigInteger[n];
        for (int i = 0; i < n; i++)
            k[i] = new BigInteger((long)Math.Round(kC[i].Real));
        return k;
    }

    // Babai reduction using arbitrary-precision arithmetic.
    private static BigInteger[] BabaiBigFloat(
        BigInteger[] F, BigInteger[] G, BigInteger[] f, BigInteger[] g, int n, uint prec)
    {
        // We use our BigFloat struct for arbitrary precision arithmetic.
        int logn = FftLogN(n);

        // Represent complex numbers as pairs of BigFloat.
        BigFloat[] FA_re = new BigFloat[n], FA_im = new BigFloat[n];
        BigFloat[] GA_re = new BigFloat[n], GA_im = new BigFloat[n];
        BigFloat[] fA_re = new BigFloat[n], fA_im = new BigFloat[n];
        BigFloat[] gA_re = new BigFloat[n], gA_im = new BigFloat[n];

        for (int i = 0; i < n; i++)
        {
            FA_re[i] = BigFloat.FromBigInteger(F[i], prec);
            FA_im[i] = BigFloat.Zero(prec);
            GA_re[i] = BigFloat.FromBigInteger(G[i], prec);
            GA_im[i] = BigFloat.Zero(prec);
            fA_re[i] = BigFloat.FromBigInteger(f[i], prec);
            fA_im[i] = BigFloat.Zero(prec);
            gA_re[i] = BigFloat.FromBigInteger(g[i], prec);
            gA_im[i] = BigFloat.Zero(prec);
        }

        // FFT on each array.
        void DoFFT(BigFloat[] re, BigFloat[] im)
        {
            int k = 0;
            for (int length = n >> 1; length >= 1; length >>= 1)
            {
                for (int start = 0; start < n; start += 2 * length)
                {
                    k++;
                    int brk = FftBitRevStatic(k, logn);
                    // w = exp(i*pi*brk/n)
                    (BigFloat wRe, BigFloat wIm) = BigFloat.CosSin(brk, n, prec);
                    for (int j = start; j < start + length; j++)
                    {
                        // t = w * arr[j+length]
                        BigFloat tRe = BigFloat.Sub(BigFloat.Mul(wRe, re[j + length], prec),
                                                    BigFloat.Mul(wIm, im[j + length], prec), prec);
                        BigFloat tIm = BigFloat.Add(BigFloat.Mul(wRe, im[j + length], prec),
                                                    BigFloat.Mul(wIm, re[j + length], prec), prec);
                        // arr[j+length] = arr[j] - t
                        BigFloat newRe1 = BigFloat.Sub(re[j], tRe, prec);
                        BigFloat newIm1 = BigFloat.Sub(im[j], tIm, prec);
                        // arr[j] = arr[j] + t
                        re[j] = BigFloat.Add(re[j], tRe, prec);
                        im[j] = BigFloat.Add(im[j], tIm, prec);
                        re[j + length] = newRe1;
                        im[j + length] = newIm1;
                    }
                }
            }
        }

        void DoIFFT(BigFloat[] re, BigFloat[] im)
        {
            int k = n;
            for (int length = 1; length < n; length <<= 1)
            {
                for (int start = n - 2 * length; start >= 0; start -= 2 * length)
                {
                    k--;
                    int brk = FftBitRevStatic(k, logn);
                    // wInv = exp(-i*pi*brk/n)
                    (BigFloat wRe, BigFloat wIm) = BigFloat.CosSin(brk, n, prec);
                    // negate wIm for inverse
                    BigFloat wImInv = BigFloat.Negate(wIm, prec);
                    for (int j = start; j < start + length; j++)
                    {
                        BigFloat aRe = re[j], aIm = im[j];
                        BigFloat bRe = re[j + length], bIm = im[j + length];
                        re[j] = BigFloat.Add(aRe, bRe, prec);
                        im[j] = BigFloat.Add(aIm, bIm, prec);
                        // diff = a - b
                        BigFloat dRe = BigFloat.Sub(aRe, bRe, prec);
                        BigFloat dIm = BigFloat.Sub(aIm, bIm, prec);
                        // wInv * diff
                        re[j + length] = BigFloat.Sub(BigFloat.Mul(wRe, dRe, prec),
                                                      BigFloat.Mul(wImInv, dIm, prec), prec);
                        im[j + length] = BigFloat.Add(BigFloat.Mul(wRe, dIm, prec),
                                                      BigFloat.Mul(wImInv, dRe, prec), prec);
                    }
                }
            }
            BigFloat invN = BigFloat.FromDouble(1.0 / n, prec);
            for (int i = 0; i < n; i++)
            {
                re[i] = BigFloat.Mul(re[i], invN, prec);
                im[i] = BigFloat.Mul(im[i], invN, prec);
            }
        }

        DoFFT(FA_re, FA_im);
        DoFFT(GA_re, GA_im);
        DoFFT(fA_re, fA_im);
        DoFFT(gA_re, gA_im);

        BigFloat[] kA_re = new BigFloat[n];
        BigFloat[] kA_im = new BigFloat[n];

        for (int i = 0; i < n; i++)
        {
            // fConj = (fA[i].re, -fA[i].im)
            // gConj = (gA[i].re, -gA[i].im)
            // num = FA[i]*fConj + GA[i]*gConj
            BigFloat fConjRe = fA_re[i];
            BigFloat fConjIm = BigFloat.Negate(fA_im[i], prec);
            BigFloat gConjRe = gA_re[i];
            BigFloat gConjIm = BigFloat.Negate(gA_im[i], prec);

            // FA[i] * fConj
            BigFloat numRe = BigFloat.Sub(BigFloat.Mul(FA_re[i], fConjRe, prec),
                                          BigFloat.Mul(FA_im[i], fConjIm, prec), prec);
            BigFloat numIm = BigFloat.Add(BigFloat.Mul(FA_re[i], fConjIm, prec),
                                          BigFloat.Mul(FA_im[i], fConjRe, prec), prec);

            // GA[i] * gConj
            BigFloat numRe2 = BigFloat.Sub(BigFloat.Mul(GA_re[i], gConjRe, prec),
                                           BigFloat.Mul(GA_im[i], gConjIm, prec), prec);
            BigFloat numIm2 = BigFloat.Add(BigFloat.Mul(GA_re[i], gConjIm, prec),
                                           BigFloat.Mul(GA_im[i], gConjRe, prec), prec);

            numRe = BigFloat.Add(numRe, numRe2, prec);
            numIm = BigFloat.Add(numIm, numIm2, prec);

            // denom = |fA[i]|^2 + |gA[i]|^2
            BigFloat fMag2 = BigFloat.Add(BigFloat.Mul(fA_re[i], fA_re[i], prec),
                                          BigFloat.Mul(fA_im[i], fA_im[i], prec), prec);
            BigFloat gMag2 = BigFloat.Add(BigFloat.Mul(gA_re[i], gA_re[i], prec),
                                          BigFloat.Mul(gA_im[i], gA_im[i], prec), prec);
            BigFloat denom = BigFloat.Add(fMag2, gMag2, prec);

            if (!denom.IsZero())
            {
                kA_re[i] = BigFloat.Div(numRe, denom, prec);
                kA_im[i] = BigFloat.Div(numIm, denom, prec);
            }
            else
            {
                kA_re[i] = BigFloat.Zero(prec);
                kA_im[i] = BigFloat.Zero(prec);
            }
        }

        DoIFFT(kA_re, kA_im);

        BigInteger[] result = new BigInteger[n];
        for (int i = 0; i < n; i++)
            result[i] = kA_re[i].Round();
        return result;
    }

    private static int FftLogN(int n)
    {
        int logn = 0;
        for (int t = n; t > 1; t >>= 1)
            logn++;
        return logn;
    }

    private static int FftBitRevStatic(int k, int logn)
    {
        int r = 0;
        for (int i = 0; i < logn; i++)
        {
            r = (r << 1) | (k & 1);
            k >>= 1;
        }
        return r;
    }

    // Multiply polynomials over Z[x]/(x^n+1) exactly using int64.
    private static long[] PolyMulIntZ(int[] a, int[] b, int n)
    {
        long[] c = new long[n];
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                int idx = i + j;
                long val = (long)a[i] * b[j];
                if (idx < n)
                    c[idx] += val;
                else
                    c[idx - n] -= val;
            }
        }
        return c;
    }

    // Multiply polynomials over Z[x]/(x^n+1) using BigInteger.
    private static BigInteger[] PolyMulIntZBig(BigInteger[] a, BigInteger[] b, int n)
    {
        BigInteger[] c = new BigInteger[n];
        for (int i = 0; i < n; i++) c[i] = BigInteger.Zero;
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                int idx = i + j;
                BigInteger val = a[i] * b[j];
                if (idx < n)
                    c[idx] += val;
                else
                    c[idx - n] -= val;
            }
        }
        return c;
    }

    // Field norm from Z[x]/(x^n+1) to Z[x]/(x^{n/2}+1).
    private static BigInteger[] FieldNormBig(BigInteger[] f, int n)
    {
        int h = n / 2;
        BigInteger[] f0 = new BigInteger[h];
        BigInteger[] f1 = new BigInteger[h];
        for (int i = 0; i < h; i++)
        {
            f0[i] = f[2 * i];
            f1[i] = f[2 * i + 1];
        }
        BigInteger[] f0sq = PolyMulIntZBig(f0, f0, h);
        BigInteger[] f1sq = PolyMulIntZBig(f1, f1, h);

        BigInteger[] result = new BigInteger[h];
        result[0] = f0sq[0] + f1sq[h - 1];
        for (int i = 1; i < h; i++)
            result[i] = f0sq[i] - f1sq[i - 1];
        return result;
    }

    // Tower conjugate: f*(x) = f_0(x^2) - x*f_1(x^2) (negate odd coefficients).
    private static BigInteger[] TowerConjugateBig(BigInteger[] f)
    {
        int n = f.Length;
        BigInteger[] result = new BigInteger[n];
        for (int i = 0; i < n; i++)
            result[i] = (i % 2 == 0) ? f[i] : -f[i];
        return result;
    }

    // Lift (F', G') from degree n/2 to degree n.
    private static (BigInteger[] F, BigInteger[] G) LiftBig(
        BigInteger[] Fp, BigInteger[] Gp,
        BigInteger[] f, BigInteger[] g, int n)
    {
        int h = n / 2;
        BigInteger[] FpLift = new BigInteger[n];
        BigInteger[] GpLift = new BigInteger[n];
        for (int i = 0; i < n; i++) { FpLift[i] = BigInteger.Zero; GpLift[i] = BigInteger.Zero; }
        for (int i = 0; i < h; i++)
        {
            FpLift[2 * i] = Fp[i];
            GpLift[2 * i] = Gp[i];
        }

        BigInteger[] fConj = TowerConjugateBig(f);
        BigInteger[] gConj = TowerConjugateBig(g);
        BigInteger[] F = PolyMulIntZBig(gConj, FpLift, n);
        BigInteger[] G = PolyMulIntZBig(fConj, GpLift, n);
        return (F, G);
    }

    private static BigInteger[] Int32ToBig(int[] a)
    {
        BigInteger[] res = new BigInteger[a.Length];
        for (int i = 0; i < a.Length; i++)
            res[i] = new BigInteger(a[i]);
        return res;
    }
}

// Simple arbitrary-precision float using BigInteger mantissa.
// Represents value = mantissa * 2^exponent.
internal struct BigFloat
{
    private readonly BigInteger _mantissa;
    private readonly int _exponent; // value = _mantissa * 2^_exponent
    private readonly uint _prec;

    private BigFloat(BigInteger mantissa, int exponent, uint prec)
    {
        _mantissa = mantissa;
        _exponent = exponent;
        _prec = prec;
    }

    public static BigFloat Zero(uint prec) => new(BigInteger.Zero, 0, prec);

    public bool IsZero() => _mantissa.IsZero;

    public static BigFloat FromDouble(double d, uint prec)
    {
        if (d == 0) return Zero(prec);
        long bits = BitConverter.DoubleToInt64Bits(d);
        long mantissa = bits & 0x000FFFFFFFFFFFFFL;
        int exp = (int)((bits >> 52) & 0x7FF);
        bool negative = (bits & unchecked((long)0x8000000000000000L)) != 0;

        BigInteger m;
        int e;
        if (exp == 0)
        {
            // Subnormal
            m = new BigInteger(mantissa);
            e = -1074;
        }
        else
        {
            m = new BigInteger(mantissa | (1L << 52));
            e = exp - 1075;
        }
        if (negative) m = -m;
        return Normalize(m, e, prec);
    }

    public static BigFloat FromBigInteger(BigInteger v, uint prec)
    {
        if (v.IsZero) return Zero(prec);
        return Normalize(v, 0, prec);
    }

    private static BigFloat Normalize(BigInteger m, int e, uint prec)
    {
        if (m.IsZero) return Zero(prec);
        // We want _mantissa to have exactly prec significant bits.
        int mBits = (int)m.GetBitLength();
        int shift = mBits - (int)prec;
        if (shift > 0)
        {
            // Round half-up.
            BigInteger half = BigInteger.One << (shift - 1);
            m = (m + (m >= 0 ? half : -half)) >> shift;
            e += shift;
        }
        else if (shift < 0)
        {
            m <<= -shift;
            e += shift;
        }
        return new BigFloat(m, e, prec);
    }

    public static BigFloat Add(BigFloat a, BigFloat b, uint prec)
    {
        if (a.IsZero()) return b.WithPrec(prec);
        if (b.IsZero()) return a.WithPrec(prec);
        // Align exponents.
        int aE = a._exponent, bE = b._exponent;
        BigInteger aM = a._mantissa, bM = b._mantissa;
        if (aE > bE)
        {
            int diff = aE - bE;
            aM <<= diff;
            aE = bE;
        }
        else if (bE > aE)
        {
            int diff = bE - aE;
            bM <<= diff;
        }
        return Normalize(aM + bM, aE, prec);
    }

    public static BigFloat Sub(BigFloat a, BigFloat b, uint prec)
    {
        return Add(a, new BigFloat(-b._mantissa, b._exponent, prec), prec);
    }

    public static BigFloat Mul(BigFloat a, BigFloat b, uint prec)
    {
        if (a.IsZero() || b.IsZero()) return Zero(prec);
        return Normalize(a._mantissa * b._mantissa, a._exponent + b._exponent, prec);
    }

    public static BigFloat Div(BigFloat a, BigFloat b, uint prec)
    {
        if (a.IsZero()) return Zero(prec);
        // a / b = (a._m << extra) / b._m, exponent adjusted.
        int extra = (int)prec + (int)b._mantissa.GetBitLength();
        BigInteger scaled = a._mantissa * (BigInteger.One << extra);
        BigInteger q = scaled / b._mantissa;
        return Normalize(q, a._exponent - b._exponent - extra, prec);
    }

    public static BigFloat Negate(BigFloat a, uint prec)
    {
        return new BigFloat(-a._mantissa, a._exponent, prec);
    }

    private BigFloat WithPrec(uint prec)
    {
        if (_prec == prec) return this;
        return Normalize(_mantissa, _exponent, prec);
    }

    // Round to nearest integer (round half away from zero).
    public BigInteger Round()
    {
        if (_exponent >= 0)
        {
            // Integer already: shift left.
            return _mantissa << _exponent;
        }
        int shift = -_exponent;
        BigInteger half = BigInteger.One << (shift - 1);
        bool negative = _mantissa < 0;
        BigInteger absM = BigInteger.Abs(_mantissa);
        BigInteger rounded = (absM + half) >> shift;
        return negative ? -rounded : rounded;
    }

    // Compute (cos(pi*num/den), sin(pi*num/den)) using double precision.
    // For the precision required in NTRU Babai (deep levels), we use Machin-like high-precision.
    public static (BigFloat cos, BigFloat sin) CosSin(int num, int den, uint prec)
    {
        if (prec <= 53)
        {
            double angle = Math.PI * num / den;
            return (FromDouble(Math.Cos(angle), prec), FromDouble(Math.Sin(angle), prec));
        }

        // High precision using BigInteger arithmetic.
        // Compute pi with sufficient precision.
        BigInteger piFixed = ComputePiFixed(prec + 64);
        int fixedScale = (int)(prec + 64);

        // angle = pi * num / den  (in fixed-point scaled by 2^fixedScale)
        BigInteger angleFixed = piFixed * num / den;

        // Compute sin and cos using Taylor series in fixed point.
        BigInteger cosFixed = ComputeCosFixed(angleFixed, fixedScale, prec);
        BigInteger sinFixed = ComputeSinFixed(angleFixed, fixedScale, prec);

        // Convert back to BigFloat (value = fixed / 2^fixedScale).
        return (Normalize(cosFixed, -fixedScale, prec), Normalize(sinFixed, -fixedScale, prec));
    }

    // Compute pi * 2^bits using Machin's formula.
    private static BigInteger ComputePiFixed(uint bits)
    {
        BigInteger scale = BigInteger.One << (int)bits;
        // pi/4 = 4*arctan(1/5) - arctan(1/239)
        BigInteger a5 = ArctanRecipFixed(5, bits);
        BigInteger a239 = ArctanRecipFixed(239, bits);
        return 4 * (4 * a5 - a239);
    }

    // arctan(1/x) * 2^bits using Taylor series.
    private static BigInteger ArctanRecipFixed(long x, uint bits)
    {
        BigInteger scale = BigInteger.One << (int)bits;
        BigInteger xBig = new BigInteger(x);
        BigInteger x2 = xBig * xBig;

        BigInteger term = scale / xBig; // 1/x
        BigInteger sum = term;
        long sign = -1;
        for (long k = 3; ; k += 2)
        {
            term /= x2;
            BigInteger addend = term / k;
            if (addend.IsZero) break;
            if (sign < 0)
                sum -= addend;
            else
                sum += addend;
            sign = -sign;
        }
        return sum;
    }

    // Compute cos(angle) where angle is in fixed-point (scaled by 2^bits).
    private static BigInteger ComputeCosFixed(BigInteger angle, int bits, uint prec)
    {
        BigInteger scale = BigInteger.One << bits;
        BigInteger angle2 = (angle * angle) >> bits;

        BigInteger cosTerm = scale; // 1
        BigInteger cosSum = scale;

        for (long k = 1; ; k++)
        {
            cosTerm = -(cosTerm * angle2 >> bits) / ((2 * k - 1) * (2 * k));
            cosSum += cosTerm;
            if (BigInteger.Abs(cosTerm) < (scale >> (int)prec)) break;
        }
        return cosSum;
    }

    // Compute sin(angle) where angle is in fixed-point (scaled by 2^bits).
    private static BigInteger ComputeSinFixed(BigInteger angle, int bits, uint prec)
    {
        BigInteger scale = BigInteger.One << bits;
        BigInteger angle2 = (angle * angle) >> bits;

        BigInteger sinTerm = angle; // x
        BigInteger sinSum = angle;

        for (long k = 1; ; k++)
        {
            sinTerm = -(sinTerm * angle2 >> bits) / ((2 * k) * (2 * k + 1));
            sinSum += sinTerm;
            if (BigInteger.Abs(sinTerm) < (scale >> (int)prec)) break;
        }
        return sinSum;
    }
}
