using System.Numerics;
using System.Security.Cryptography;

namespace FnDsa;

// FN-DSA signing (FIPS 206). Ported from Go reference implementation.
internal static class FnDsaSign
{
    private const int Q = Ntt.Q;

    // Hash a message (salt||msg) to a polynomial c in Z_q[x]/(x^n+1).
    // Uses SHAKE256 with rejection sampling.
    internal static int[] HashToPoint(byte[] msg, Params p)
    {
        int n = p.N;
        int[] out_ = new int[n];

        // Generate enough SHAKE256 output for rejection sampling.
        // In practice, need slightly more than 2*n bytes.
        int bufSize = n * 3; // generous buffer
        byte[] shakeOut = Shake256Hash(msg, bufSize);

        int count = 0;
        int pos = 0;
        while (count < n)
        {
            if (pos + 2 > shakeOut.Length)
            {
                // Expand more if needed (should be rare).
                bufSize *= 2;
                shakeOut = Shake256Hash(msg, bufSize);
                pos = 0;
                count = 0;
            }
            int v = (int)((uint)shakeOut[pos] | ((uint)shakeOut[pos + 1] << 8));
            pos += 2;
            if (v < 5 * Q)
            {
                out_[count] = v % Q;
                count++;
            }
        }
        return out_;
    }

    // Center v mod Q to (-Q/2, Q/2].
    internal static int CenterModQ(int v)
    {
        v = ((v % Q) + Q) % Q;
        if (v > Q / 2) v -= Q;
        return v;
    }

    // Convert int[] polynomial to complex FFT domain.
    private static Complex[] Int32sToFFT(int[] a, int n)
    {
        Complex[] f = new Complex[n];
        for (int i = 0; i < n; i++)
            f[i] = new Complex(a[i], 0);
        Fft.FFT(f, n);
        return f;
    }

    // Apply IFFT and round to nearest integer polynomial.
    private static int[] RoundFFTToInt32s(Complex[] fft, int n)
    {
        Complex[] tmp = new Complex[n];
        Array.Copy(fft, tmp, n);
        Fft.IFFT(tmp, n);
        int[] out_ = new int[n];
        for (int i = 0; i < n; i++)
            out_[i] = (int)Math.Round(tmp[i].Real);
        return out_;
    }

    // Recover G from (f, g, F) via NTRU equation: G = g*F*f^{-1} mod q.
    internal static (int[]? G, bool ok) RecoverG(int[] f, int[] g, int[] F, int n)
    {
        int[] gModQ = new int[n];
        int[] FModQ = new int[n];
        for (int i = 0; i < n; i++)
        {
            gModQ[i] = ((g[i] % Q) + Q) % Q;
            FModQ[i] = ((F[i] % Q) + Q) % Q;
        }
        int[] gF = Ntt.PolyMulNtt(gModQ, FModQ, n);

        int[] fModQ = new int[n];
        for (int i = 0; i < n; i++)
            fModQ[i] = ((f[i] % Q) + Q) % Q;
        int[] fNtt = new int[n];
        Array.Copy(fModQ, fNtt, n);
        Ntt.NTT(fNtt, n);

        foreach (int v in fNtt)
            if (v == 0) return (null, false);

        int[] fInvNtt = new int[n];
        for (int i = 0; i < n; i++)
            fInvNtt[i] = Ntt.NttPow(fNtt[i], Q - 2);
        Ntt.INTT(fInvNtt, n);

        int[] G = Ntt.PolyMulNtt(gF, fInvNtt, n);
        int[] result = new int[n];
        for (int i = 0; i < n; i++)
        {
            int v = G[i];
            if (v > Q / 2) v -= Q;
            result[i] = v;
        }
        return (result, true);
    }

    // Babai nearest-plane sampling.
    internal static (int[] s1, int[] s2) FfSamplingBabai(
        int[] c, int[] f, int[] g, int[] F, int[] G, int n)
    {
        Complex[] cFFT = Int32sToFFT(c, n);
        Complex[] fFFT = Int32sToFFT(f, n);
        Complex[] gFFT = Int32sToFFT(g, n);
        Complex[] FFFT = Int32sToFFT(F, n);
        Complex[] GFFT = Int32sToFFT(G, n);

        // Gram-Schmidt: b1^* = b1 - mu10*b0^*
        var b1StarFFT = new (Complex c0, Complex c1)[n];
        double[] b1StarNormSq = new double[n];
        for (int j = 0; j < n; j++)
        {
            Complex gj = gFFT[j];
            Complex fj = fFFT[j];
            Complex Gj = GFFT[j];
            Complex Fj = FFFT[j];
            double b0NormSq = gj.Real * gj.Real + gj.Imaginary * gj.Imaginary
                            + fj.Real * fj.Real + fj.Imaginary * fj.Imaginary;
            Complex mu10 = Complex.Zero;
            if (b0NormSq != 0)
            {
                Complex num = Gj * Complex.Conjugate(gj) + Fj * Complex.Conjugate(fj);
                mu10 = new Complex(num.Real / b0NormSq, num.Imaginary / b0NormSq);
            }
            Complex b1s0 = Gj - mu10 * gj;
            Complex b1s1 = -Fj + mu10 * fj;
            b1StarFFT[j] = (b1s0, b1s1);
            b1StarNormSq[j] = b1s0.Real * b1s0.Real + b1s0.Imaginary * b1s0.Imaginary
                             + b1s1.Real * b1s1.Real + b1s1.Imaginary * b1s1.Imaginary;
        }

        // Step 1: project c along b1^*.
        Complex[] tau1FFT = new Complex[n];
        for (int j = 0; j < n; j++)
        {
            double b1sNorm = b1StarNormSq[j];
            if (b1sNorm != 0)
            {
                Complex b1s0 = b1StarFFT[j].c0;
                Complex num = cFFT[j] * Complex.Conjugate(b1s0);
                tau1FFT[j] = new Complex(num.Real / b1sNorm, num.Imaginary / b1sNorm);
            }
        }
        int[] z1 = RoundFFTToInt32s(tau1FFT, n);
        Complex[] z1FFT = Int32sToFFT(z1, n);

        // Update target.
        Complex[] cPrimeFFT = new Complex[n];
        Complex[] xPrimeFFT = new Complex[n];
        for (int j = 0; j < n; j++)
        {
            cPrimeFFT[j] = cFFT[j] - z1FFT[j] * GFFT[j];
            xPrimeFFT[j] = z1FFT[j] * FFFT[j];
        }

        // Step 2: project along b0^*.
        Complex[] tau0FFT = new Complex[n];
        for (int j = 0; j < n; j++)
        {
            Complex gj = gFFT[j];
            Complex fj = fFFT[j];
            double b0NormSq = gj.Real * gj.Real + gj.Imaginary * gj.Imaginary
                            + fj.Real * fj.Real + fj.Imaginary * fj.Imaginary;
            if (b0NormSq != 0)
            {
                Complex num = cPrimeFFT[j] * Complex.Conjugate(gj)
                            - xPrimeFFT[j] * Complex.Conjugate(fj);
                tau0FFT[j] = new Complex(num.Real / b0NormSq, num.Imaginary / b0NormSq);
            }
        }
        int[] z0 = RoundFFTToInt32s(tau0FFT, n);
        Complex[] z0FFT = Int32sToFFT(z0, n);

        // Compute s1, s2.
        Complex[] s1FFT = new Complex[n];
        Complex[] s2FFT = new Complex[n];
        for (int j = 0; j < n; j++)
        {
            s1FFT[j] = z0FFT[j] * fFFT[j] + z1FFT[j] * FFFT[j];
            s2FFT[j] = cFFT[j] - z0FFT[j] * gFFT[j] - z1FFT[j] * GFFT[j];
        }

        int[] s1Raw = RoundFFTToInt32s(s1FFT, n);
        int[] s2Raw = RoundFFTToInt32s(s2FFT, n);

        int[] s1out = new int[n];
        int[] s2out = new int[n];
        for (int i = 0; i < n; i++)
        {
            s1out[i] = CenterModQ(s1Raw[i]);
            s2out[i] = CenterModQ(s2Raw[i]);
        }
        return (s1out, s2out);
    }

    // Squared norm of (s1, s2).
    internal static long NormSq(int[] s1, int[] s2)
    {
        long n = 0;
        foreach (int v in s1) n += (long)v * v;
        foreach (int v in s2) n += (long)v * v;
        return n;
    }

    // Sign a message using the secret key.
    internal static byte[] SignMessage(byte[] sk, byte[] msg, Params p)
    {
        var (f, g, F, ok) = Encode.DecodeSk(sk, p);
        if (!ok) throw new ArgumentException("FN-DSA: invalid secret key");
        int n = p.N;

        var (G, ok2) = FnDsaSign.RecoverG(f, g, F, n);
        if (!ok2) throw new ArgumentException("FN-DSA: invalid secret key: f not invertible mod q");

        int[] h = NtruKeygen.NtruPublicKey(f, g, p);

        byte[] salt = new byte[40];
        const int maxAttempts = 1000;
        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            RandomNumberGenerator.Fill(salt);

            byte[] hashInput = new byte[40 + msg.Length];
            Array.Copy(salt, hashInput, 40);
            Array.Copy(msg, 0, hashInput, 40, msg.Length);
            int[] c = HashToPoint(hashInput, p);

            int[] cCentered = new int[n];
            for (int i = 0; i < n; i++)
                cCentered[i] = CenterModQ(c[i]);

            var (s1, s2) = FfSamplingBabai(cCentered, f, g, F, G!, n);

            // Verify s1*h + s2 ≡ c (mod q).
            int[] s1ModQ = new int[n];
            for (int i = 0; i < n; i++)
                s1ModQ[i] = ((s1[i] % Q) + Q) % Q;
            int[] s1h = Ntt.PolyMulNtt(s1ModQ, h, n);
            bool valid = true;
            for (int i = 0; i < n; i++)
            {
                int sum = (int)(((long)s1h[i] + s2[i]) % Q);
                if (sum < 0) sum += Q;
                if (sum != c[i]) { valid = false; break; }
            }
            if (!valid) continue;

            // Check norm bound.
            long ns = NormSq(s1, s2);
            if (ns > p.BetaSq) continue;

            var (sig, encOk) = Encode.EncodeSig(salt, s1, p);
            if (!encOk) continue;
            return sig!;
        }

        throw new InvalidOperationException("FN-DSA: signing failed after max attempts");
    }

    // SHAKE-256 wrapper using our pure-managed implementation.
    private static byte[] Shake256Hash(byte[] input, int outputLen)
    {
        return Shake256Impl.Hash(input, outputLen);
    }
}
