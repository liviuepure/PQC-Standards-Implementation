using System.Numerics;

namespace FnDsa;

// Complex FFT/IFFT/SplitFFT/MergeFFT for FN-DSA (FIPS 206 / FALCON).
// Ported from Go reference implementation.
internal static class Fft
{
    private static int FftLogN(int n)
    {
        int logn = 0;
        for (int t = n; t > 1; t >>= 1)
            logn++;
        return logn;
    }

    private static int FftBitRev(int k, int logn)
    {
        int r = 0;
        for (int i = 0; i < logn; i++)
        {
            r = (r << 1) | (k & 1);
            k >>= 1;
        }
        return r;
    }

    // In-place forward negacyclic complex FFT over C[x]/(x^n+1).
    internal static void FFT(Complex[] f, int n)
    {
        int logn = FftLogN(n);
        int k = 0;
        for (int length = n >> 1; length >= 1; length >>= 1)
        {
            for (int start = 0; start < n; start += 2 * length)
            {
                k++;
                int brk = FftBitRev(k, logn);
                Complex w = Complex.FromPolarCoordinates(1.0, Math.PI * brk / n);
                for (int j = start; j < start + length; j++)
                {
                    Complex t = w * f[j + length];
                    f[j + length] = f[j] - t;
                    f[j] = f[j] + t;
                }
            }
        }
    }

    // In-place inverse negacyclic complex FFT. Scaled by 1/n.
    internal static void IFFT(Complex[] f, int n)
    {
        int logn = FftLogN(n);
        int k = n;
        for (int length = 1; length < n; length <<= 1)
        {
            for (int start = n - 2 * length; start >= 0; start -= 2 * length)
            {
                k--;
                int brk = FftBitRev(k, logn);
                Complex wInv = Complex.FromPolarCoordinates(1.0, -Math.PI * brk / n);
                for (int j = start; j < start + length; j++)
                {
                    Complex t = f[j];
                    f[j] = t + f[j + length];
                    f[j + length] = wInv * (t - f[j + length]);
                }
            }
        }
        double invN = 1.0 / n;
        for (int i = 0; i < n; i++)
            f[i] *= invN;
    }

    // Split f(x) = f0(x^2) + x*f1(x^2) in the FFT domain.
    internal static (Complex[] f0, Complex[] f1) SplitFFT(Complex[] f, int n)
    {
        int logn = FftLogN(n);
        int h = n / 2;
        Complex[] f0 = new Complex[h];
        Complex[] f1 = new Complex[h];
        for (int kk = 0; kk < h; kk++)
        {
            int j = FftBitRev(kk, logn - 1);
            Complex omegaJ = Complex.FromPolarCoordinates(1.0, Math.PI * (2 * j + 1) / n);
            Complex a = f[2 * kk];
            Complex b = f[2 * kk + 1];
            f0[kk] = (a + b) / 2;
            f1[kk] = (a - b) / (2 * omegaJ);
        }
        return (f0, f1);
    }

    // Merge: reconstruct f from f0 and f1 (inverse of SplitFFT).
    internal static Complex[] MergeFFT(Complex[] f0, Complex[] f1, int n)
    {
        int logn = FftLogN(n);
        int h = n / 2;
        Complex[] f = new Complex[n];
        for (int kk = 0; kk < h; kk++)
        {
            int j = FftBitRev(kk, logn - 1);
            Complex omegaJ = Complex.FromPolarCoordinates(1.0, Math.PI * (2 * j + 1) / n);
            Complex t = omegaJ * f1[kk];
            f[2 * kk] = f0[kk] + t;
            f[2 * kk + 1] = f0[kk] - t;
        }
        return f;
    }
}
