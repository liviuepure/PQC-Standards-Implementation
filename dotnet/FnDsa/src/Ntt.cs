namespace FnDsa;

// NTT and INTT for FN-DSA (FIPS 206 / FALCON) mod q = 12289.
// Ported from Go reference implementation.
internal static class Ntt
{
    internal const int Q = 12289;

    // Precomputed zeta tables, initialized in static constructor.
    private static readonly int[] ZetasFwd512 = new int[512];
    private static readonly int[] ZetasInv512 = new int[512];
    private static readonly int[] ZetasFwd1024 = new int[1024];
    private static readonly int[] ZetasInv1024 = new int[1024];

    static Ntt()
    {
        // psi_512 = 11^((Q-1)/(2*512)) mod Q
        long psi512 = NttPow(11, (Q - 1) / (2 * 512));
        for (int k = 0; k < 512; k++)
        {
            int br = NttBitRev(k, 9);
            int z = NttPow(psi512, br);
            ZetasFwd512[k] = z;
            ZetasInv512[k] = NttPow(z, Q - 2);
        }

        // psi_1024 = 11^((Q-1)/(2*1024)) mod Q
        long psi1024 = NttPow(11, (Q - 1) / (2 * 1024));
        for (int k = 0; k < 1024; k++)
        {
            int br = NttBitRev(k, 10);
            int z = NttPow(psi1024, br);
            ZetasFwd1024[k] = z;
            ZetasInv1024[k] = NttPow(z, Q - 2);
        }
    }

    internal static int NttMulModQ(long a, long b) => (int)(a * b % Q);

    internal static int NttAddModQ(int a, int b)
    {
        int r = a + b;
        if (r >= Q) r -= Q;
        return r;
    }

    internal static int NttSubModQ(int a, int b)
    {
        int r = a - b;
        if (r < 0) r += Q;
        return r;
    }

    internal static int NttPow(long baseVal, long exp)
    {
        long result = 1;
        long b = baseVal % Q;
        if (b < 0) b += Q;
        while (exp > 0)
        {
            if ((exp & 1) == 1)
                result = result * b % Q;
            exp >>= 1;
            b = b * b % Q;
        }
        return (int)result;
    }

    internal static int NttBitRev(int k, int logn)
    {
        int r = 0;
        for (int i = 0; i < logn; i++)
        {
            r = (r << 1) | (k & 1);
            k >>= 1;
        }
        return r;
    }

    // In-place forward NTT mod Q.
    internal static void NTT(int[] f, int n)
    {
        int[] zetas = n == 512 ? ZetasFwd512 : ZetasFwd1024;
        int k = 0;
        for (int length = n >> 1; length >= 1; length >>= 1)
        {
            for (int start = 0; start < n; start += 2 * length)
            {
                k++;
                long zeta = zetas[k];
                for (int j = start; j < start + length; j++)
                {
                    int t = NttMulModQ(zeta, f[j + length]);
                    f[j + length] = NttSubModQ(f[j], t);
                    f[j] = NttAddModQ(f[j], t);
                }
            }
        }
    }

    // In-place inverse NTT mod Q.
    internal static void INTT(int[] f, int n)
    {
        int[] zetasInv = n == 512 ? ZetasInv512 : ZetasInv1024;
        long nInv = NttPow(n, Q - 2);

        int k = n;
        for (int length = 1; length < n; length <<= 1)
        {
            for (int start = n - 2 * length; start >= 0; start -= 2 * length)
            {
                k--;
                long zetaInv = zetasInv[k];
                for (int j = start; j < start + length; j++)
                {
                    int t = f[j];
                    f[j] = NttAddModQ(t, f[j + length]);
                    f[j + length] = NttMulModQ(zetaInv, NttSubModQ(t, f[j + length]));
                }
            }
        }

        // Scale by n^{-1} mod Q.
        for (int i = 0; i < n; i++)
            f[i] = NttMulModQ(nInv, f[i]);
    }

    // Polynomial multiply mod (Q, x^n+1) using NTT.
    internal static int[] PolyMulNtt(int[] a, int[] b, int n)
    {
        int[] aNtt = new int[n];
        int[] bNtt = new int[n];
        Array.Copy(a, aNtt, n);
        Array.Copy(b, bNtt, n);
        NTT(aNtt, n);
        NTT(bNtt, n);
        int[] cNtt = new int[n];
        for (int i = 0; i < n; i++)
            cNtt[i] = (int)((long)aNtt[i] * bNtt[i] % Q);
        INTT(cNtt, n);
        return cNtt;
    }

    // Polynomial add mod Q.
    internal static int[] PolyAdd(int[] a, int[] b, int n)
    {
        int[] c = new int[n];
        for (int i = 0; i < n; i++)
            c[i] = NttAddModQ(((a[i] % Q) + Q) % Q, ((b[i] % Q) + Q) % Q);
        return c;
    }

    // Polynomial subtract mod Q.
    internal static int[] PolySub(int[] a, int[] b, int n)
    {
        int[] c = new int[n];
        for (int i = 0; i < n; i++)
        {
            int ai = ((a[i] % Q) + Q) % Q;
            int bi = ((b[i] % Q) + Q) % Q;
            c[i] = NttSubModQ(ai, bi);
        }
        return c;
    }
}
