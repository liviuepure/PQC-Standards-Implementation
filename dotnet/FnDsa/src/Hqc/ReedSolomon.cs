namespace FnDsa.Hqc;

/// <summary>
/// Reed-Solomon encoding and decoding over GF(2^8) for HQC.
/// RS(n1, k) with minimum distance d = n1 - k + 1 = 2*delta + 1.
/// Generator polynomial g(x) = prod(x - alpha^i) for i = 1..2*delta.
/// Alpha is the primitive element of GF(2^8) (alpha = 2, using polynomial 0x11D).
/// Forney X_j factor MUST be included for correct error values.
/// </summary>
internal static class ReedSolomon
{
    private const byte GFGenVal = 2;

    /// <summary>Computes the RS generator polynomial of degree 2*delta.</summary>
    private static byte[] GeneratorPoly(int delta)
    {
        int deg = 2 * delta;
        var g = new byte[deg + 1];
        g[0] = 1; // g(x) = 1

        // Multiply by (x - alpha^i) for i = 1..2*delta
        for (int i = 1; i <= deg; i++)
        {
            byte alphai = GF256.Pow(GFGenVal, i);
            byte prev = 0;
            for (int j = 0; j <= deg; j++)
            {
                byte tmp = g[j];
                g[j] = (byte)(GF256.Mul(g[j], alphai) ^ prev);
                prev = tmp;
            }
        }
        return g;
    }

    /// <summary>
    /// Systematic RS encoding.
    /// Input: msg of length k bytes.
    /// Output: codeword of length n1 bytes (parity || msg).
    /// </summary>
    public static byte[] Encode(byte[] msg, HqcParams p)
    {
        int k = p.K;
        int n1 = p.N1;
        int delta = p.Delta;
        byte[] g = GeneratorPoly(delta);
        int parityLen = 2 * delta;

        var feedback = new byte[parityLen];

        for (int i = k - 1; i >= 0; i--)
        {
            byte coeff = GF256.Add(msg[i], feedback[parityLen - 1]);
            for (int j = parityLen - 1; j > 0; j--)
                feedback[j] = GF256.Add(feedback[j - 1], GF256.Mul(coeff, g[j]));
            feedback[0] = GF256.Mul(coeff, g[0]);
        }

        var codeword = new byte[n1];
        Array.Copy(feedback, codeword, parityLen);
        Array.Copy(msg, 0, codeword, parityLen, k);
        return codeword;
    }

    /// <summary>
    /// Decodes a received RS codeword.
    /// Returns (decoded message, success).
    /// </summary>
    public static (byte[]? msg, bool ok) Decode(byte[] received, HqcParams p)
    {
        int n1 = p.N1;
        int k = p.K;
        int delta = p.Delta;

        var r = new byte[n1];
        Array.Copy(received, r, n1);

        // Step 1: Compute syndromes S[1..2*delta]
        var syndromes = new byte[2 * delta + 1]; // syndromes[0] unused
        bool allZero = true;
        for (int i = 1; i <= 2 * delta; i++)
        {
            byte alphai = GF256.Pow(GFGenVal, i);
            byte s = 0;
            for (int j = n1 - 1; j >= 0; j--)
                s = GF256.Add(GF256.Mul(s, alphai), r[j]);
            syndromes[i] = s;
            if (s != 0) allZero = false;
        }

        if (allZero)
        {
            var msg = new byte[k];
            Array.Copy(r, 2 * delta, msg, 0, k);
            return (msg, true);
        }

        // Step 2: Berlekamp-Massey to find error locator sigma
        byte[] sigma = BerlekampMassey(syndromes, delta);
        int sigDeg = 0;
        for (int i = delta; i >= 0; i--)
        {
            if (sigma[i] != 0)
            {
                sigDeg = i;
                break;
            }
        }
        if (sigDeg > delta) return (null, false);

        // Step 3: Chien search - find roots of sigma
        var errorPositions = new List<int>(sigDeg);
        for (int i = 0; i < n1; i++)
        {
            byte alphaInv = GF256.Pow(GFGenVal, 255 - i);
            byte val = 0;
            byte alphaPow = 1;
            for (int j = 0; j <= sigDeg; j++)
            {
                val ^= GF256.Mul(sigma[j], alphaPow);
                alphaPow = GF256.Mul(alphaPow, alphaInv);
            }
            if (val == 0) errorPositions.Add(i);
        }

        if (errorPositions.Count != sigDeg) return (null, false);

        // Step 4: Forney's algorithm - compute error values
        // omega(x) = S(x) * sigma(x) mod x^(2*delta+1)
        var omega = new byte[2 * delta + 1];
        for (int i = 0; i < 2 * delta; i++)
        {
            for (int j = 0; j <= sigDeg && j <= i; j++)
                omega[i + 1] ^= GF256.Mul(sigma[j], syndromes[i + 1 - j]);
        }

        // sigma'(x) = formal derivative of sigma
        var sigmaPrime = new byte[delta + 1];
        for (int i = 1; i <= sigDeg; i += 2)
            sigmaPrime[i - 1] = sigma[i];

        // Correct errors using Forney's formula: e_j = X_j * omega(X_j^{-1}) / sigma'(X_j^{-1})
        foreach (int pos in errorPositions)
        {
            byte alphaInvI = GF256.Inv(GF256.Pow(GFGenVal, pos));

            // Evaluate omega(alpha^(-pos))
            byte omegaVal = 0;
            byte alphaPow = 1;
            for (int j = 0; j <= 2 * delta; j++)
            {
                omegaVal ^= GF256.Mul(omega[j], alphaPow);
                alphaPow = GF256.Mul(alphaPow, alphaInvI);
            }

            // Evaluate sigma'(alpha^(-pos))
            byte sigPrimeVal = 0;
            alphaPow = 1;
            for (int j = 0; j < sigmaPrime.Length; j++)
            {
                sigPrimeVal ^= GF256.Mul(sigmaPrime[j], alphaPow);
                alphaPow = GF256.Mul(alphaPow, alphaInvI);
            }

            if (sigPrimeVal == 0) return (null, false);

            // Forney: e_j = X_j * omega(X_j^{-1}) / sigma'(X_j^{-1})
            byte xj = GF256.Pow(GFGenVal, pos);
            byte errorVal = GF256.Mul(GF256.Mul(xj, omegaVal), GF256.Inv(sigPrimeVal));
            r[pos] ^= errorVal;
        }

        // Extract message
        var result = new byte[k];
        Array.Copy(r, 2 * delta, result, 0, k);
        return (result, true);
    }

    /// <summary>Berlekamp-Massey algorithm for error locator polynomial.</summary>
    private static byte[] BerlekampMassey(byte[] syndromes, int delta)
    {
        int n = 2 * delta;
        var sigma = new byte[delta + 2];
        sigma[0] = 1;
        var b = new byte[delta + 2];
        b[0] = 1;
        int L = 0;
        int m = 1;
        byte deltaN = 1; // previous discrepancy

        for (int kk = 1; kk <= n; kk++)
        {
            byte d = syndromes[kk];
            for (int i = 1; i <= L; i++)
                d ^= GF256.Mul(sigma[i], syndromes[kk - i]);

            if (d == 0)
            {
                m++;
                continue;
            }

            var t = new byte[delta + 2];
            Array.Copy(sigma, t, sigma.Length);
            byte coeff = GF256.Mul(d, GF256.Inv(deltaN));
            for (int i = 0; i <= delta + 1 - m; i++)
            {
                if (i + m <= delta + 1)
                    t[i + m] ^= GF256.Mul(coeff, b[i]);
            }

            if (2 * L < kk)
            {
                Array.Copy(sigma, b, sigma.Length);
                L = kk - L;
                deltaN = d;
                m = 1;
            }
            else
            {
                m++;
            }
            Array.Copy(t, sigma, t.Length);
        }

        var result = new byte[delta + 1];
        Array.Copy(sigma, result, delta + 1);
        return result;
    }
}
