namespace FnDsa;

// FN-DSA verification (FIPS 206 Algorithm 4).
// Ported from Go reference implementation.
internal static class FnDsaVerify
{
    private const int Q = Ntt.Q;

    // Returns true iff sig is a valid FN-DSA signature on msg under public key pk.
    internal static bool VerifySignature(byte[] pk, byte[] msg, byte[] sig, Params p)
    {
        // 1. Decode public key.
        int[]? h = Encode.DecodePk(pk, p);
        if (h is null) return false;

        // 2. Decode signature.
        var (salt, s1, ok) = Encode.DecodeSig(sig, p);
        if (!ok) return false;

        // 3. Recompute c = HashToPoint(salt || msg).
        byte[] hashInput = new byte[40 + msg.Length];
        Array.Copy(salt!, hashInput, 40);
        Array.Copy(msg, 0, hashInput, 40, msg.Length);
        int[] c = FnDsaSign.HashToPoint(hashInput, p);

        // 4. Compute s2 = c - s1*h (mod q), centered.
        int n = p.N;
        int[] s1ModQ = new int[n];
        for (int i = 0; i < n; i++)
            s1ModQ[i] = ((s1![i] % Q) + Q) % Q;
        int[] s1h = Ntt.PolyMulNtt(s1ModQ, h, n);
        int[] s2 = new int[n];
        for (int i = 0; i < n; i++)
            s2[i] = FnDsaSign.CenterModQ(c[i] - s1h[i]);

        // 5. Norm check.
        return FnDsaSign.NormSq(s1!, s2) <= p.BetaSq;
    }
}
