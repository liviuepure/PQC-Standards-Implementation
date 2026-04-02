namespace FnDsa;

public static class FnDsaApi
{
    public static (byte[] Pk, byte[] Sk) KeyGen(Params p, Random? rng = null)
    {
        // rng parameter is ignored; we use OS CSPRNG via RandomNumberGenerator.
        var (f, g, F, _) = NtruKeygen.KeyGen(p);
        int[] h = NtruKeygen.NtruPublicKey(f, g, p);
        byte[] pk = Encode.EncodePk(h, p);
        byte[] sk = Encode.EncodeSk(f, g, F, p);
        return (pk, sk);
    }

    public static byte[] Sign(byte[] sk, byte[] msg, Params p, Random? rng = null)
    {
        // rng parameter is ignored; we use OS CSPRNG via RandomNumberGenerator.
        return FnDsaSign.SignMessage(sk, msg, p);
    }

    public static bool Verify(byte[] pk, byte[] msg, byte[] sig, Params p)
    {
        return FnDsaVerify.VerifySignature(pk, msg, sig, p);
    }
}
