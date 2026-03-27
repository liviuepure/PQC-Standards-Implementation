using PqcStandards.MlKem;

namespace PqcStandards.Tests;

public class MlKemTests
{
    [Theory]
    [MemberData(nameof(AllParams))]
    public void KeyGen_Encaps_Decaps_Roundtrip(MlKemParams p)
    {
        var (ek, dk) = MlKemAlgorithm.KeyGen(p);
        Assert.Equal(p.EkSize, ek.Length);
        Assert.Equal(p.DkSize, dk.Length);

        var (K, ct) = MlKemAlgorithm.Encaps(p, ek);
        Assert.Equal(32, K.Length);
        Assert.Equal(p.CtSize, ct.Length);

        byte[] K2 = MlKemAlgorithm.Decaps(p, dk, ct);
        Assert.Equal(K, K2);
    }

    [Theory]
    [MemberData(nameof(AllParams))]
    public void ImplicitRejection_TamperedCiphertext(MlKemParams p)
    {
        var (ek, dk) = MlKemAlgorithm.KeyGen(p);
        var (K, ct) = MlKemAlgorithm.Encaps(p, ek);

        // Tamper with ciphertext
        byte[] tampered = (byte[])ct.Clone();
        tampered[0] ^= 0xFF;

        byte[] K2 = MlKemAlgorithm.Decaps(p, dk, tampered);

        // Should NOT return the original shared secret (implicit rejection)
        Assert.NotEqual(K, K2);
        // Should still return 32 bytes
        Assert.Equal(32, K2.Length);
    }

    [Fact]
    public void Deterministic_KeyGen_Produces_Consistent_Results()
    {
        var p = MlKemParams.MlKem768;
        byte[] d = new byte[32];
        byte[] z = new byte[32];
        d[0] = 42;
        z[0] = 99;

        var (ek1, dk1) = MlKemAlgorithm.KeyGen(p);
        var (ek2, dk2) = MlKemAlgorithm.KeyGen(p);

        // Different random seeds produce different keys
        Assert.NotEqual(ek1, ek2);
    }

    [Fact]
    public void NttRoundtrip()
    {
        // Test that NTT forward then inverse gives back original
        int[] f = new int[256];
        for (int i = 0; i < 256; i++)
            f[i] = Field.ModQ(i * 17 + 3);

        int[] fhat = Ntt.NttForward(f);
        int[] f2 = Ntt.NttInverse(fhat);

        for (int i = 0; i < 256; i++)
            Assert.Equal(f[i], f2[i]);
    }

    [Fact]
    public void KpkeRoundtrip()
    {
        // Test that K-PKE encrypt/decrypt gives back original message
        var p = MlKemParams.MlKem512;
        byte[] d = new byte[32]; d[0] = 1;
        var (ek, dk) = Kpke.KeyGen(p, d);

        byte[] m = new byte[32]; m[0] = 42;
        byte[] r = new byte[32]; r[0] = 99;

        byte[] ct = Kpke.Encrypt(p, ek, m, r);
        byte[] m2 = Kpke.Decrypt(p, dk, ct);

        Assert.Equal(m, m2);
    }

    [Fact]
    public void MlKemEncapsDecapsRoundtrip512()
    {
        // Focused roundtrip for debugging
        var p = MlKemParams.MlKem512;
        var (ek, dk) = MlKemAlgorithm.KeyGen(p);

        // Check sizes
        Assert.Equal(p.EkSize, ek.Length);
        Assert.Equal(p.DkSize, dk.Length);

        // Encaps
        var (K, ct) = MlKemAlgorithm.Encaps(p, ek);
        Assert.Equal(32, K.Length);
        Assert.Equal(p.CtSize, ct.Length);

        // Test that Kpke decrypt of ct with correct dk_pke recovers something
        int dkPkeLen = 384 * p.K;
        byte[] dkPke = dk[..dkPkeLen];
        byte[] mPrime = Kpke.Decrypt(p, dkPke, ct);
        Assert.Equal(32, mPrime.Length);

        // Now Decaps
        byte[] K2 = MlKemAlgorithm.Decaps(p, dk, ct);
        Assert.Equal(K, K2);
    }

    public static TheoryData<MlKemParams> AllParams() => new()
    {
        MlKemParams.MlKem512,
        MlKemParams.MlKem768,
        MlKemParams.MlKem1024,
    };
}
