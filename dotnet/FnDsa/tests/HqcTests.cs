using System;
using FnDsa.Hqc;
using Xunit;

namespace FnDsa.Tests;

public class HqcTests
{
    [Theory]
    [InlineData("HQC-128")]
    [InlineData("HQC-192")]
    [InlineData("HQC-256")]
    public void KEMRoundtrip(string paramName)
    {
        var p = GetParams(paramName);

        var (pk, sk) = HqcKem.KeyGen(p);
        Assert.Equal(p.PKSize, pk.Length);
        Assert.Equal(p.SKSize, sk.Length);

        var (ct, ss1) = HqcKem.Encaps(pk, p);
        Assert.Equal(p.CTSize, ct.Length);
        Assert.Equal(p.SSSize, ss1.Length);

        byte[] ss2 = HqcKem.Decaps(sk, ct, p);
        Assert.Equal(ss1, ss2);
    }

    [Theory]
    [InlineData("HQC-128")]
    [InlineData("HQC-192")]
    [InlineData("HQC-256")]
    public void KEMMultipleRoundtrips(string paramName)
    {
        var p = GetParams(paramName);
        const int trials = 10;

        for (int i = 0; i < trials; i++)
        {
            var (pk, sk) = HqcKem.KeyGen(p);
            var (ct, ss1) = HqcKem.Encaps(pk, p);
            byte[] ss2 = HqcKem.Decaps(sk, ct, p);
            Assert.Equal(ss1, ss2);
        }
    }

    [Theory]
    [InlineData("HQC-128")]
    [InlineData("HQC-192")]
    [InlineData("HQC-256")]
    public void CorruptedCiphertextRejection(string paramName)
    {
        var p = GetParams(paramName);

        var (pk, sk) = HqcKem.KeyGen(p);
        var (ct, ss1) = HqcKem.Encaps(pk, p);

        // Corrupt the ciphertext
        ct[0] ^= 0xFF;
        ct[1] ^= 0xFF;

        byte[] ss2 = HqcKem.Decaps(sk, ct, p);

        // Shared secrets must differ with corrupted ciphertext
        Assert.NotEqual(ss1, ss2);
    }

    private static HqcParams GetParams(string name) => name switch
    {
        "HQC-128" => HqcParams.HQC128,
        "HQC-192" => HqcParams.HQC192,
        "HQC-256" => HqcParams.HQC256,
        _ => throw new ArgumentException($"Unknown param: {name}")
    };
}
