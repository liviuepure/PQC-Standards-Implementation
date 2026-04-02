using System;
using System.IO;
using System.Text.Json;
using FnDsa;
using Xunit;

public class FnDsaTests
{
    [Theory]
    [MemberData(nameof(AllParams))]
    public void ParamSizes(Params p)
    {
        Assert.True(p.PkSize > 0);
        Assert.True(p.SkSize > 0);
        Assert.True(p.SigSize > 0);
        Assert.True(p.BetaSq > 0);
    }

    [Theory]
    [MemberData(nameof(AllParams))]
    public void Roundtrip(Params p)
    {
        var (pk, sk) = FnDsaApi.KeyGen(p);
        Assert.Equal(p.PkSize, pk.Length);
        Assert.Equal(p.SkSize, sk.Length);

        byte[] msg = System.Text.Encoding.UTF8.GetBytes("test message FN-DSA");
        byte[] sig = FnDsaApi.Sign(sk, msg, p);

        if (p.Padded) Assert.Equal(p.SigSize, sig.Length);
        else Assert.True(sig.Length <= p.SigSize);

        Assert.True(FnDsaApi.Verify(pk, msg, sig, p));
        Assert.False(FnDsaApi.Verify(pk, System.Text.Encoding.UTF8.GetBytes("wrong"), sig, p));

        byte[] tampered = (byte[])sig.Clone();
        tampered[Math.Min(42, tampered.Length - 1)] ^= 0x01;
        Assert.False(FnDsaApi.Verify(pk, msg, tampered, p));
    }

    [Fact]
    public void InteropVectors()
    {
        bool anyRan = false;
        foreach (var (name, p) in new[] { ("FN-DSA-512", Params.FnDsa512), ("FN-DSA-1024", Params.FnDsa1024) })
        {
            var path = Path.Combine("..", "..", "..", "..", "..", "..", "test-vectors", "fn-dsa", $"{name}.json");
            Assert.True(File.Exists(path), $"Missing vector file: {name}");
            var doc = JsonDocument.Parse(File.ReadAllText(path));
            foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
            {
                var pk = Convert.FromHexString(v.GetProperty("pk").GetString()!);
                var msg = Convert.FromHexString(v.GetProperty("msg").GetString()!);
                var sig = Convert.FromHexString(v.GetProperty("sig").GetString()!);
                Assert.True(FnDsaApi.Verify(pk, msg, sig, p));
            }
            anyRan = true;
        }
        Assert.True(anyRan, "No FN-DSA test vector files found");
    }

    public static TheoryData<Params> AllParams() => new()
    {
        Params.FnDsa512, Params.FnDsa1024,
        Params.FnDsaPadded512, Params.FnDsaPadded1024
    };
}
