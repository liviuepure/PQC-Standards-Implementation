using System.Numerics;
using System.Security.Cryptography;

namespace FnDsa;

// Gaussian sampler for FN-DSA (FIPS 206 §3.12).
// Ported from Go reference implementation.
internal static class Gaussian
{
    private const double Sigma0 = 1.8205;

    // RCDT table: 18 entries of 72-bit values (hi:uint8, lo:uint64).
    private static readonly (byte hi, ulong lo)[] RcdtTable = new (byte, ulong)[]
    {
        (199, 16610441552002023424UL),
        (103, 7624082642567692288UL),
        (42,  919243735747002368UL),
        (13,  3484267233246674944UL),
        (3,   2772878652510347264UL),
        (0,   10479598105528201216UL),
        (0,   1418221736465465344UL),
        (0,   143439473028577328UL),
        (0,   10810581864167812UL),
        (0,   605874652027744UL),
        (0,   25212870589170UL),
        (0,   778215157694UL),
        (0,   17802250993UL),
        (0,   301647562UL),
        (0,   3784361UL),
        (0,   35141UL),
        (0,   241UL),
        (0,   1UL),
    };

    // Branchless unsigned 64-bit less-than: returns 1 if a < b, else 0.
    private static ulong Lt64(ulong a, ulong b) =>
        ((~a & b) | (~(a ^ b) & (a - b))) >> 63;

    // Branchless equality check for bytes: returns 1 if a == b, else 0.
    private static ulong Eq8(byte a, byte b)
    {
        ulong x = (ulong)a ^ (ulong)b;
        return (x - 1) >> 63;
    }

    // Sample from D_{Z, sigma0} using the RCDT table.
    private static int SampleBaseGaussian()
    {
        Span<byte> buf = stackalloc byte[10]; // 9 bytes for sample + 1 for sign
        RandomNumberGenerator.Fill(buf);

        // Interpret buf[0..7] as little-endian uint64, buf[8] as hi byte.
        ulong sampleLo = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(buf[0..8]);
        byte sampleHi = buf[8];

        int z = 0;
        for (int i = 0; i < RcdtTable.Length; i++)
        {
            byte tHi = RcdtTable[i].hi;
            ulong tLo = RcdtTable[i].lo;

            ulong hiLT = Lt64((ulong)sampleHi, (ulong)tHi);
            ulong hiEQ = Eq8(sampleHi, tHi);
            ulong loLT = Lt64(sampleLo, tLo);
            ulong lt72 = hiLT | (hiEQ & loLT);
            z += (int)lt72;
        }

        // Sign bit from buf[9].
        int signBit = buf[9] & 1;
        int mask = -signBit;
        return (z ^ mask) - mask;
    }

    // Sample from D_{Z, sigma} centered at 0.
    internal static int SampleGaussian(double sigma)
    {
        double sigma2 = sigma * sigma;
        double sigma02 = Sigma0 * Sigma0;
        double c = (sigma2 - sigma02) / (2 * sigma2 * sigma02);

        byte[] ubuf = new byte[8];
        while (true)
        {
            int z = SampleBaseGaussian();

            double fz = z;
            double logProb = -fz * fz * c;

            // Sample u in [0,1) using 53 random bits.
            RandomNumberGenerator.Fill(ubuf);
            ulong u53 = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(ubuf) >> 11;
            double u = (double)u53 / (double)(1UL << 53);

            if (u < Math.Exp(logProb))
                return z;
        }
    }
}
