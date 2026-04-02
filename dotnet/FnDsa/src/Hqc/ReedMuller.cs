namespace FnDsa.Hqc;

/// <summary>
/// Reed-Muller code RM(1, 7) for HQC.
/// Encodes 8 bits (1 byte) into 128 bits using Walsh-Hadamard basis,
/// then duplicates for additional error correction (multiplicity copies).
/// </summary>
internal static class ReedMuller
{
    private const int BaseLen = 128;

    /// <summary>Encodes a single byte into a 128-bit RM(1,7) codeword [lo, hi].</summary>
    public static (ulong lo, ulong hi) EncodeBase(byte msg)
    {
        ulong lo = 0, hi = 0;

        ulong Expand(int bit) => unchecked((ulong)(-(long)((msg >> bit) & 1)));

        // Bit 0: constant row (all-ones if set)
        lo ^= Expand(0);
        hi ^= Expand(0);

        // Bit 1: pattern 0xAAAAAAAAAAAAAAAA
        lo ^= Expand(1) & 0xAAAAAAAAAAAAAAAA;
        hi ^= Expand(1) & 0xAAAAAAAAAAAAAAAA;

        // Bit 2: pattern 0xCCCCCCCCCCCCCCCC
        lo ^= Expand(2) & 0xCCCCCCCCCCCCCCCC;
        hi ^= Expand(2) & 0xCCCCCCCCCCCCCCCC;

        // Bit 3: pattern 0xF0F0F0F0F0F0F0F0
        lo ^= Expand(3) & 0xF0F0F0F0F0F0F0F0;
        hi ^= Expand(3) & 0xF0F0F0F0F0F0F0F0;

        // Bit 4: pattern 0xFF00FF00FF00FF00
        lo ^= Expand(4) & 0xFF00FF00FF00FF00;
        hi ^= Expand(4) & 0xFF00FF00FF00FF00;

        // Bit 5: pattern 0xFFFF0000FFFF0000
        lo ^= Expand(5) & 0xFFFF0000FFFF0000;
        hi ^= Expand(5) & 0xFFFF0000FFFF0000;

        // Bit 6: pattern 0xFFFFFFFF00000000
        lo ^= Expand(6) & 0xFFFFFFFF00000000;
        hi ^= Expand(6) & 0xFFFFFFFF00000000;

        // Bit 7: (0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
        hi ^= Expand(7);

        return (lo, hi);
    }

    /// <summary>
    /// Decodes an n2-bit received codeword (with duplicated RM(1,7))
    /// to a single byte using Walsh-Hadamard transform.
    /// </summary>
    public static byte Decode(ulong[] src, int n2, int multiplicity)
    {
        // Step 1: Accumulate all copies into signed sum array of 128 entries
        var sums = new int[BaseLen];

        int bitPos = 0;
        for (int rep = 0; rep < multiplicity; rep++)
        {
            for (int i = 0; i < BaseLen; i++)
            {
                int wordIdx = bitPos / 64;
                int bitIdx = bitPos % 64;
                int bit = 0;
                if (wordIdx < src.Length)
                    bit = (int)((src[wordIdx] >> bitIdx) & 1);
                // Convert 0/1 to +1/-1 (0 -> +1, 1 -> -1)
                sums[i] += 1 - 2 * bit;
                bitPos++;
            }
        }

        // Step 2: Fast Walsh-Hadamard Transform (in-place, 7 passes)
        for (int pass = 0; pass < 7; pass++)
        {
            int step = 1 << pass;
            for (int i = 0; i < BaseLen; i += 2 * step)
            {
                for (int j = i; j < i + step; j++)
                {
                    int a = sums[j];
                    int b = sums[j + step];
                    sums[j] = a + b;
                    sums[j + step] = a - b;
                }
            }
        }

        // Step 3: Find position with maximum absolute value
        int maxAbs = 0;
        int maxPos = 0;
        int sign = 1;

        for (int i = 0; i < BaseLen; i++)
        {
            int v = sums[i];
            int abs = v < 0 ? -v : v;
            if (abs > maxAbs)
            {
                maxAbs = abs;
                maxPos = i;
                sign = v > 0 ? 1 : -1;
            }
        }

        // Step 4: Recover the message byte
        byte msg = (byte)(maxPos << 1);
        if (sign < 0)
            msg |= 1;
        return msg;
    }

    /// <summary>Encodes a byte into the dst vector starting at bitOffset.</summary>
    public static void EncodeInto(ulong[] dst, byte msg, int bitOffset, int multiplicity)
    {
        var (baseLo, baseHi) = EncodeBase(msg);

        int bitPos = bitOffset;
        for (int rep = 0; rep < multiplicity; rep++)
        {
            for (int w = 0; w < 2; w++)
            {
                ulong word = w == 0 ? baseLo : baseHi;
                int dstWord = bitPos / 64;
                int dstBit = bitPos % 64;

                if (dstBit == 0 && dstWord < dst.Length)
                {
                    dst[dstWord] ^= word;
                    bitPos += 64;
                }
                else
                {
                    for (int bit = 0; bit < 64; bit++)
                    {
                        if ((word & (1UL << bit)) != 0)
                        {
                            int idx = bitPos / 64;
                            int off = bitPos % 64;
                            if (idx < dst.Length)
                                dst[idx] ^= 1UL << off;
                        }
                        bitPos++;
                    }
                }
            }
        }
    }
}
