namespace FnDsa.Hqc;

/// <summary>
/// Tensor product code: concatenated RS (outer) x RM (inner) code.
/// Encoding: message m (k bytes) -> RS encode to n1 bytes -> each byte RM-encoded to n2 bits.
/// Decoding: received n1*n2 bits -> split into n1 blocks of n2 bits -> RM-decode each -> RS-decode.
/// </summary>
internal static class TensorCode
{
    /// <summary>Encodes a k-byte message into an n1*n2-bit codeword.</summary>
    public static ulong[] Encode(byte[] msg, HqcParams p)
    {
        // Step 1: RS encode the message
        byte[] rsCodeword = ReedSolomon.Encode(msg, p);

        // Step 2: RM encode each RS symbol
        var result = new ulong[p.VecN1N2Size64];
        for (int i = 0; i < p.N1; i++)
            ReedMuller.EncodeInto(result, rsCodeword[i], i * p.N2, p.Multiplicity);

        return result;
    }

    /// <summary>Decodes a received n1*n2-bit word back to a k-byte message.</summary>
    public static (byte[]? msg, bool ok) Decode(ulong[] received, HqcParams p)
    {
        // Step 1: RM-decode each block of n2 bits to get one byte
        var rsReceived = new byte[p.N1];
        for (int i = 0; i < p.N1; i++)
        {
            ulong[] block = ExtractBits(received, i * p.N2, p.N2);
            rsReceived[i] = ReedMuller.Decode(block, p.N2, p.Multiplicity);
        }

        // Step 2: RS-decode
        return ReedSolomon.Decode(rsReceived, p);
    }

    /// <summary>Extracts nBits bits from src starting at bitOffset.</summary>
    private static ulong[] ExtractBits(ulong[] src, int bitOffset, int nBits)
    {
        int nWords = (nBits + 63) / 64;
        var result = new ulong[nWords];

        int srcWord = bitOffset / 64;
        int srcBit = bitOffset % 64;

        if (srcBit == 0)
        {
            for (int i = 0; i < nWords && srcWord + i < src.Length; i++)
                result[i] = src[srcWord + i];
        }
        else
        {
            for (int i = 0; i < nWords; i++)
            {
                int idx = srcWord + i;
                if (idx < src.Length)
                    result[i] = src[idx] >> srcBit;
                if (idx + 1 < src.Length)
                    result[i] |= src[idx + 1] << (64 - srcBit);
            }
        }

        int rem = nBits % 64;
        if (rem != 0 && nWords > 0)
            result[nWords - 1] &= (1UL << rem) - 1;

        return result;
    }
}
