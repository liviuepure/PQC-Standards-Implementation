using System.Buffers.Binary;
using System.Numerics;

namespace FnDsa.Hqc;

/// <summary>
/// GF(2) polynomial arithmetic: polynomials over GF(2) packed into ulong[] words.
/// Arithmetic is in GF(2)[x]/(x^n - 1).
/// </summary>
internal static class GF2
{
    /// <summary>Polynomial addition: out = a XOR b.</summary>
    public static ulong[] VectAdd(ulong[] a, ulong[] b)
    {
        int n = a.Length;
        var result = new ulong[n];
        for (int i = 0; i < n; i++)
            result[i] = a[i] ^ b[i];
        return result;
    }

    /// <summary>In-place addition: a ^= b.</summary>
    public static void VectAddInPlace(ulong[] a, ulong[] b)
    {
        for (int i = 0; i < b.Length; i++)
            a[i] ^= b[i];
    }

    /// <summary>Sets bit at position pos in the vector v.</summary>
    public static void VectSetBit(ulong[] v, int pos)
    {
        v[pos / 64] |= 1UL << (pos % 64);
    }

    /// <summary>Returns the bit at position pos in the vector v.</summary>
    public static ulong VectGetBit(ulong[] v, int pos)
    {
        return (v[pos / 64] >> (pos % 64)) & 1;
    }

    /// <summary>Returns the Hamming weight of a GF(2) vector.</summary>
    public static int VectWeight(ulong[] v)
    {
        int w = 0;
        for (int i = 0; i < v.Length; i++)
            w += BitOperations.PopCount(v[i]);
        return w;
    }

    /// <summary>Converts a ulong vector to bytes (little-endian).</summary>
    public static byte[] VectToBytes(ulong[] v, int nBytes)
    {
        var result = new byte[nBytes];
        Span<byte> tmpBuf = stackalloc byte[8];
        for (int i = 0; i < v.Length && i * 8 < nBytes; i++)
        {
            int remaining = nBytes - i * 8;
            if (remaining >= 8)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(i * 8), v[i]);
            }
            else
            {
                BinaryPrimitives.WriteUInt64LittleEndian(tmpBuf, v[i]);
                tmpBuf[..remaining].CopyTo(result.AsSpan(i * 8));
            }
        }
        return result;
    }

    /// <summary>Converts bytes to a ulong vector (little-endian).</summary>
    public static ulong[] VectFromBytes(ReadOnlySpan<byte> data, int nWords)
    {
        var v = new ulong[nWords];
        Span<byte> tmpBuf = stackalloc byte[8];
        for (int i = 0; i < nWords; i++)
        {
            int start = i * 8;
            if (start >= data.Length) break;
            int end = start + 8;
            if (end > data.Length)
            {
                tmpBuf.Clear();
                data[start..].CopyTo(tmpBuf);
                v[i] = BinaryPrimitives.ReadUInt64LittleEndian(tmpBuf);
            }
            else
            {
                v[i] = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(start, 8));
            }
        }
        return v;
    }

    /// <summary>Returns a copy of v truncated/masked to exactly nBits bits.</summary>
    public static ulong[] VectResize(ulong[] v, int nBits)
    {
        int nWords = (nBits + 63) / 64;
        var result = new ulong[nWords];
        int copyLen = Math.Min(v.Length, nWords);
        Array.Copy(v, result, copyLen);
        int rem = nBits % 64;
        if (rem != 0 && nWords > 0)
            result[nWords - 1] &= (1UL << rem) - 1;
        return result;
    }

    /// <summary>Constant-time equality: returns 1 if a == b, 0 otherwise.</summary>
    public static int VectEqual(ulong[] a, ulong[] b)
    {
        ulong diff = 0;
        int n = Math.Min(a.Length, b.Length);
        for (int i = 0; i < n; i++)
            diff |= a[i] ^ b[i];
        for (int i = n; i < a.Length; i++)
            diff |= a[i];
        for (int i = n; i < b.Length; i++)
            diff |= b[i];
        ulong d = diff | (diff >> 32);
        d |= d >> 16;
        d |= d >> 8;
        d |= d >> 4;
        d |= d >> 2;
        d |= d >> 1;
        return 1 - (int)(d & 1);
    }

    /// <summary>
    /// Carryless multiplication of two 64-bit words.
    /// Returns (lo, hi) such that a * b = hi&lt;&lt;64 | lo in GF(2).
    /// </summary>
    private static (ulong lo, ulong hi) BaseMul(ulong a, ulong b)
    {
        ulong lo = 0, hi = 0;
        for (int i = 0; i < 64; i++)
        {
            if (((a >> i) & 1) == 0) continue;
            if (i == 0)
            {
                lo ^= b;
            }
            else
            {
                lo ^= b << i;
                hi ^= b >> (64 - i);
            }
        }
        return (lo, hi);
    }

    /// <summary>Schoolbook polynomial multiplication of two GF(2) polynomials.</summary>
    private static ulong[] SchoolbookMul(ulong[] a, int sizeA, ulong[] b, int sizeB)
    {
        var result = new ulong[sizeA + sizeB];
        for (int i = 0; i < sizeA; i++)
        {
            if (a[i] == 0) continue;
            for (int j = 0; j < sizeB; j++)
            {
                if (b[j] == 0) continue;
                var (lo, hi) = BaseMul(a[i], b[j]);
                result[i + j] ^= lo;
                result[i + j + 1] ^= hi;
            }
        }
        return result;
    }

    /// <summary>Computes a * b mod (x^n - 1) in GF(2)[x].</summary>
    public static ulong[] VectMul(ulong[] a, ulong[] b, int n)
    {
        int nWords = (n + 63) / 64;

        var aPad = new ulong[nWords];
        var bPad = new ulong[nWords];
        Array.Copy(a, aPad, Math.Min(a.Length, nWords));
        Array.Copy(b, bPad, Math.Min(b.Length, nWords));

        int rem = n % 64;
        if (rem != 0)
        {
            aPad[nWords - 1] &= (1UL << rem) - 1;
            bPad[nWords - 1] &= (1UL << rem) - 1;
        }

        ulong[] prod = SchoolbookMul(aPad, nWords, bPad, nWords);

        var result = new ulong[nWords];
        Array.Copy(prod, result, nWords);

        int wordOff = n / 64;

        if (rem == 0)
        {
            for (int i = 0; i < nWords; i++)
            {
                if (wordOff + i < 2 * nWords)
                    result[i] ^= prod[wordOff + i];
            }
        }
        else
        {
            for (int i = 0; i < nWords; i++)
            {
                int idx = wordOff + i;
                if (idx < 2 * nWords)
                    result[i] ^= prod[idx] >> rem;
                if (idx + 1 < 2 * nWords)
                    result[i] ^= prod[idx + 1] << (64 - rem);
            }
        }

        if (rem != 0)
            result[nWords - 1] &= (1UL << rem) - 1;

        return result;
    }
}
