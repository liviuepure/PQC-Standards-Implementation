namespace FnDsa;

// FIPS 206 key and signature encoding/decoding for FN-DSA.
// Ported from Go reference implementation.
internal static class Encode
{
    // ─────────────────────────────────────────────────────────────────────
    // Public-key encoding (14 bits per NTT coefficient, LSB-first)
    // ─────────────────────────────────────────────────────────────────────

    internal static byte[] EncodePk(int[] h, Params p)
    {
        byte[] out_ = new byte[p.PkSize];
        out_[0] = (byte)(0x00 | p.LogN);
        PackBits14(out_.AsSpan(1), h, p.N);
        return out_;
    }

    internal static int[]? DecodePk(byte[] data, Params p)
    {
        if (data.Length != p.PkSize) return null;
        if (data[0] != (byte)(0x00 | p.LogN)) return null;
        return UnpackBits14(data.AsSpan(1), p.N);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Secret-key encoding
    // ─────────────────────────────────────────────────────────────────────

    internal static byte[] EncodeSk(int[] f, int[] g, int[] F, Params p)
    {
        byte[] out_ = new byte[p.SkSize];
        out_[0] = (byte)(0x50 | p.LogN);
        int fgBits = p.FgBits;
        int offset = 1;
        PackSignedBits(out_.AsSpan(offset), f, p.N, fgBits);
        offset += (p.N * fgBits) / 8;
        PackSignedBits(out_.AsSpan(offset), g, p.N, fgBits);
        offset += (p.N * fgBits) / 8;
        PackSignedBits(out_.AsSpan(offset), F, p.N, 8);
        return out_;
    }

    internal static (int[] f, int[] g, int[] F, bool ok) DecodeSk(byte[] data, Params p)
    {
        if (data.Length != p.SkSize) return (null!, null!, null!, false);
        if (data[0] != (byte)(0x50 | p.LogN)) return (null!, null!, null!, false);
        int fgBits = p.FgBits;
        int offset = 1;
        int[] f = UnpackSignedBits(data.AsSpan(offset), p.N, fgBits);
        offset += (p.N * fgBits) / 8;
        int[] g = UnpackSignedBits(data.AsSpan(offset), p.N, fgBits);
        offset += (p.N * fgBits) / 8;
        int[] F = UnpackSignedBits(data.AsSpan(offset), p.N, 8);
        return (f, g, F, true);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Signature encoding (variable-length compressed s1)
    // ─────────────────────────────────────────────────────────────────────

    internal static int LoBitsFor(Params p) => p.N == 1024 ? 7 : 6;

    internal static (byte[]? sig, bool ok) EncodeSig(byte[] salt, int[] s1, Params p)
    {
        int capacity = p.SigMaxLen - 41;
        byte[] compBuf = new byte[capacity];
        var (used, ok) = CompressS1(compBuf, s1, p.N, LoBitsFor(p));
        if (!ok) return (null, false);

        byte[] out_;
        if (p.Padded)
            out_ = new byte[p.SigSize];
        else
            out_ = new byte[1 + 40 + used];

        out_[0] = (byte)(0x30 | p.LogN);
        Array.Copy(salt, 0, out_, 1, 40);
        Array.Copy(compBuf, 0, out_, 41, used);
        return (out_, true);
    }

    internal static (byte[]? salt, int[]? s1, bool ok) DecodeSig(byte[] data, Params p)
    {
        if (data.Length < 41) return (null, null, false);
        if (data[0] != (byte)(0x30 | p.LogN)) return (null, null, false);
        if (p.Padded)
        {
            if (data.Length != p.SigSize) return (null, null, false);
        }
        else
        {
            if (data.Length > p.SigMaxLen) return (null, null, false);
        }

        byte[] salt = new byte[40];
        Array.Copy(data, 1, salt, 0, 40);

        var (s1, ok) = DecompressS1(data.AsSpan(41), p.N, LoBitsFor(p));
        if (!ok) return (null, null, false);
        return (salt, s1, true);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────

    private static void PackBits14(Span<byte> dst, int[] src, int n)
    {
        int cursor = 0;
        for (int i = 0; i < n; i++)
        {
            uint v = (uint)src[i] & 0x3FFF;
            int byteIdx = cursor >> 3;
            int bitIdx = cursor & 7;
            dst[byteIdx] |= (byte)(v << bitIdx);
            if (bitIdx == 0)
            {
                dst[byteIdx + 1] |= (byte)(v >> 8);
            }
            else
            {
                dst[byteIdx + 1] |= (byte)(v >> (8 - bitIdx));
                if (bitIdx > 2)
                    dst[byteIdx + 2] |= (byte)(v >> (16 - bitIdx));
            }
            cursor += 14;
        }
    }

    private static int[] UnpackBits14(ReadOnlySpan<byte> src, int n)
    {
        int[] out_ = new int[n];
        int cursor = 0;
        for (int i = 0; i < n; i++)
        {
            int byteIdx = cursor >> 3;
            int bitIdx = cursor & 7;
            uint v;
            if (bitIdx == 0)
            {
                v = (uint)src[byteIdx] | (uint)src[byteIdx + 1] << 8;
            }
            else
            {
                v = (uint)src[byteIdx] >> bitIdx;
                v |= (uint)src[byteIdx + 1] << (8 - bitIdx);
                if (bitIdx > 2)
                    v |= (uint)src[byteIdx + 2] << (16 - bitIdx);
            }
            out_[i] = (int)(v & 0x3FFF);
            cursor += 14;
        }
        return out_;
    }

    private static void PackSignedBits(Span<byte> dst, int[] src, int n, int bits)
    {
        uint mask = (uint)((1 << bits) - 1);
        int cursor = 0;
        for (int i = 0; i < n; i++)
        {
            uint v = (uint)src[i] & mask;
            int rem = bits;
            int cur = cursor;
            while (rem > 0)
            {
                int byteIdx = cur >> 3;
                int bitIdx = cur & 7;
                int avail = 8 - bitIdx;
                int chunk = rem < avail ? rem : avail;
                dst[byteIdx] |= (byte)((v & (uint)((1 << chunk) - 1)) << bitIdx);
                v >>= chunk;
                cur += chunk;
                rem -= chunk;
            }
            cursor += bits;
        }
    }

    private static int[] UnpackSignedBits(ReadOnlySpan<byte> src, int n, int bits)
    {
        int[] out_ = new int[n];
        uint mask = (uint)((1 << bits) - 1);
        uint signBit = (uint)(1 << (bits - 1));
        int cursor = 0;
        for (int i = 0; i < n; i++)
        {
            uint v = 0;
            int rem = bits;
            int cur = cursor;
            int shift = 0;
            while (rem > 0)
            {
                int byteIdx = cur >> 3;
                int bitIdx = cur & 7;
                int avail = 8 - bitIdx;
                int chunk = rem < avail ? rem : avail;
                uint b = (uint)(src[byteIdx] >> bitIdx) & (uint)((1 << chunk) - 1);
                v |= b << shift;
                shift += chunk;
                cur += chunk;
                rem -= chunk;
            }
            v &= mask;
            if ((v & signBit) != 0)
                v |= ~mask;
            out_[i] = (int)v;
            cursor += bits;
        }
        return out_;
    }

    private static (int used, bool ok) CompressS1(byte[] dst, int[] s1, int n, int lo)
    {
        int loMask = (1 << lo) - 1;
        int cursor = 0;
        int capacity = dst.Length * 8;

        bool WriteBit(byte bit)
        {
            if (cursor >= capacity) return false;
            if (bit != 0) dst[cursor >> 3] |= (byte)(1 << (cursor & 7));
            cursor++;
            return true;
        }

        for (int i = 0; i < n; i++)
        {
            int s = s1[i];
            int v = s < 0 ? -s : s;
            int low = v & loMask;
            int high = v >> lo;

            for (int b = 0; b < lo; b++)
                if (!WriteBit((byte)((low >> b) & 1))) return (0, false);

            for (int h = 0; h < high; h++)
                if (!WriteBit(1)) return (0, false);

            if (!WriteBit(0)) return (0, false);

            byte signBit = (s < 0) ? (byte)1 : (byte)0;
            if (!WriteBit(signBit)) return (0, false);
        }

        return ((cursor + 7) / 8, true);
    }

    private static (int[]? s1, bool ok) DecompressS1(ReadOnlySpan<byte> src, int n, int lo)
    {
        // Convert to array to avoid ref-struct capture limitation.
        byte[] srcArr = src.ToArray();
        int totalBits = srcArr.Length * 8;
        int cursor = 0;

        int[] out_ = new int[n];
        for (int i = 0; i < n; i++)
        {
            int low = 0;
            for (int b = 0; b < lo; b++)
            {
                if (cursor >= totalBits) return (null, false);
                byte bit = (byte)((srcArr[cursor >> 3] >> (cursor & 7)) & 1);
                cursor++;
                low |= (int)bit << b;
            }

            int high = 0;
            while (true)
            {
                if (cursor >= totalBits) return (null, false);
                byte bit = (byte)((srcArr[cursor >> 3] >> (cursor & 7)) & 1);
                cursor++;
                if (bit == 0) break;
                high++;
            }

            if (cursor >= totalBits) return (null, false);
            byte signBit = (byte)((srcArr[cursor >> 3] >> (cursor & 7)) & 1);
            cursor++;

            int vv = (high << lo) | low;
            if (signBit == 1)
            {
                if (vv == 0) return (null, false); // non-canonical zero
                vv = -vv;
            }
            out_[i] = vv;
        }
        return (out_, true);
    }
}
