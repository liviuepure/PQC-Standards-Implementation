namespace FnDsa.Hqc;

/// <summary>
/// GF(2^8) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
/// Generator alpha = 2 (primitive element).
/// </summary>
internal static class GF256
{
    private const int GFPolyVal = 0x11D;
    private const int GFGen = 2;
    private const int GFMulOrder = 255;

    private static readonly byte[] Exp = new byte[512];
    private static readonly byte[] Log = new byte[256];

    static GF256()
    {
        InitTables();
    }

    private static void InitTables()
    {
        ushort x = 1;
        for (int i = 0; i < 255; i++)
        {
            Exp[i] = (byte)x;
            Exp[i + 255] = (byte)x; // wrap-around
            Log[x] = (byte)i;
            x <<= 1;
            if (x >= 256) x ^= GFPolyVal;
        }
        Log[0] = 0;
        Exp[510] = Exp[0];
    }

    /// <summary>Addition in GF(2^8) = XOR.</summary>
    public static byte Add(byte a, byte b) => (byte)(a ^ b);

    /// <summary>Multiplication in GF(2^8) via log/exp tables.</summary>
    public static byte Mul(byte a, byte b)
    {
        if (a == 0 || b == 0) return 0;
        return Exp[Log[a] + Log[b]];
    }

    /// <summary>Multiplicative inverse in GF(2^8). Returns 0 if a == 0.</summary>
    public static byte Inv(byte a)
    {
        if (a == 0) return 0;
        return Exp[255 - Log[a]];
    }

    /// <summary>Exponentiation: a^n in GF(2^8).</summary>
    public static byte Pow(byte a, int n)
    {
        if (a == 0) return n == 0 ? (byte)1 : (byte)0;
        int logA = Log[a];
        int logResult = (logA * n) % 255;
        if (logResult < 0) logResult += 255;
        return Exp[logResult];
    }

    /// <summary>Division: a / b in GF(2^8). Throws if b == 0.</summary>
    public static byte Div(byte a, byte b)
    {
        if (b == 0) throw new DivideByZeroException("GF256 division by zero");
        if (a == 0) return 0;
        int logDiff = Log[a] - Log[b];
        if (logDiff < 0) logDiff += 255;
        return Exp[logDiff];
    }
}
