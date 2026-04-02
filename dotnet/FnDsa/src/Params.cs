namespace FnDsa;

public sealed record Params(
    string Name, int N, int LogN, bool Padded,
    int PkSize, int SkSize, int SigSize, int SigMaxLen, long BetaSq, int FgBits)
{
    public static readonly Params FnDsa512 = new("FN-DSA-512", 512, 9, false, 897, 1281, 666, 666, 34034726L, 6);
    public static readonly Params FnDsa1024 = new("FN-DSA-1024", 1024, 10, false, 1793, 2305, 1280, 1280, 70265242L, 5);
    public static readonly Params FnDsaPadded512 = new("FN-DSA-PADDED-512", 512, 9, true, 897, 1281, 809, 666, 34034726L, 6);
    public static readonly Params FnDsaPadded1024 = new("FN-DSA-PADDED-1024", 1024, 10, true, 1793, 2305, 1473, 1280, 70265242L, 5);
}
