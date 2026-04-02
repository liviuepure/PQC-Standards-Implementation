// Params.swift — FN-DSA parameter sets (FIPS 206 / FALCON)

public let Q: Int32 = 12289

public struct Params {
    public let name: String
    public let n: Int
    public let logN: Int
    public let padded: Bool
    public let pkSize: Int
    public let skSize: Int
    public let sigSize: Int
    /// Maximum variable-length signature size (before padding).
    /// For non-padded variants this equals sigSize; for padded variants it is
    /// the non-padded maximum.
    public let sigMaxLen: Int
    public let betaSq: Int64
    public let fgBits: Int
}

public let fnDsa512 = Params(
    name: "FN-DSA-512", n: 512, logN: 9, padded: false,
    pkSize: 897, skSize: 1281, sigSize: 666, sigMaxLen: 666,
    betaSq: 34034726, fgBits: 6)

public let fnDsa1024 = Params(
    name: "FN-DSA-1024", n: 1024, logN: 10, padded: false,
    pkSize: 1793, skSize: 2305, sigSize: 1280, sigMaxLen: 1280,
    betaSq: 70265242, fgBits: 5)

public let fnDsaPadded512 = Params(
    name: "FN-DSA-PADDED-512", n: 512, logN: 9, padded: true,
    pkSize: 897, skSize: 1281, sigSize: 809, sigMaxLen: 666,
    betaSq: 34034726, fgBits: 6)

public let fnDsaPadded1024 = Params(
    name: "FN-DSA-PADDED-1024", n: 1024, logN: 10, padded: true,
    pkSize: 1793, skSize: 2305, sigSize: 1473, sigMaxLen: 1280,
    betaSq: 70265242, fgBits: 5)
