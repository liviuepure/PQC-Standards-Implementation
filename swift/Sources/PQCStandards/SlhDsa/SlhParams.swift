// SLH-DSA Parameter Sets (FIPS 205)

public struct SlhDsaParams {
    public let name: String
    public let n: Int          // Security parameter (hash output bytes)
    public let h: Int          // Total tree height
    public let d: Int          // Number of layers (hypertree)
    public let hPrime: Int     // Height of each XMSS tree (h/d)
    public let a: Int          // FORS tree height (log2 of leaves per tree)
    public let k: Int          // Number of FORS trees
    public let w: Int          // Winternitz parameter
    public let lgW: Int        // log2(w)
    public let isSHAKE: Bool   // true = SHAKE, false = SHA2

    // WOTS+ parameters
    public var len1: Int { (8 * n + lgW - 1) / lgW }
    public var len2: Int {
        var x = len1 * (w - 1)
        var bits = 0
        while x > 0 { x >>= 1; bits += 1 }
        return (bits + lgW - 1) / lgW
    }
    public var len: Int { len1 + len2 }

    // Sizes
    public var sigBytes: Int {
        // SLH-DSA sig = R (n bytes) + FORS sig + HT sig
        let forsSig = k * (a + 1) * n
        let htSig = d * (len + hPrime) * n
        return n + forsSig + htSig
    }
    public var pkBytes: Int { 2 * n }  // PK.seed || PK.root
    public var skBytes: Int { 4 * n }  // SK.seed || SK.prf || PK.seed || PK.root

    // SLH-DSA-SHAKE-128f
    public static let shake128f = SlhDsaParams(
        name: "SLH-DSA-SHAKE-128f",
        n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, w: 16, lgW: 4, isSHAKE: true
    )

    // SLH-DSA-SHAKE-128s
    public static let shake128s = SlhDsaParams(
        name: "SLH-DSA-SHAKE-128s",
        n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, w: 16, lgW: 4, isSHAKE: true
    )

    // SLH-DSA-SHAKE-256f
    public static let shake256f = SlhDsaParams(
        name: "SLH-DSA-SHAKE-256f",
        n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, w: 16, lgW: 4, isSHAKE: true
    )
}
