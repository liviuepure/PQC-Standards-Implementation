// ML-DSA Parameter Sets (FIPS 204)

public struct MlDsaParams {
    public let name: String
    public let k: Int
    public let l: Int
    public let eta: Int
    public let tau: Int
    public let beta: Int32
    public let gamma1: Int32
    public let gamma2: Int32
    public let omega: Int
    public let lambda: Int  // collision strength in bits
    public let n: Int = 256
    public let q: Int32 = 8380417
    public let d: Int = 13

    public var pkBytes: Int { 32 + 320 * k }
    public var skBytes: Int { 32 + 32 + 64 + 32 * ((l + k) * bitlen(2 * eta) + k * d) / 8 }
    public var sigBytes: Int { lambda / 4 + l * 32 * (1 + bitlen(Int(gamma1) - 1)) + omega + k }

    private func bitlen(_ v: Int) -> Int {
        if v == 0 { return 0 }
        var x = v
        var bits = 0
        while x > 0 { x >>= 1; bits += 1 }
        return bits
    }

    public static let mlDsa44 = MlDsaParams(
        name: "ML-DSA-44", k: 4, l: 4, eta: 2, tau: 39,
        beta: 78, gamma1: 1 << 17, gamma2: (8380417 - 1) / 88,
        omega: 80, lambda: 128
    )

    public static let mlDsa65 = MlDsaParams(
        name: "ML-DSA-65", k: 6, l: 5, eta: 4, tau: 49,
        beta: 196, gamma1: 1 << 19, gamma2: (8380417 - 1) / 32,
        omega: 55, lambda: 192
    )

    public static let mlDsa87 = MlDsaParams(
        name: "ML-DSA-87", k: 8, l: 7, eta: 2, tau: 60,
        beta: 120, gamma1: 1 << 19, gamma2: (8380417 - 1) / 32,
        omega: 75, lambda: 256
    )
}
