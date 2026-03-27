// ML-KEM Parameter Sets

public struct MlKemParams {
    public let name: String
    public let k: Int
    public let eta1: Int
    public let eta2: Int
    public let du: Int
    public let dv: Int
    public let n: Int = 256
    public let q: Int32 = 3329

    // Derived sizes
    public var secretKeyBytes: Int { 384 * k }
    public var publicKeyBytes: Int { 384 * k + 32 }
    public var ciphertextBytes: Int { du * k * 32 + dv * 32 }
    public var sharedSecretBytes: Int { 32 }
    public var encapsKeyBytes: Int { publicKeyBytes }
    public var decapsKeyBytes: Int { 768 * k + 96 }

    public static let mlKem512 = MlKemParams(name: "ML-KEM-512", k: 2, eta1: 3, eta2: 2, du: 10, dv: 4)
    public static let mlKem768 = MlKemParams(name: "ML-KEM-768", k: 3, eta1: 2, eta2: 2, du: 10, dv: 4)
    public static let mlKem1024 = MlKemParams(name: "ML-KEM-1024", k: 4, eta1: 2, eta2: 2, du: 11, dv: 5)
}
