// TLS 1.3 Signature Algorithms for PQC

public struct TlsSignatureAlgorithm {
    public let name: String
    public let value: UInt16
    public let description: String
}

public enum TlsSigAlgorithms {
    // Classical
    public static let ed25519 = TlsSignatureAlgorithm(
        name: "ed25519", value: 0x0807,
        description: "Ed25519"
    )

    public static let ecdsaSecp256r1Sha256 = TlsSignatureAlgorithm(
        name: "ecdsa_secp256r1_sha256", value: 0x0403,
        description: "ECDSA-P256-SHA256"
    )

    // PQC
    public static let mlDsa44 = TlsSignatureAlgorithm(
        name: "mldsa44", value: 0x0901,
        description: "ML-DSA-44"
    )

    public static let mlDsa65 = TlsSignatureAlgorithm(
        name: "mldsa65", value: 0x0902,
        description: "ML-DSA-65"
    )

    public static let mlDsa87 = TlsSignatureAlgorithm(
        name: "mldsa87", value: 0x0903,
        description: "ML-DSA-87"
    )

    // Composite
    public static let mlDsa65Ed25519 = TlsSignatureAlgorithm(
        name: "mldsa65_ed25519", value: 0x0904,
        description: "ML-DSA-65 + Ed25519 Composite"
    )

    public static let mlDsa87Ed448 = TlsSignatureAlgorithm(
        name: "mldsa87_ed448", value: 0x0905,
        description: "ML-DSA-87 + Ed448 Composite"
    )

    public static let allAlgorithms: [TlsSignatureAlgorithm] = [
        ed25519, ecdsaSecp256r1Sha256,
        mlDsa44, mlDsa65, mlDsa87,
        mlDsa65Ed25519, mlDsa87Ed448,
    ]

    public static func byValue(_ value: UInt16) -> TlsSignatureAlgorithm? {
        return allAlgorithms.first { $0.value == value }
    }
}
