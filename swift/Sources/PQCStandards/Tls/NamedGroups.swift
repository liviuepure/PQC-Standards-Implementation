// TLS 1.3 Named Groups for PQC

public struct TlsNamedGroup {
    public let name: String
    public let value: UInt16
    public let keyShareSize: Int
    public let description: String
}

public enum TlsNamedGroups {
    // Classical groups
    public static let x25519 = TlsNamedGroup(
        name: "x25519", value: 0x001D, keyShareSize: 32,
        description: "X25519 ECDH"
    )

    public static let secp256r1 = TlsNamedGroup(
        name: "secp256r1", value: 0x0017, keyShareSize: 65,
        description: "NIST P-256 ECDH"
    )

    // PQC groups
    public static let mlKem512 = TlsNamedGroup(
        name: "mlkem512", value: 0x0200, keyShareSize: 800,
        description: "ML-KEM-512"
    )

    public static let mlKem768 = TlsNamedGroup(
        name: "mlkem768", value: 0x0201, keyShareSize: 1184,
        description: "ML-KEM-768"
    )

    public static let mlKem1024 = TlsNamedGroup(
        name: "mlkem1024", value: 0x0202, keyShareSize: 1568,
        description: "ML-KEM-1024"
    )

    // Hybrid groups
    public static let x25519MlKem768 = TlsNamedGroup(
        name: "X25519MLKEM768", value: 0x4588, keyShareSize: 1216,
        description: "X25519 + ML-KEM-768 Hybrid"
    )

    public static let secp256r1MlKem768 = TlsNamedGroup(
        name: "SecP256r1MLKEM768", value: 0x4589, keyShareSize: 1249,
        description: "P-256 + ML-KEM-768 Hybrid"
    )

    public static let allGroups: [TlsNamedGroup] = [
        x25519, secp256r1, mlKem512, mlKem768, mlKem1024,
        x25519MlKem768, secp256r1MlKem768,
    ]

    public static func byValue(_ value: UInt16) -> TlsNamedGroup? {
        return allGroups.first { $0.value == value }
    }
}
