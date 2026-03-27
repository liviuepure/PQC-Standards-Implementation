// TLS 1.3 Cipher Suites

public struct TlsCipherSuite {
    public let name: String
    public let value: UInt16
    public let description: String
}

public enum TlsCipherSuites {
    public static let aes128GcmSha256 = TlsCipherSuite(
        name: "TLS_AES_128_GCM_SHA256", value: 0x1301,
        description: "AES-128-GCM with SHA-256"
    )

    public static let aes256GcmSha384 = TlsCipherSuite(
        name: "TLS_AES_256_GCM_SHA384", value: 0x1302,
        description: "AES-256-GCM with SHA-384"
    )

    public static let chacha20Poly1305Sha256 = TlsCipherSuite(
        name: "TLS_CHACHA20_POLY1305_SHA256", value: 0x1303,
        description: "ChaCha20-Poly1305 with SHA-256"
    )

    public static let allSuites: [TlsCipherSuite] = [
        aes128GcmSha256, aes256GcmSha384, chacha20Poly1305Sha256,
    ]

    public static func byValue(_ value: UInt16) -> TlsCipherSuite? {
        return allSuites.first { $0.value == value }
    }
}
