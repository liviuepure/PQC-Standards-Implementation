// Hybrid KEM: X25519 + ML-KEM

import Foundation
import CryptoKit

public struct HybridKemKeyPair {
    public let classicalPublicKey: [UInt8]
    public let classicalSecretKey: [UInt8]
    public let pqPublicKey: [UInt8]
    public let pqSecretKey: [UInt8]
}

public struct HybridKemEncapsResult {
    public let classicalCiphertext: [UInt8]
    public let pqCiphertext: [UInt8]
    public let sharedSecret: [UInt8]
}

public enum HybridKem {
    /// Generate hybrid key pair (X25519 + ML-KEM-768)
    public static func keyGen(params: MlKemParams = .mlKem768) -> HybridKemKeyPair {
        // X25519
        let x25519Private = Curve25519.KeyAgreement.PrivateKey()
        let x25519Public = x25519Private.publicKey

        // ML-KEM
        let mlKemKp = MlKem.keyGen(params: params)

        return HybridKemKeyPair(
            classicalPublicKey: Array(x25519Public.rawRepresentation),
            classicalSecretKey: Array(x25519Private.rawRepresentation),
            pqPublicKey: mlKemKp.encapsulationKey,
            pqSecretKey: mlKemKp.decapsulationKey
        )
    }

    /// Encapsulate with hybrid KEM
    public static func encapsulate(params: MlKemParams = .mlKem768,
                                    classicalPublicKey: [UInt8],
                                    pqPublicKey: [UInt8]) -> HybridKemEncapsResult {
        // X25519 key exchange
        let ephemeralPrivate = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublic = ephemeralPrivate.publicKey
        let peerPublicKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: classicalPublicKey)
        let x25519Shared = try! ephemeralPrivate.sharedSecretFromKeyAgreement(with: peerPublicKey)

        // ML-KEM encapsulation
        let mlKemResult = MlKem.encapsulate(params: params, ek: pqPublicKey)

        // Combine shared secrets: SHA-256(x25519_ss || mlkem_ss)
        let x25519SharedBytes = x25519Shared.withUnsafeBytes { Array($0) }
        let combinedSecret = KemHash.sha3_256(x25519SharedBytes + mlKemResult.sharedSecret)

        return HybridKemEncapsResult(
            classicalCiphertext: Array(ephemeralPublic.rawRepresentation),
            pqCiphertext: mlKemResult.ciphertext,
            sharedSecret: combinedSecret
        )
    }

    /// Decapsulate with hybrid KEM
    public static func decapsulate(params: MlKemParams = .mlKem768,
                                    classicalSecretKey: [UInt8],
                                    pqSecretKey: [UInt8],
                                    classicalCiphertext: [UInt8],
                                    pqCiphertext: [UInt8]) -> [UInt8] {
        // X25519
        let privateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: classicalSecretKey)
        let ephemeralPublic = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: classicalCiphertext)
        let x25519Shared = try! privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublic)

        // ML-KEM
        let mlKemShared = MlKem.decapsulate(params: params, dk: pqSecretKey, ct: pqCiphertext)

        // Combine
        let x25519SharedBytes = x25519Shared.withUnsafeBytes { Array($0) }
        return KemHash.sha3_256(x25519SharedBytes + mlKemShared)
    }
}
