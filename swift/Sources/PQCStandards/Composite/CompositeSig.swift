// Composite Signature: Ed25519 + ML-DSA

import Foundation
import CryptoKit

public struct CompositeKeyPair {
    public let classicalPublicKey: [UInt8]
    public let classicalSecretKey: [UInt8]
    public let pqPublicKey: [UInt8]
    public let pqSecretKey: [UInt8]
}

public struct CompositeSignature {
    public let classicalSig: [UInt8]
    public let pqSig: [UInt8]
}

public enum CompositeSig {
    /// Generate composite key pair (Ed25519 + ML-DSA-65)
    public static func keyGen(params: MlDsaParams = .mlDsa65) -> CompositeKeyPair {
        let ed25519Private = Curve25519.Signing.PrivateKey()
        let ed25519Public = ed25519Private.publicKey

        let mlDsaKp = MlDsa.keyGen(params: params)

        return CompositeKeyPair(
            classicalPublicKey: Array(ed25519Public.rawRepresentation),
            classicalSecretKey: Array(ed25519Private.rawRepresentation),
            pqPublicKey: mlDsaKp.publicKey,
            pqSecretKey: mlDsaKp.secretKey
        )
    }

    /// Sign with composite signature
    public static func sign(params: MlDsaParams = .mlDsa65,
                           classicalSecretKey: [UInt8],
                           pqSecretKey: [UInt8],
                           message: [UInt8]) -> CompositeSignature? {
        // Ed25519 sign
        let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: classicalSecretKey)
        let ed25519Sig = try! privateKey.signature(for: Data(message))

        // ML-DSA sign
        guard let mlDsaSig = MlDsa.sign(params: params, sk: pqSecretKey, message: message) else {
            return nil
        }

        return CompositeSignature(
            classicalSig: Array(ed25519Sig),
            pqSig: mlDsaSig
        )
    }

    /// Verify composite signature (both must pass)
    public static func verify(params: MlDsaParams = .mlDsa65,
                             classicalPublicKey: [UInt8],
                             pqPublicKey: [UInt8],
                             message: [UInt8],
                             signature: CompositeSignature) -> Bool {
        // Ed25519 verify
        let publicKey = try! Curve25519.Signing.PublicKey(rawRepresentation: classicalPublicKey)
        let ed25519Valid = publicKey.isValidSignature(Data(signature.classicalSig), for: Data(message))

        if !ed25519Valid { return false }

        // ML-DSA verify
        return MlDsa.verify(params: params, pk: pqPublicKey, message: message, signature: signature.pqSig)
    }
}
