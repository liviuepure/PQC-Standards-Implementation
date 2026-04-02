// FnDsa.swift — Public API for FN-DSA (FIPS 206 / FALCON).

import Foundation

public struct FnDsa {
    /// Generate a key pair for the given parameter set.
    /// Returns (publicKey, secretKey) or nil on failure.
    public static func keyGen(_ p: Params) -> (pk: [UInt8], sk: [UInt8])? {
        guard let (f, g, F, _) = ntruKeyGen(p) else { return nil }
        let h = ntruPublicKey(f, g, p)
        let pk = encodePK(h, p)
        let sk = encodeSK(f, g, F, p)
        return (pk, sk)
    }

    /// Sign a message using the secret key.
    /// Returns the signature bytes, or nil on failure.
    public static func sign(sk: [UInt8], msg: [UInt8], params: Params) -> [UInt8]? {
        return signInternal(sk, msg, params)
    }

    /// Verify a signature on a message with the given public key.
    public static func verify(pk: [UInt8], msg: [UInt8], sig: [UInt8], params: Params) -> Bool {
        return verifyInternal(pk, msg, sig, params)
    }
}
