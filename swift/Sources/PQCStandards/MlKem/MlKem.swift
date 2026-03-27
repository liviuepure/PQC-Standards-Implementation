// ML-KEM (FIPS 203) - Full KEM

import Foundation
import CryptoKit

public struct MlKemKeyPair {
    public let encapsulationKey: [UInt8]
    public let decapsulationKey: [UInt8]
}

public struct MlKemEncapsResult {
    public let ciphertext: [UInt8]
    public let sharedSecret: [UInt8]
}

public enum MlKem {
    /// Generate a key pair
    public static func keyGen(params: MlKemParams) -> MlKemKeyPair {
        var rng = SystemRandomNumberGenerator()
        var d = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { d[i] = UInt8.random(in: 0...255, using: &rng) }
        var z = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { z[i] = UInt8.random(in: 0...255, using: &rng) }
        return keyGenInternal(params: params, d: d, z: z)
    }

    /// Deterministic keygen for testing
    public static func keyGenInternal(params: MlKemParams, d: [UInt8], z: [UInt8]) -> MlKemKeyPair {
        let (ek, dk) = Kpke.keyGen(params: params, d: d)
        // dk_full = dk || ek || H(ek) || z
        let hEk = KemHash.h(ek)
        let dkFull = dk + ek + hEk + z
        return MlKemKeyPair(encapsulationKey: ek, decapsulationKey: dkFull)
    }

    /// Encapsulate
    public static func encapsulate(params: MlKemParams, ek: [UInt8]) -> MlKemEncapsResult {
        var rng = SystemRandomNumberGenerator()
        var m = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { m[i] = UInt8.random(in: 0...255, using: &rng) }
        return encapsulateInternal(params: params, ek: ek, m: m)
    }

    /// Deterministic encapsulate for testing
    public static func encapsulateInternal(params: MlKemParams, ek: [UInt8], m: [UInt8]) -> MlKemEncapsResult {
        let hEk = KemHash.h(ek)
        let (kBar, r) = KemHash.g(m + hEk)
        let ct = Kpke.encrypt(params: params, ek: ek, m: m, r: r)
        let k = KemHash.sha3_256(kBar + KemHash.h(ct))
        return MlKemEncapsResult(ciphertext: ct, sharedSecret: k)
    }

    /// Decapsulate
    public static func decapsulate(params: MlKemParams, dk: [UInt8], ct: [UInt8]) -> [UInt8] {
        let k = params.k
        let dkPke = Array(dk[0..<(384 * k)])
        let ek = Array(dk[(384 * k)..<(384 * k + params.publicKeyBytes)])
        let hEk = Array(dk[(384 * k + params.publicKeyBytes)..<(384 * k + params.publicKeyBytes + 32)])
        let z = Array(dk[(384 * k + params.publicKeyBytes + 32)...])

        let mPrime = Kpke.decrypt(params: params, dk: dkPke, ct: ct)
        let (kBar, r) = KemHash.g(mPrime + hEk)
        let ctPrime = Kpke.encrypt(params: params, ek: ek, m: mPrime, r: r)

        // Implicit rejection
        let kReject = KemHash.sha3_256(z + KemHash.h(ct))

        if ct.count == ctPrime.count && ct == ctPrime {
            return KemHash.sha3_256(kBar + KemHash.h(ct))
        } else {
            return kReject
        }
    }
}
