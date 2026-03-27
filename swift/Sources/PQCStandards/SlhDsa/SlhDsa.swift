// SLH-DSA (FIPS 205) - Stateless Hash-Based Digital Signature

import Foundation

public struct SlhDsaKeyPair {
    public let publicKey: [UInt8]
    public let secretKey: [UInt8]
}

public enum SlhDsa {
    /// Key Generation
    public static func keyGen(params: SlhDsaParams) -> SlhDsaKeyPair {
        var rng = SystemRandomNumberGenerator()
        var skSeed = [UInt8](repeating: 0, count: params.n)
        var skPrf = [UInt8](repeating: 0, count: params.n)
        var pkSeed = [UInt8](repeating: 0, count: params.n)
        for i in 0..<params.n {
            skSeed[i] = UInt8.random(in: 0...255, using: &rng)
            skPrf[i] = UInt8.random(in: 0...255, using: &rng)
            pkSeed[i] = UInt8.random(in: 0...255, using: &rng)
        }
        return keyGenInternal(params: params, skSeed: skSeed, skPrf: skPrf, pkSeed: pkSeed)
    }

    /// Deterministic keygen
    public static func keyGenInternal(params: SlhDsaParams, skSeed: [UInt8],
                                       skPrf: [UInt8], pkSeed: [UInt8]) -> SlhDsaKeyPair {
        var adrs = SlhAddress()
        adrs.setLayerAddress(UInt32(params.d - 1))
        let root = Xmss.node(params: params, skSeed: skSeed, pkSeed: pkSeed,
                            idx: 0, height: params.hPrime, adrs: &adrs)

        let pk = pkSeed + root
        let sk = skSeed + skPrf + pkSeed + root
        return SlhDsaKeyPair(publicKey: pk, secretKey: sk)
    }

    /// Sign
    public static func sign(params: SlhDsaParams, sk: [UInt8], message: [UInt8]) -> [UInt8] {
        let n = params.n
        let skSeed = Array(sk[0..<n])
        let skPrf = Array(sk[n..<(2*n)])
        let pkSeed = Array(sk[(2*n)..<(3*n)])
        let pkRoot = Array(sk[(3*n)..<(4*n)])

        // Generate randomizer
        var rng = SystemRandomNumberGenerator()
        var optRand = [UInt8](repeating: 0, count: n)
        for i in 0..<n { optRand[i] = UInt8.random(in: 0...255, using: &rng) }

        return signInternal(params: params, skSeed: skSeed, skPrf: skPrf,
                           pkSeed: pkSeed, pkRoot: pkRoot, message: message, optRand: optRand)
    }

    /// Deterministic sign
    public static func signInternal(params: SlhDsaParams, skSeed: [UInt8], skPrf: [UInt8],
                                     pkSeed: [UInt8], pkRoot: [UInt8],
                                     message: [UInt8], optRand: [UInt8]) -> [UInt8] {
        let n = params.n

        // R = PRFmsg(SK.prf, optrand, msg)
        let r = SlhHash.prfMsg(params: params, skPrf: skPrf, optRand: optRand, msg: message)

        // Digest
        let digest = SlhHash.hMsg(params: params, r: r, pkSeed: pkSeed, pkRoot: pkRoot, msg: message)
        let (md, idxTree, idxLeaf) = SlhHash.splitDigest(params: params, digest: digest)

        // FORS sign
        var adrs = SlhAddress()
        adrs.setLayerAddress(0)
        adrs.setTreeAddressBytes(idxTree)
        adrs.setType(SlhAddress.forsTree)
        adrs.setKeyPairAddress(idxLeaf)

        let forsSig = Fors.sign(params: params, md: md, skSeed: skSeed,
                               pkSeed: pkSeed, adrs: &adrs)
        let forsPk = Fors.pkFromSig(params: params, sig: forsSig, md: md,
                                    pkSeed: pkSeed, adrs: &adrs)

        // Hypertree sign
        let htSig = Hypertree.sign(params: params, msg: forsPk, skSeed: skSeed,
                                   pkSeed: pkSeed, idxTree: idxTree, idxLeaf: idxLeaf)

        return r + forsSig + htSig
    }

    /// Verify
    public static func verify(params: SlhDsaParams, pk: [UInt8], message: [UInt8],
                             signature: [UInt8]) -> Bool {
        let n = params.n
        let pkSeed = Array(pk[0..<n])
        let pkRoot = Array(pk[n..<(2*n)])

        let r = Array(signature[0..<n])
        let forsSigSize = params.k * (params.a + 1) * n
        let forsSig = Array(signature[n..<(n + forsSigSize)])
        let htSig = Array(signature[(n + forsSigSize)...])

        // Digest
        let digest = SlhHash.hMsg(params: params, r: r, pkSeed: pkSeed, pkRoot: pkRoot, msg: message)
        let (md, idxTree, idxLeaf) = SlhHash.splitDigest(params: params, digest: digest)

        // FORS verify
        var adrs = SlhAddress()
        adrs.setLayerAddress(0)
        adrs.setTreeAddressBytes(idxTree)
        adrs.setType(SlhAddress.forsTree)
        adrs.setKeyPairAddress(idxLeaf)

        let forsPk = Fors.pkFromSig(params: params, sig: forsSig, md: md,
                                    pkSeed: pkSeed, adrs: &adrs)

        // Hypertree verify
        return Hypertree.verify(params: params, msg: forsPk, sig: htSig,
                               pkSeed: pkSeed, pkRoot: pkRoot,
                               idxTree: idxTree, idxLeaf: idxLeaf)
    }
}
