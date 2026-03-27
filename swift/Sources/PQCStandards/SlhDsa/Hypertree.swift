// SLH-DSA Hypertree

public enum Hypertree {
    /// Hypertree Sign
    public static func sign(params: SlhDsaParams, msg: [UInt8], skSeed: [UInt8],
                           pkSeed: [UInt8], idxTree: UInt64, idxLeaf: UInt32) -> [UInt8] {
        var adrs = SlhAddress()

        // Sign at layer 0
        adrs.setLayerAddress(0)
        adrs.setTreeAddressBytes(idxTree)
        var sig = Xmss.sign(params: params, msg: msg, skSeed: skSeed,
                           pkSeed: pkSeed, idx: idxLeaf, adrs: &adrs)

        var root = Xmss.rootFromSig(params: params, sig: sig, msg: msg,
                                     pkSeed: pkSeed, idx: idxLeaf, adrs: &adrs)

        // Sign at higher layers
        var tree = idxTree
        var leaf = UInt32(tree & UInt64((1 << params.hPrime) - 1))

        for j in 1..<params.d {
            tree >>= params.hPrime
            leaf = UInt32(tree & UInt64((1 << params.hPrime) - 1))

            adrs.setLayerAddress(UInt32(j))
            adrs.setTreeAddressBytes(tree >> params.hPrime)

            let layerSig = Xmss.sign(params: params, msg: root, skSeed: skSeed,
                                     pkSeed: pkSeed, idx: leaf, adrs: &adrs)
            sig.append(contentsOf: layerSig)

            if j < params.d - 1 {
                root = Xmss.rootFromSig(params: params, sig: layerSig, msg: root,
                                         pkSeed: pkSeed, idx: leaf, adrs: &adrs)
            }
        }
        return sig
    }

    /// Hypertree Verify
    public static func verify(params: SlhDsaParams, msg: [UInt8], sig: [UInt8],
                             pkSeed: [UInt8], pkRoot: [UInt8],
                             idxTree: UInt64, idxLeaf: UInt32) -> Bool {
        var adrs = SlhAddress()
        let sigBlockSize = (params.len + params.hPrime) * params.n

        // Verify at layer 0
        adrs.setLayerAddress(0)
        adrs.setTreeAddressBytes(idxTree)
        let sig0 = Array(sig[0..<sigBlockSize])
        var node = Xmss.rootFromSig(params: params, sig: sig0, msg: msg,
                                     pkSeed: pkSeed, idx: idxLeaf, adrs: &adrs)

        var tree = idxTree
        var sigOff = sigBlockSize

        for j in 1..<params.d {
            tree >>= params.hPrime
            let leaf = UInt32(tree & UInt64((1 << params.hPrime) - 1))

            adrs.setLayerAddress(UInt32(j))
            adrs.setTreeAddressBytes(tree >> params.hPrime)

            let layerSig = Array(sig[sigOff..<(sigOff + sigBlockSize)])
            sigOff += sigBlockSize

            node = Xmss.rootFromSig(params: params, sig: layerSig, msg: node,
                                     pkSeed: pkSeed, idx: leaf, adrs: &adrs)
        }

        return node == pkRoot
    }
}
