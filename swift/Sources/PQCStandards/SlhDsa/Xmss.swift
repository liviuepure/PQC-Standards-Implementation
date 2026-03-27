// SLH-DSA XMSS

public enum Xmss {
    /// Compute XMSS public key (Merkle tree root)
    public static func node(params: SlhDsaParams, skSeed: [UInt8], pkSeed: [UInt8],
                           idx: UInt32, height: Int, adrs: inout SlhAddress) -> [UInt8] {
        if height == 0 {
            // Leaf node: WOTS+ public key
            adrs.setType(SlhAddress.wotsHash)
            adrs.setKeyPairAddress(idx)
            return WotsPlus.pkGen(params: params, skSeed: skSeed, pkSeed: pkSeed, adrs: &adrs)
        }

        let left = node(params: params, skSeed: skSeed, pkSeed: pkSeed,
                        idx: 2 * idx, height: height - 1, adrs: &adrs)
        let right = node(params: params, skSeed: skSeed, pkSeed: pkSeed,
                         idx: 2 * idx + 1, height: height - 1, adrs: &adrs)

        adrs.setType(SlhAddress.tree)
        adrs.setTreeHeight(UInt32(height))
        adrs.setTreeIndex(idx)
        return SlhHash.h(params: params, pkSeed: pkSeed, adrs: adrs, m1: left, m2: right)
    }

    /// XMSS Sign
    public static func sign(params: SlhDsaParams, msg: [UInt8], skSeed: [UInt8],
                           pkSeed: [UInt8], idx: UInt32, adrs: inout SlhAddress) -> [UInt8] {
        // WOTS+ signature
        adrs.setType(SlhAddress.wotsHash)
        adrs.setKeyPairAddress(idx)
        var sig = WotsPlus.sign(params: params, msg: msg, skSeed: skSeed,
                                pkSeed: pkSeed, adrs: &adrs)

        // Authentication path
        for j in 0..<params.hPrime {
            let s = (idx >> j) ^ 1
            let authNode = node(params: params, skSeed: skSeed, pkSeed: pkSeed,
                               idx: s, height: j, adrs: &adrs)
            sig.append(contentsOf: authNode)
        }
        return sig
    }

    /// XMSS Compute root from signature
    public static func rootFromSig(params: SlhDsaParams, sig: [UInt8], msg: [UInt8],
                                   pkSeed: [UInt8], idx: UInt32, adrs: inout SlhAddress) -> [UInt8] {
        let n = params.n
        let wotsSig = Array(sig[0..<(params.len * n)])
        let authPath = Array(sig[(params.len * n)...])

        // Compute WOTS+ pk from signature
        adrs.setType(SlhAddress.wotsHash)
        adrs.setKeyPairAddress(idx)
        var node = WotsPlus.pkFromSig(params: params, sig: wotsSig, msg: msg,
                                       pkSeed: pkSeed, adrs: &adrs)

        adrs.setType(SlhAddress.tree)
        for j in 0..<params.hPrime {
            adrs.setTreeHeight(UInt32(j + 1))
            let authNode = Array(authPath[(j * n)..<((j + 1) * n)])
            let treeIdx = idx >> (j + 1)
            adrs.setTreeIndex(treeIdx)

            if ((idx >> j) & 1) == 0 {
                node = SlhHash.h(params: params, pkSeed: pkSeed, adrs: adrs,
                                m1: node, m2: authNode)
            } else {
                node = SlhHash.h(params: params, pkSeed: pkSeed, adrs: adrs,
                                m1: authNode, m2: node)
            }
        }
        return node
    }
}
