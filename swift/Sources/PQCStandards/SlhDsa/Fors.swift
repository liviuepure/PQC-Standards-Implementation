// SLH-DSA FORS (Forest of Random Subsets)

public enum Fors {
    /// FORS tree leaf
    public static func forsLeaf(params: SlhDsaParams, skSeed: [UInt8], pkSeed: [UInt8],
                                adrs: inout SlhAddress, idx: UInt32) -> [UInt8] {
        let kpAddr = adrs.getKeyPairAddress()
        adrs.setType(SlhAddress.forsKeyPrf)
        adrs.setKeyPairAddress(kpAddr)
        adrs.setTreeIndex(idx)
        let sk = SlhHash.prf(params: params, pkSeed: pkSeed, skSeed: skSeed, adrs: adrs)
        adrs.setType(SlhAddress.forsTree)
        adrs.setKeyPairAddress(kpAddr)
        adrs.setTreeHeight(0)
        adrs.setTreeIndex(idx)
        return SlhHash.f(params: params, pkSeed: pkSeed, adrs: adrs, m: sk)
    }

    /// FORS tree node
    public static func forsNode(params: SlhDsaParams, skSeed: [UInt8], pkSeed: [UInt8],
                                adrs: inout SlhAddress, idx: UInt32, height: Int) -> [UInt8] {
        if height == 0 {
            return forsLeaf(params: params, skSeed: skSeed, pkSeed: pkSeed, adrs: &adrs, idx: idx)
        }
        let left = forsNode(params: params, skSeed: skSeed, pkSeed: pkSeed,
                           adrs: &adrs, idx: 2 * idx, height: height - 1)
        let right = forsNode(params: params, skSeed: skSeed, pkSeed: pkSeed,
                            adrs: &adrs, idx: 2 * idx + 1, height: height - 1)
        let kpAddr = adrs.getKeyPairAddress()
        adrs.setType(SlhAddress.forsTree)
        adrs.setKeyPairAddress(kpAddr)
        adrs.setTreeHeight(UInt32(height))
        adrs.setTreeIndex(idx)
        return SlhHash.h(params: params, pkSeed: pkSeed, adrs: adrs, m1: left, m2: right)
    }

    /// FORS Sign
    public static func sign(params: SlhDsaParams, md: [UInt8], skSeed: [UInt8],
                           pkSeed: [UInt8], adrs: inout SlhAddress) -> [UInt8] {
        let indices = SlhHash.messageToIndices(md: md, k: params.k, a: params.a)
        let kpAddr = adrs.getKeyPairAddress()
        var sig = [UInt8]()

        for i in 0..<params.k {
            let idx = indices[i]
            let treeOffset = UInt32(i) * (1 << params.a)

            // Secret key value
            adrs.setType(SlhAddress.forsKeyPrf)
            adrs.setKeyPairAddress(kpAddr)
            adrs.setTreeIndex(treeOffset + idx)
            let sk = SlhHash.prf(params: params, pkSeed: pkSeed, skSeed: skSeed, adrs: adrs)
            sig.append(contentsOf: sk)

            // Auth path: at each level j, include the sibling subtree root
            for j in 0..<params.a {
                // The absolute index of the leaf's ancestor at height j
                let ancestorIdx = (treeOffset + idx) >> j
                // The sibling has absolute index: ancestor ^ 1
                let siblingIdx = ancestorIdx ^ 1
                let sibNode = forsNode(params: params, skSeed: skSeed, pkSeed: pkSeed,
                                      adrs: &adrs, idx: siblingIdx, height: j)
                sig.append(contentsOf: sibNode)
            }
        }
        return sig
    }

    /// FORS pk from sig
    public static func pkFromSig(params: SlhDsaParams, sig: [UInt8], md: [UInt8],
                                 pkSeed: [UInt8], adrs: inout SlhAddress) -> [UInt8] {
        let n = params.n
        let indices = SlhHash.messageToIndices(md: md, k: params.k, a: params.a)
        let kpAddr = adrs.getKeyPairAddress()
        var roots = [UInt8]()

        var sigOff = 0
        for i in 0..<params.k {
            let idx = indices[i]
            let sk = Array(sig[sigOff..<(sigOff + n)])
            sigOff += n

            // Compute leaf from sk
            adrs.setType(SlhAddress.forsTree)
            adrs.setKeyPairAddress(kpAddr)
            adrs.setTreeHeight(0)
            let treeIdx = UInt32(i) * (1 << params.a) + idx
            adrs.setTreeIndex(treeIdx)
            var node = SlhHash.f(params: params, pkSeed: pkSeed, adrs: adrs, m: sk)

            // Walk up the tree
            for j in 0..<params.a {
                let authNode = Array(sig[sigOff..<(sigOff + n)])
                sigOff += n

                adrs.setTreeHeight(UInt32(j + 1))
                let parentIdx = treeIdx >> (j + 1)
                adrs.setTreeIndex(parentIdx)

                if ((treeIdx >> j) & 1) == 0 {
                    node = SlhHash.h(params: params, pkSeed: pkSeed, adrs: adrs,
                                    m1: node, m2: authNode)
                } else {
                    node = SlhHash.h(params: params, pkSeed: pkSeed, adrs: adrs,
                                    m1: authNode, m2: node)
                }
            }
            roots.append(contentsOf: node)
        }

        adrs.setType(SlhAddress.forsRoots)
        adrs.setKeyPairAddress(kpAddr)
        adrs.setTreeHeight(0)
        adrs.setTreeIndex(0)
        return SlhHash.tl(params: params, pkSeed: pkSeed, adrs: adrs, m: roots)
    }
}
