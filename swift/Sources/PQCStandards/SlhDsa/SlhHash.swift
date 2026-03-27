// SLH-DSA Hash Functions (SHAKE-based)

import Foundation

public enum SlhHash {
    /// PRF: SHAKE-256(PK.seed || ADRS || SK.seed, n)
    public static func prf(params: SlhDsaParams, pkSeed: [UInt8], skSeed: [UInt8], adrs: SlhAddress) -> [UInt8] {
        return KemHash.shake256(pkSeed + adrs.data + skSeed, outputLen: params.n)
    }

    /// PRFmsg: SHAKE-256(SK.prf || optrand || msg, n)
    public static func prfMsg(params: SlhDsaParams, skPrf: [UInt8], optRand: [UInt8], msg: [UInt8]) -> [UInt8] {
        return KemHash.shake256(skPrf + optRand + msg, outputLen: params.n)
    }

    /// F: SHAKE-256(PK.seed || ADRS || M, n)
    public static func f(params: SlhDsaParams, pkSeed: [UInt8], adrs: SlhAddress, m: [UInt8]) -> [UInt8] {
        return KemHash.shake256(pkSeed + adrs.data + m, outputLen: params.n)
    }

    /// H: SHAKE-256(PK.seed || ADRS || M1 || M2, n)
    public static func h(params: SlhDsaParams, pkSeed: [UInt8], adrs: SlhAddress, m1: [UInt8], m2: [UInt8]) -> [UInt8] {
        return KemHash.shake256(pkSeed + adrs.data + m1 + m2, outputLen: params.n)
    }

    /// T_l: SHAKE-256(PK.seed || ADRS || M, n)
    public static func tl(params: SlhDsaParams, pkSeed: [UInt8], adrs: SlhAddress, m: [UInt8]) -> [UInt8] {
        return KemHash.shake256(pkSeed + adrs.data + m, outputLen: params.n)
    }

    /// Hmsg: SHAKE-256(R || PK.seed || PK.root || msg, 8*ceil(k*a/8))
    public static func hMsg(params: SlhDsaParams, r: [UInt8], pkSeed: [UInt8], pkRoot: [UInt8], msg: [UInt8]) -> [UInt8] {
        let outputLen = (params.k * params.a + 7) / 8 + ((params.h - params.h / params.d + 7) / 8) + (((params.h / params.d) + 7) / 8)
        // Actually: ceil((k * log2(2^a)) / 8) + ... We need k*a bits for FORS + h-h/d bits for tree + h/d bits for leaf
        let totalBits = params.k * params.a + params.h - params.h / params.d + params.h / params.d
        let totalBytes = (totalBits + 7) / 8
        return KemHash.shake256(r + pkSeed + pkRoot + msg, outputLen: totalBytes)
    }

    /// Split message digest into md, idx_tree, idx_leaf
    public static func splitDigest(params: SlhDsaParams, digest: [UInt8]) -> (md: [UInt8], idxTree: UInt64, idxLeaf: UInt32) {
        let mdBytes = (params.k * params.a + 7) / 8
        let treeBits = params.h - params.h / params.d
        let treeBytes = (treeBits + 7) / 8
        let leafBits = params.h / params.d
        let leafBytes = (leafBits + 7) / 8

        let md = Array(digest[0..<mdBytes])

        var idxTree: UInt64 = 0
        for i in 0..<treeBytes {
            idxTree = (idxTree << 8) | UInt64(digest[mdBytes + i])
        }
        idxTree &= (1 << treeBits) - 1

        var idxLeaf: UInt32 = 0
        for i in 0..<leafBytes {
            idxLeaf = (idxLeaf << 8) | UInt32(digest[mdBytes + treeBytes + i])
        }
        idxLeaf &= UInt32((1 << leafBits) - 1)

        return (md, idxTree, idxLeaf)
    }

    /// Convert message digest to FORS indices
    public static func messageToIndices(md: [UInt8], k: Int, a: Int) -> [UInt32] {
        var indices = [UInt32]()
        var bits = [UInt8]()
        for byte in md {
            for b in stride(from: 7, through: 0, by: -1) {
                bits.append((byte >> b) & 1)
            }
        }
        for i in 0..<k {
            var idx: UInt32 = 0
            for j in 0..<a {
                let bitIdx = i * a + j
                if bitIdx < bits.count {
                    idx = (idx << 1) | UInt32(bits[bitIdx])
                } else {
                    idx = idx << 1
                }
            }
            indices.append(idx)
        }
        return indices
    }
}
