// SLH-DSA WOTS+ One-Time Signature

public enum WotsPlus {
    /// Chain function: iterate F hash `steps` times
    public static func chain(params: SlhDsaParams, x: [UInt8], start: Int, steps: Int,
                             pkSeed: [UInt8], adrs: inout SlhAddress) -> [UInt8] {
        var result = x
        for i in start..<(start + steps) {
            adrs.setHashAddress(UInt32(i))
            result = SlhHash.f(params: params, pkSeed: pkSeed, adrs: adrs, m: result)
        }
        return result
    }

    /// Generate WOTS+ public key
    public static func pkGen(params: SlhDsaParams, skSeed: [UInt8], pkSeed: [UInt8],
                             adrs: inout SlhAddress) -> [UInt8] {
        var wotsPkAdrs = adrs.copy()
        var tmp = [UInt8]()

        for i in 0..<params.len {
            adrs.setChainAddress(UInt32(i))
            adrs.setHashAddress(0)
            adrs.setType(SlhAddress.wotsKeyPrf)
            adrs.setKeyPairAddress(wotsPkAdrs.data[20..<24].withUnsafeBufferPointer { buf in
                let p = buf.baseAddress!
                return UInt32(p[0]) << 24 | UInt32(p[1]) << 16 | UInt32(p[2]) << 8 | UInt32(p[3])
            })
            let sk = SlhHash.prf(params: params, pkSeed: pkSeed, skSeed: skSeed, adrs: adrs)

            adrs.setType(SlhAddress.wotsHash)
            adrs.setChainAddress(UInt32(i))
            let node = chain(params: params, x: sk, start: 0, steps: params.w - 1,
                            pkSeed: pkSeed, adrs: &adrs)
            tmp.append(contentsOf: node)
        }

        wotsPkAdrs.setType(SlhAddress.wotsPk)
        return SlhHash.tl(params: params, pkSeed: pkSeed, adrs: wotsPkAdrs, m: tmp)
    }

    /// WOTS+ Sign
    public static func sign(params: SlhDsaParams, msg: [UInt8], skSeed: [UInt8],
                           pkSeed: [UInt8], adrs: inout SlhAddress) -> [UInt8] {
        // Convert message to base-w
        let baseW = toBaseW(msg: msg, w: params.w, outLen: params.len1)
        let csum = checksum(baseW: baseW, w: params.w, len2: params.len2, lgW: params.lgW)
        let allW = baseW + csum

        var sig = [UInt8]()
        let kpAddr = getKeyPairAddress(adrs)

        for i in 0..<params.len {
            adrs.setType(SlhAddress.wotsKeyPrf)
            adrs.setKeyPairAddress(kpAddr)
            adrs.setChainAddress(UInt32(i))
            adrs.setHashAddress(0)
            let sk = SlhHash.prf(params: params, pkSeed: pkSeed, skSeed: skSeed, adrs: adrs)

            adrs.setType(SlhAddress.wotsHash)
            adrs.setChainAddress(UInt32(i))
            let node = chain(params: params, x: sk, start: 0, steps: allW[i],
                            pkSeed: pkSeed, adrs: &adrs)
            sig.append(contentsOf: node)
        }
        return sig
    }

    /// WOTS+ pk from sig
    public static func pkFromSig(params: SlhDsaParams, sig: [UInt8], msg: [UInt8],
                                 pkSeed: [UInt8], adrs: inout SlhAddress) -> [UInt8] {
        let baseW = toBaseW(msg: msg, w: params.w, outLen: params.len1)
        let csum = checksum(baseW: baseW, w: params.w, len2: params.len2, lgW: params.lgW)
        let allW = baseW + csum

        var wotsPkAdrs = adrs.copy()
        var tmp = [UInt8]()

        for i in 0..<params.len {
            adrs.setType(SlhAddress.wotsHash)
            adrs.setChainAddress(UInt32(i))
            let sigBlock = Array(sig[(i * params.n)..<((i + 1) * params.n)])
            let node = chain(params: params, x: sigBlock, start: allW[i],
                            steps: params.w - 1 - allW[i], pkSeed: pkSeed, adrs: &adrs)
            tmp.append(contentsOf: node)
        }

        wotsPkAdrs.setType(SlhAddress.wotsPk)
        return SlhHash.tl(params: params, pkSeed: pkSeed, adrs: wotsPkAdrs, m: tmp)
    }

    // Helper: extract keypair address
    static func getKeyPairAddress(_ adrs: SlhAddress) -> UInt32 {
        return UInt32(adrs.data[20]) << 24 | UInt32(adrs.data[21]) << 16 |
               UInt32(adrs.data[22]) << 8 | UInt32(adrs.data[23])
    }

    /// Convert message to base-w representation
    public static func toBaseW(msg: [UInt8], w: Int, outLen: Int) -> [Int] {
        var result = [Int]()
        let lgW = w == 16 ? 4 : (w == 256 ? 8 : 4)
        var bits = 0
        var total = 0
        var idx = 0
        for _ in 0..<outLen {
            if bits == 0 {
                total = idx < msg.count ? Int(msg[idx]) : 0
                idx += 1
                bits = 8
            }
            bits -= lgW
            result.append((total >> bits) & (w - 1))
        }
        return result
    }

    /// Compute WOTS+ checksum
    public static func checksum(baseW: [Int], w: Int, len2: Int, lgW: Int) -> [Int] {
        var csum = 0
        for v in baseW {
            csum += (w - 1) - v
        }
        csum <<= ((8 - ((baseW.count * lgW) % 8)) % 8)
        let totalBits = len2 * lgW
        let totalBytes = (totalBits + 7) / 8
        var csumBytes = [UInt8]()
        var c = csum
        for _ in 0..<totalBytes {
            csumBytes.insert(UInt8(c & 0xFF), at: 0)
            c >>= 8
        }
        return toBaseW(msg: csumBytes, w: w, outLen: len2)
    }
}
