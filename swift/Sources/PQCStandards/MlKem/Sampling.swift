// ML-KEM Sampling

public enum KemSampling {
    /// Sample NTT polynomial from XOF stream (rejection sampling)
    public static func sampleNtt(rho: [UInt8], i: UInt8, j: UInt8) -> [Int32] {
        var xof = KemHash.xof(rho, i: i, j: j)
        var coeffs = [Int32]()
        coeffs.reserveCapacity(256)

        while coeffs.count < 256 {
            let bytes = xof.squeeze(count: 3)
            let d1 = Int32(bytes[0]) | (Int32(bytes[1] & 0x0F) << 8)
            let d2 = Int32(bytes[1] >> 4) | (Int32(bytes[2]) << 4)
            if d1 < KemField.q { coeffs.append(d1) }
            if coeffs.count < 256 && d2 < KemField.q { coeffs.append(d2) }
        }
        return Array(coeffs.prefix(256))
    }

    /// Sample CBD (centered binomial distribution) with parameter eta
    /// Input: 64*eta bytes. Output: 256 coefficients in [-eta, eta] mod q.
    public static func sampleCbd(bytes: [UInt8], eta: Int) -> [Int32] {
        var coeffs = [Int32](repeating: 0, count: 256)
        // Generic CBD: for each coefficient, sum eta bits - sum eta bits
        // Total bits needed = 256 * 2 * eta, total bytes = 64 * eta
        var bitIdx = 0
        func getBit() -> Int32 {
            let bytePos = bitIdx / 8
            let bitPos = bitIdx % 8
            bitIdx += 1
            return Int32((bytes[bytePos] >> bitPos) & 1)
        }
        for i in 0..<256 {
            var a: Int32 = 0
            for _ in 0..<eta { a += getBit() }
            var b: Int32 = 0
            for _ in 0..<eta { b += getBit() }
            coeffs[i] = KemField.reduce(a - b)
        }
        return coeffs
    }

    /// Sample a polynomial vector from PRF
    public static func samplePolyVec(sigma: [UInt8], k: Int, eta: Int, offset: UInt8) -> [[Int32]] {
        var vec = [[Int32]]()
        for i in 0..<k {
            let prfBytes = KemHash.prf(sigma, b: offset + UInt8(i), eta: eta)
            vec.append(sampleCbd(bytes: prfBytes, eta: eta))
        }
        return vec
    }
}
