// ML-DSA Number Theoretic Transform (8 layers, n=256, q=8380417)

public enum DsaNtt {
    // Precomputed zetas: powers of 1753 mod q in bit-reversed order
    public static let zetas: [Int32] = {
        let q: Int64 = 8380417
        let g: Int64 = 1753
        var powers = [Int32](repeating: 0, count: 256)
        powers[0] = 1
        for i in 1..<256 {
            powers[i] = Int32((Int64(powers[i-1]) * g) % q)
        }
        func bitrev8(_ x: Int) -> Int {
            var r = 0; var v = x
            for _ in 0..<8 { r = (r << 1) | (v & 1); v >>= 1 }
            return r
        }
        var result = [Int32](repeating: 0, count: 256)
        for i in 0..<256 {
            result[i] = powers[bitrev8(i)]
        }
        return result
    }()

    /// Forward NTT (8 layers)
    public static func ntt(_ f: inout [Int32]) {
        var k = 1
        var len = 128
        while len >= 1 {
            var start = 0
            while start < 256 {
                let z = zetas[k]
                k += 1
                for j in start..<(start + len) {
                    let t = DsaField.mul(z, f[j + len])
                    f[j + len] = DsaField.sub(f[j], t)
                    f[j] = DsaField.add(f[j], t)
                }
                start += 2 * len
            }
            len /= 2
        }
    }

    /// Inverse NTT (8 layers)
    public static func invNtt(_ f: inout [Int32]) {
        var k = 255
        var len = 1
        while len <= 128 {
            var start = 0
            while start < 256 {
                let z = zetas[k]
                k -= 1
                for j in start..<(start + len) {
                    let t = f[j]
                    f[j] = DsaField.add(t, f[j + len])
                    f[j + len] = DsaField.mul(z, DsaField.sub(f[j + len], t))
                }
                start += 2 * len
            }
            len *= 2
        }
        // Multiply by n^{-1} mod q
        // 256^{-1} mod 8380417 = 8347681
        let nInv: Int32 = 8347681
        for i in 0..<256 {
            f[i] = DsaField.mul(f[i], nInv)
        }
    }

    /// Pointwise multiply (NTT domain)
    public static func pointwiseMul(_ a: [Int32], _ b: [Int32]) -> [Int32] {
        var r = [Int32](repeating: 0, count: 256)
        for i in 0..<256 {
            r[i] = DsaField.mul(a[i], b[i])
        }
        return r
    }

    /// Add two polynomials
    public static func polyAdd(_ a: [Int32], _ b: [Int32]) -> [Int32] {
        var r = [Int32](repeating: 0, count: 256)
        for i in 0..<256 {
            r[i] = DsaField.add(a[i], b[i])
        }
        return r
    }

    /// Subtract two polynomials
    public static func polySub(_ a: [Int32], _ b: [Int32]) -> [Int32] {
        var r = [Int32](repeating: 0, count: 256)
        for i in 0..<256 {
            r[i] = DsaField.sub(a[i], b[i])
        }
        return r
    }
}
