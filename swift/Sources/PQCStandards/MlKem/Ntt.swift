// ML-KEM Number Theoretic Transform

public enum KemNtt {
    // Precomputed zetas: powers of 17 mod 3329 in bit-reversed order
    // zetas[i] = 17^(brv(i)) mod q, for i in 0..<128, with 7-bit bit-reversal
    public static let zetas: [Int32] = {
        let q: Int32 = 3329
        let g: Int32 = 17
        // First compute all powers of g mod q up to 256
        var powers = [Int32](repeating: 0, count: 256)
        powers[0] = 1
        for i in 1..<256 {
            powers[i] = Int32((Int64(powers[i-1]) * Int64(g)) % Int64(q))
        }
        func bitrev7(_ x: Int) -> Int {
            var r = 0; var v = x
            for _ in 0..<7 { r = (r << 1) | (v & 1); v >>= 1 }
            return r
        }
        var result = [Int32](repeating: 0, count: 128)
        for i in 0..<128 {
            result[i] = powers[bitrev7(i)]
        }
        return result
    }()

    // Gammas for basemul: gamma[i] = 17^(2*brv(i)+1) mod q for i in 0..<128
    // where brv is 7-bit reversal
    public static let gammas: [Int32] = {
        let q: Int32 = 3329
        let g: Int32 = 17
        var powers = [Int32](repeating: 0, count: 512)
        powers[0] = 1
        for i in 1..<512 {
            powers[i] = Int32((Int64(powers[i-1]) * Int64(g)) % Int64(q))
        }
        func bitrev7(_ x: Int) -> Int {
            var r = 0; var v = x
            for _ in 0..<7 { r = (r << 1) | (v & 1); v >>= 1 }
            return r
        }
        var result = [Int32](repeating: 0, count: 128)
        for i in 0..<128 {
            let exp = 2 * bitrev7(i) + 1
            result[i] = powers[exp % 256]
        }
        return result
    }()

    /// Forward NTT: in-place, 7 layers
    public static func ntt(_ f: inout [Int32]) {
        var k = 1
        var len = 128
        while len >= 2 {
            var start = 0
            while start < 256 {
                let z = zetas[k]
                k += 1
                for j in start..<(start + len) {
                    let t = KemField.mul(z, f[j + len])
                    f[j + len] = KemField.sub(f[j], t)
                    f[j] = KemField.add(f[j], t)
                }
                start += 2 * len
            }
            len /= 2
        }
    }

    /// Inverse NTT: in-place, 7 layers
    public static func invNtt(_ f: inout [Int32]) {
        var k = 127
        var len = 2
        while len <= 128 {
            var start = 0
            while start < 256 {
                let z = zetas[k]
                k -= 1
                for j in start..<(start + len) {
                    let t = f[j]
                    f[j] = KemField.add(t, f[j + len])
                    f[j + len] = KemField.mul(z, KemField.sub(f[j + len], t))
                }
                start += 2 * len
            }
            len *= 2
        }
        // Multiply by n^{-1} mod q: 256^{-1} mod 3329 = 3316
        // Since 3329 = 13*256 + 1, so 256 * (-13) = 1 (mod 3329), so 256^{-1} = 3329-13 = 3316
        let nInv: Int32 = 3316
        for i in 0..<256 {
            f[i] = KemField.mul(f[i], nInv)
        }
    }

    /// Basemul: multiply two NTT-domain polynomials pairwise
    public static func basemul(_ a: [Int32], _ b: [Int32]) -> [Int32] {
        var r = [Int32](repeating: 0, count: 256)
        for i in 0..<128 {
            let gamma = gammas[i]
            let a0 = a[2*i], a1 = a[2*i+1]
            let b0 = b[2*i], b1 = b[2*i+1]
            // (a0 + a1*X) * (b0 + b1*X) mod (X^2 - gamma)
            r[2*i]   = KemField.add(KemField.mul(a0, b0), KemField.mul(KemField.mul(a1, b1), gamma))
            r[2*i+1] = KemField.add(KemField.mul(a0, b1), KemField.mul(a1, b0))
        }
        return r
    }

    /// Add two polynomials
    public static func polyAdd(_ a: [Int32], _ b: [Int32]) -> [Int32] {
        var r = [Int32](repeating: 0, count: 256)
        for i in 0..<256 {
            r[i] = KemField.add(a[i], b[i])
        }
        return r
    }

    /// Subtract two polynomials
    public static func polySub(_ a: [Int32], _ b: [Int32]) -> [Int32] {
        var r = [Int32](repeating: 0, count: 256)
        for i in 0..<256 {
            r[i] = KemField.sub(a[i], b[i])
        }
        return r
    }
}
