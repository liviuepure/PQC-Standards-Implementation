// ML-DSA Decompose, HighBits, LowBits, MakeHint, UseHint

public enum DsaDecompose {
    /// Decompose r into (r1, r0) where r = r1*2*gamma2 + r0 with |r0| <= gamma2
    public static func decompose(_ r: Int32, gamma2: Int32) -> (r1: Int32, r0: Int32) {
        let q = DsaField.q
        var rPlus = r % q
        if rPlus < 0 { rPlus += q }

        // r0 = rPlus mod+/- (2*gamma2)
        var r0 = rPlus % (2 * gamma2)
        if r0 > gamma2 { r0 -= 2 * gamma2 }

        if rPlus - r0 == q - 1 {
            return (0, r0 - 1)
        } else {
            return ((rPlus - r0) / (2 * gamma2), r0)
        }
    }

    /// HighBits
    public static func highBits(_ r: Int32, gamma2: Int32) -> Int32 {
        return decompose(r, gamma2: gamma2).r1
    }

    /// LowBits
    public static func lowBits(_ r: Int32, gamma2: Int32) -> Int32 {
        return decompose(r, gamma2: gamma2).r0
    }

    /// MakeHint
    public static func makeHint(_ z: Int32, _ r: Int32, gamma2: Int32) -> Bool {
        let r1 = highBits(r, gamma2: gamma2)
        let v1 = highBits(DsaField.add(r, z), gamma2: gamma2)
        return r1 != v1
    }

    /// UseHint
    public static func useHint(_ h: Bool, _ r: Int32, gamma2: Int32) -> Int32 {
        let (r1, r0) = decompose(r, gamma2: gamma2)
        if !h { return r1 }

        let q = DsaField.q
        let m: Int32
        if gamma2 == (q - 1) / 88 {
            m = 44
        } else {
            m = 16
        }

        if r0 > 0 {
            return (r1 + 1) % m
        } else {
            return (r1 - 1 + m) % m
        }
    }

    /// Infinity norm of a polynomial
    public static func polyNorm(_ p: [Int32]) -> Int32 {
        var maxVal: Int32 = 0
        let q = DsaField.q
        for c in p {
            var v = c % q
            if v < 0 { v += q }
            if v > q / 2 { v = q - v }
            if v > maxVal { maxVal = v }
        }
        return maxVal
    }

    /// Infinity norm of a vector
    public static func vecNorm(_ v: [[Int32]]) -> Int32 {
        var maxVal: Int32 = 0
        for p in v {
            let n = polyNorm(p)
            if n > maxVal { maxVal = n }
        }
        return maxVal
    }
}
