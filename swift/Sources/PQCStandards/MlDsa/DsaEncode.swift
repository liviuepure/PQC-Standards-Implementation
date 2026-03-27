// ML-DSA Encoding Functions

public enum DsaEncode {
    /// Encode polynomial with coefficients in [0, 2^d - 1]
    public static func polyEncode(_ poly: [Int32], bits: Int) -> [UInt8] {
        return KemEncode.byteEncode(poly, d: bits)
    }

    /// Decode polynomial
    public static func polyDecode(_ bytes: [UInt8], bits: Int) -> [Int32] {
        return KemEncode.byteDecode(bytes, d: bits)
    }

    /// Encode t1 (10 bits per coefficient)
    public static func encodeT1(_ t1: [[Int32]]) -> [UInt8] {
        var result = [UInt8]()
        for poly in t1 {
            result.append(contentsOf: KemEncode.byteEncode(poly, d: 10))
        }
        return result
    }

    /// Decode t1
    public static func decodeT1(_ bytes: [UInt8], k: Int) -> [[Int32]] {
        var result = [[Int32]]()
        for i in 0..<k {
            let start = 320 * i
            let polyBytes = Array(bytes[start..<(start + 320)])
            result.append(KemEncode.byteDecode(polyBytes, d: 10))
        }
        return result
    }

    /// Encode t0 (13 bits, centered)
    public static func encodeT0(_ t0: [[Int32]]) -> [UInt8] {
        var result = [UInt8]()
        for poly in t0 {
            let shifted = poly.map { (1 << 12) - $0 }  // Map to unsigned
            result.append(contentsOf: KemEncode.byteEncode(shifted, d: 13))
        }
        return result
    }

    /// Decode t0
    public static func decodeT0(_ bytes: [UInt8], k: Int) -> [[Int32]] {
        var result = [[Int32]]()
        for i in 0..<k {
            let start = 416 * i
            let polyBytes = Array(bytes[start..<(start + 416)])
            let decoded = KemEncode.byteDecode(polyBytes, d: 13)
            let centered = decoded.map { DsaField.reduce(Int64((1 << 12) - $0)) }
            result.append(centered)
        }
        return result
    }

    /// Encode eta-bounded polynomial
    public static func encodeEta(_ poly: [Int32], eta: Int) -> [UInt8] {
        let bits = eta == 2 ? 3 : 4
        let mapped = poly.map { c -> Int32 in
            var v = c % DsaField.q
            if v < 0 { v += DsaField.q }
            if v > DsaField.q / 2 { v = v - DsaField.q }
            return Int32(eta) - v
        }
        return KemEncode.byteEncode(mapped, d: bits)
    }

    /// Decode eta-bounded polynomial
    public static func decodeEta(_ bytes: [UInt8], eta: Int) -> [Int32] {
        let bits = eta == 2 ? 3 : 4
        let decoded = KemEncode.byteDecode(bytes, d: bits)
        return decoded.map { DsaField.reduce(Int64(Int32(eta) - $0)) }
    }

    /// Encode z with gamma1-bounded coefficients
    public static func encodeZ(_ z: [[Int32]], gamma1: Int32) -> [UInt8] {
        let bits = gamma1 == (1 << 17) ? 18 : 20
        var result = [UInt8]()
        for poly in z {
            let mapped = poly.map { c -> Int32 in
                var v = c % DsaField.q
                if v < 0 { v += DsaField.q }
                if v > DsaField.q / 2 { v = DsaField.q - v; return gamma1 + v }
                return gamma1 - v
            }
            result.append(contentsOf: KemEncode.byteEncode(mapped, d: bits))
        }
        return result
    }

    /// Decode z
    public static func decodeZ(_ bytes: [UInt8], l: Int, gamma1: Int32) -> [[Int32]] {
        let bits = gamma1 == (1 << 17) ? 18 : 20
        let polyBytes = bits * 256 / 8
        var result = [[Int32]]()
        for i in 0..<l {
            let start = polyBytes * i
            let decoded = KemEncode.byteDecode(Array(bytes[start..<(start + polyBytes)]), d: bits)
            let centered = decoded.map { DsaField.reduce(Int64(gamma1 - $0)) }
            result.append(centered)
        }
        return result
    }

    /// Encode hint vector
    public static func encodeHint(_ h: [[Bool]], omega: Int, k: Int) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: omega + k)
        var idx = 0
        for i in 0..<k {
            for j in 0..<256 {
                if h[i][j] {
                    result[idx] = UInt8(j)
                    idx += 1
                }
            }
            result[omega + i] = UInt8(idx)
        }
        return result
    }

    /// Decode hint vector
    public static func decodeHint(_ bytes: [UInt8], omega: Int, k: Int) -> [[Bool]]? {
        var h = [[Bool]](repeating: [Bool](repeating: false, count: 256), count: k)
        var idx = 0
        for i in 0..<k {
            let limit = Int(bytes[omega + i])
            if limit < idx { return nil }
            for j in idx..<limit {
                if j >= omega { return nil }
                let pos = Int(bytes[j])
                if pos >= 256 { return nil }
                h[i][pos] = true
            }
            idx = limit
        }
        // Check remaining positions are zero
        for j in idx..<omega {
            if bytes[j] != 0 { return nil }
        }
        return h
    }
}
