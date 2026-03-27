// ML-KEM Byte Encoding / Decoding

public enum KemEncode {
    /// Encode an array of d-bit integers into bytes
    public static func byteEncode(_ coeffs: [Int32], d: Int) -> [UInt8] {
        let n = coeffs.count
        let totalBits = n * d
        let totalBytes = (totalBits + 7) / 8
        var result = [UInt8](repeating: 0, count: totalBytes)
        var bitIndex = 0
        for c in coeffs {
            var val = Int(c)
            if d < 32 {
                val = val & ((1 << d) - 1)
            }
            for b in 0..<d {
                if (val >> b) & 1 == 1 {
                    result[bitIndex / 8] |= UInt8(1 << (bitIndex % 8))
                }
                bitIndex += 1
            }
        }
        return result
    }

    /// Decode bytes into an array of d-bit integers
    public static func byteDecode(_ bytes: [UInt8], d: Int, n: Int = 256) -> [Int32] {
        var result = [Int32](repeating: 0, count: n)
        var bitIndex = 0
        for i in 0..<n {
            var val: Int32 = 0
            for b in 0..<d {
                let byteIdx = bitIndex / 8
                let bitIdx = bitIndex % 8
                if byteIdx < bytes.count {
                    if (bytes[byteIdx] >> bitIdx) & 1 == 1 {
                        val |= Int32(1 << b)
                    }
                }
                bitIndex += 1
            }
            result[i] = val
        }
        return result
    }

    /// Encode a polynomial (12-bit coefficients) to 384 bytes
    public static func encodePoly12(_ poly: [Int32]) -> [UInt8] {
        return byteEncode(poly, d: 12)
    }

    /// Decode 384 bytes to a polynomial (12-bit coefficients mod q)
    public static func decodePoly12(_ bytes: [UInt8]) -> [Int32] {
        var poly = byteDecode(bytes, d: 12)
        for i in 0..<256 {
            poly[i] = poly[i] % KemField.q
        }
        return poly
    }
}
