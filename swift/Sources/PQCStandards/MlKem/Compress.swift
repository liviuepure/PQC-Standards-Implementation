// ML-KEM Compress/Decompress

public enum KemCompress {
    /// Compress: round(2^d / q * x) mod 2^d
    public static func compress(_ x: Int32, d: Int) -> Int32 {
        let shifted = (Int64(x) << d) + Int64(KemField.q / 2)
        return Int32(shifted / Int64(KemField.q)) & ((1 << d) - 1)
    }

    /// Decompress: round(q / 2^d * y)
    public static func decompress(_ y: Int32, d: Int) -> Int32 {
        let val = (Int64(y) * Int64(KemField.q) + (1 << (d - 1))) >> d
        return Int32(val)
    }

    /// Compress a polynomial
    public static func compressPoly(_ poly: [Int32], d: Int) -> [Int32] {
        return poly.map { compress(KemField.reduce($0), d: d) }
    }

    /// Decompress a polynomial
    public static func decompressPoly(_ poly: [Int32], d: Int) -> [Int32] {
        return poly.map { decompress($0, d: d) }
    }
}
