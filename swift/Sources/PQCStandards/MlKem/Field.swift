// ML-KEM Field Arithmetic over GF(3329)

public enum KemField {
    public static let q: Int32 = 3329
    // q^{-1} mod 2^16 (for Montgomery): we use Barrett reduction instead
    // Barrett constant: floor(2^24 / q) = floor(16777216 / 3329) = 5039

    /// Reduce mod q into [0, q)
    @inlinable
    public static func reduce(_ a: Int32) -> Int32 {
        var r = a % q
        if r < 0 { r += q }
        return r
    }

    /// Modular addition
    @inlinable
    public static func add(_ a: Int32, _ b: Int32) -> Int32 {
        return reduce(a + b)
    }

    /// Modular subtraction
    @inlinable
    public static func sub(_ a: Int32, _ b: Int32) -> Int32 {
        return reduce(a - b)
    }

    /// Modular multiplication
    @inlinable
    public static func mul(_ a: Int32, _ b: Int32) -> Int32 {
        return reduce(a * b)
    }

    /// Barrett reduction for values in [0, q^2)
    @inlinable
    public static func barrettReduce(_ a: Int32) -> Int32 {
        let t = (Int64(a) * 5039) >> 24
        var r = a - Int32(t) * q
        if r >= q { r -= q }
        if r < 0 { r += q }
        return r
    }
}
