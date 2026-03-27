// ML-DSA Field Arithmetic over GF(8380417)

public enum DsaField {
    public static let q: Int32 = 8380417

    @inlinable
    public static func reduce(_ a: Int64) -> Int32 {
        var r = Int32(a % Int64(q))
        if r < 0 { r += q }
        return r
    }

    @inlinable
    public static func add(_ a: Int32, _ b: Int32) -> Int32 {
        var r = a + b
        if r >= q { r -= q }
        if r < 0 { r += q }
        return r
    }

    @inlinable
    public static func sub(_ a: Int32, _ b: Int32) -> Int32 {
        var r = a - b
        if r < 0 { r += q }
        return r
    }

    @inlinable
    public static func mul(_ a: Int32, _ b: Int32) -> Int32 {
        return reduce(Int64(a) * Int64(b))
    }

    /// Power mod q
    public static func power(_ base: Int32, _ exp: Int32) -> Int32 {
        var result: Int64 = 1
        var b = Int64(base) % Int64(q)
        var e = exp
        while e > 0 {
            if e & 1 == 1 {
                result = (result * b) % Int64(q)
            }
            b = (b * b) % Int64(q)
            e >>= 1
        }
        return Int32(result)
    }
}
