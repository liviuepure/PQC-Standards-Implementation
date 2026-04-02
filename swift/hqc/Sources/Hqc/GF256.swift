// GF256.swift -- GF(2^8) arithmetic with irreducible polynomial 0x11D.
// x^8 + x^4 + x^3 + x^2 + 1. Generator alpha = 2 (primitive element).

import Foundation

// MARK: - Tables

/// Exponentiation table (doubled for wrap-around convenience).
private var gf256Exp = [UInt8](repeating: 0, count: 512)
/// Logarithm table.
private var gf256Log = [UInt8](repeating: 0, count: 256)

/// Irreducible polynomial for GF(2^8): x^8 + x^4 + x^3 + x^2 + 1.
let gfPolyConst: UInt16 = 0x11D
/// Primitive element (generator) for GF(2^8) with 0x11D.
let gfGenConst: UInt8 = 2

private var gf256TablesInitialized = false

/// Initialize GF(2^8) log/exp tables. Must be called before any GF(2^8) operation.
func initGF256Tables() {
    guard !gf256TablesInitialized else { return }
    gf256TablesInitialized = true

    var x: UInt16 = 1
    for i in 0..<255 {
        gf256Exp[i] = UInt8(x)
        gf256Exp[i + 255] = UInt8(x) // wrap-around
        gf256Log[Int(x)] = UInt8(i)
        x <<= 1
        if x >= 256 {
            x ^= gfPolyConst
        }
    }
    gf256Log[0] = 0       // convention: log(0) = 0 (never used for valid math)
    gf256Exp[510] = gf256Exp[0] // ensure full wrap
}

// MARK: - Arithmetic

/// Addition in GF(2^8) (XOR).
func gf256Add(_ a: UInt8, _ b: UInt8) -> UInt8 {
    return a ^ b
}

/// Multiplication in GF(2^8) via log/exp tables.
func gf256Mul(_ a: UInt8, _ b: UInt8) -> UInt8 {
    if a == 0 || b == 0 { return 0 }
    return gf256Exp[Int(gf256Log[Int(a)]) + Int(gf256Log[Int(b)])]
}

/// Constant-time GF(2^8) multiplication via carryless multiply.
func gf256MulCT(_ a: UInt8, _ b: UInt8) -> UInt8 {
    var result: UInt16 = 0
    var ab = UInt16(a)
    let bb = UInt16(b)

    for i in 0..<8 {
        result ^= ab * ((bb >> i) & 1)
        ab <<= 1
    }

    // Reduce mod 0x11D
    for i in stride(from: 14, through: 8, by: -1) {
        if result & (1 << i) != 0 {
            result ^= gfPolyConst << (i - 8)
        }
    }
    return UInt8(result)
}

/// Multiplicative inverse of a in GF(2^8). Returns 0 if a == 0.
func gf256Inv(_ a: UInt8) -> UInt8 {
    if a == 0 { return 0 }
    return gf256Exp[255 - Int(gf256Log[Int(a)])]
}

/// a^n in GF(2^8).
func gf256Pow(_ a: UInt8, _ n: Int) -> UInt8 {
    if a == 0 {
        return n == 0 ? 1 : 0
    }
    let logA = Int(gf256Log[Int(a)])
    var logResult = (logA * n) % 255
    if logResult < 0 { logResult += 255 }
    return gf256Exp[logResult]
}

/// Division a / b in GF(2^8). Traps if b == 0.
func gf256Div(_ a: UInt8, _ b: UInt8) -> UInt8 {
    precondition(b != 0, "hqc: gf256 division by zero")
    if a == 0 { return 0 }
    var logDiff = Int(gf256Log[Int(a)]) - Int(gf256Log[Int(b)])
    if logDiff < 0 { logDiff += 255 }
    return gf256Exp[logDiff]
}
