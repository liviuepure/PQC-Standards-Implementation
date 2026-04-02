// GF2.swift -- GF(2) polynomial arithmetic: polynomials packed into [UInt64] words.
// Arithmetic is in GF(2)[x]/(x^n - 1).

import Foundation

// MARK: - Basic operations

/// Polynomial addition in GF(2) (XOR).
func vectAdd(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
    let n = max(a.count, b.count)
    var out = [UInt64](repeating: 0, count: n)
    for i in 0..<a.count { out[i] = a[i] }
    for i in 0..<b.count { out[i] ^= b[i] }
    return out
}

/// In-place addition: a ^= b.
func vectAddInPlace(_ a: inout [UInt64], _ b: [UInt64]) {
    for i in 0..<b.count {
        a[i] ^= b[i]
    }
}

/// Set bit at position pos in v.
func vectSetBit(_ v: inout [UInt64], _ pos: Int) {
    v[pos / 64] |= 1 << (pos % 64)
}

/// Get bit at position pos in v.
func vectGetBit(_ v: [UInt64], _ pos: Int) -> UInt64 {
    return (v[pos / 64] >> (pos % 64)) & 1
}

/// Hamming weight of a GF(2) vector.
func vectWeight(_ v: [UInt64]) -> Int {
    var w = 0
    for word in v {
        w += popcount64(word)
    }
    return w
}

/// Number of set bits in a 64-bit word.
private func popcount64(_ x: UInt64) -> Int {
    return x.nonzeroBitCount
}

// MARK: - Serialization

/// Convert a UInt64 vector to bytes (little-endian).
func vectToBytes(_ v: [UInt64], _ nBytes: Int) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: nBytes)
    for i in 0..<v.count {
        let start = i * 8
        if start >= nBytes { break }
        let word = v[i]
        let remaining = nBytes - start
        let bytesToWrite = min(remaining, 8)
        for b in 0..<bytesToWrite {
            out[start + b] = UInt8(truncatingIfNeeded: word >> (b * 8))
        }
    }
    return out
}

/// Convert bytes to a UInt64 vector (little-endian).
func vectFromBytes(_ data: [UInt8], _ nWords: Int) -> [UInt64] {
    var v = [UInt64](repeating: 0, count: nWords)
    for i in 0..<nWords {
        let start = i * 8
        if start >= data.count { break }
        let end = min(start + 8, data.count)
        var word: UInt64 = 0
        for b in start..<end {
            word |= UInt64(data[b]) << ((b - start) * 8)
        }
        v[i] = word
    }
    return v
}

/// Truncate/mask to exactly nBits bits.
func vectResize(_ v: [UInt64], _ nBits: Int) -> [UInt64] {
    let nWords = (nBits + 63) / 64
    var out = [UInt64](repeating: 0, count: nWords)
    let copyLen = min(v.count, nWords)
    for i in 0..<copyLen { out[i] = v[i] }
    let rem = nBits % 64
    if rem != 0 && nWords > 0 {
        out[nWords - 1] &= (1 << rem) - 1
    }
    return out
}

/// Constant-time comparison. Returns 1 if equal, 0 otherwise.
func vectEqual(_ a: [UInt64], _ b: [UInt64]) -> Int {
    var diff: UInt64 = 0
    let n = min(a.count, b.count)
    for i in 0..<n {
        diff |= a[i] ^ b[i]
    }
    for i in n..<a.count { diff |= a[i] }
    for i in n..<b.count { diff |= b[i] }
    var d = diff | (diff >> 32)
    d |= d >> 16
    d |= d >> 8
    d |= d >> 4
    d |= d >> 2
    d |= d >> 1
    return 1 - Int(d & 1)
}

// MARK: - Polynomial multiplication

/// Carryless multiplication of two 64-bit words.
/// Returns (lo, hi) such that a * b = hi<<64 | lo in GF(2).
private func baseMul(_ a: UInt64, _ b: UInt64) -> (UInt64, UInt64) {
    var lo: UInt64 = 0
    var hi: UInt64 = 0

    for i in 0..<64 {
        if (a >> i) & 1 == 0 { continue }
        if i == 0 {
            lo ^= b
        } else {
            lo ^= b << i
            hi ^= b >> (64 - i)
        }
    }

    return (lo, hi)
}

/// Schoolbook polynomial multiplication of two GF(2) polynomials.
private func schoolbookMul(_ a: [UInt64], _ sizeA: Int,
                           _ b: [UInt64], _ sizeB: Int) -> [UInt64] {
    var out = [UInt64](repeating: 0, count: sizeA + sizeB)
    for i in 0..<sizeA {
        if a[i] == 0 { continue }
        for j in 0..<sizeB {
            if b[j] == 0 { continue }
            let (lo, hi) = baseMul(a[i], b[j])
            out[i + j] ^= lo
            out[i + j + 1] ^= hi
        }
    }
    return out
}

/// Polynomial multiplication mod (x^n - 1) in GF(2)[x].
func vectMul(_ a: [UInt64], _ b: [UInt64], _ n: Int) -> [UInt64] {
    let nWords = (n + 63) / 64

    // Pad a and b to nWords
    var aPad = [UInt64](repeating: 0, count: nWords)
    var bPad = [UInt64](repeating: 0, count: nWords)
    let aCopy = min(a.count, nWords)
    let bCopy = min(b.count, nWords)
    for i in 0..<aCopy { aPad[i] = a[i] }
    for i in 0..<bCopy { bPad[i] = b[i] }

    // Mask last word
    let rem = n % 64
    if rem != 0 {
        aPad[nWords - 1] &= (1 << rem) - 1
        bPad[nWords - 1] &= (1 << rem) - 1
    }

    // Full product
    let prod = schoolbookMul(aPad, nWords, bPad, nWords)

    // Reduce mod (x^n - 1): add bits above position n back in
    var out = [UInt64](repeating: 0, count: nWords)
    for i in 0..<nWords { out[i] = prod[i] }

    let wordOff = n / 64

    if rem == 0 {
        for i in 0..<nWords {
            if wordOff + i < 2 * nWords {
                out[i] ^= prod[wordOff + i]
            }
        }
    } else {
        for i in 0..<nWords {
            let idx = wordOff + i
            if idx < 2 * nWords {
                out[i] ^= prod[idx] >> rem
            }
            if idx + 1 < 2 * nWords {
                out[i] ^= prod[idx + 1] << (64 - rem)
            }
        }
    }

    // Mask the last word
    if rem != 0 {
        out[nWords - 1] &= (1 << rem) - 1
    }

    return out
}
