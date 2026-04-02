// ReedMuller.swift -- Reed-Muller code RM(1, 7) for HQC.
//
// RM(1, 7) encodes 8 bits (1 byte) into 128 bits (two UInt64 words).
// The RM codeword is then duplicated (multiplicity times) to form an
// n2-bit codeword for additional error correction.

import Foundation

/// Base RM(1,7) codeword length = 2^7 = 128 bits.
let rmBaseLen = 128

/// Encode a single byte into a 128-bit RM(1,7) codeword.
/// Returns [lo, hi] representing 128 bits.
func rmEncodeBase(_ msg: UInt8) -> (UInt64, UInt64) {
    let expand: (UInt) -> UInt64 = { bit in
        return 0 &- UInt64((msg >> bit) & 1)
    }

    var lo: UInt64 = 0
    var hi: UInt64 = 0

    // Bit 0: constant row (all-ones if set)
    lo ^= expand(0)
    hi ^= expand(0)

    // Bit 1: 0xAAAAAAAAAAAAAAAA
    lo ^= expand(1) & 0xAAAAAAAAAAAAAAAA
    hi ^= expand(1) & 0xAAAAAAAAAAAAAAAA

    // Bit 2: 0xCCCCCCCCCCCCCCCC
    lo ^= expand(2) & 0xCCCCCCCCCCCCCCCC
    hi ^= expand(2) & 0xCCCCCCCCCCCCCCCC

    // Bit 3: 0xF0F0F0F0F0F0F0F0
    lo ^= expand(3) & 0xF0F0F0F0F0F0F0F0
    hi ^= expand(3) & 0xF0F0F0F0F0F0F0F0

    // Bit 4: 0xFF00FF00FF00FF00
    lo ^= expand(4) & 0xFF00FF00FF00FF00
    hi ^= expand(4) & 0xFF00FF00FF00FF00

    // Bit 5: 0xFFFF0000FFFF0000
    lo ^= expand(5) & 0xFFFF0000FFFF0000
    hi ^= expand(5) & 0xFFFF0000FFFF0000

    // Bit 6: 0xFFFFFFFF00000000
    lo ^= expand(6) & 0xFFFFFFFF00000000
    hi ^= expand(6) & 0xFFFFFFFF00000000

    // Bit 7: (0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
    hi ^= expand(7)

    return (lo, hi)
}

/// Encode a byte into the dst vector starting at bitOffset, with multiplicity copies.
func rmEncodeInto(_ dst: inout [UInt64], _ msg: UInt8, _ bitOffset: Int, _ multiplicity: Int) {
    let (baseLo, baseHi) = rmEncodeBase(msg)
    let base = [baseLo, baseHi]

    var bitPos = bitOffset
    for _ in 0..<multiplicity {
        for w in 0..<2 {
            let word = base[w]
            let dstWord = bitPos / 64
            let dstBit = bitPos % 64

            if dstBit == 0 && dstWord < dst.count {
                dst[dstWord] ^= word
                bitPos += 64
            } else {
                for bit in 0..<64 {
                    if word & (1 << bit) != 0 {
                        let idx = bitPos / 64
                        let off = bitPos % 64
                        if idx < dst.count {
                            dst[idx] ^= 1 << off
                        }
                    }
                    bitPos += 1
                }
            }
        }
    }
}

/// Decode an n2-bit received codeword (with duplicated RM(1,7)) to a single byte
/// using Walsh-Hadamard transform.
func rmDecode(_ src: [UInt64], _ n2: Int, _ multiplicity: Int) -> UInt8 {
    // Step 1: Accumulate all copies into signed sum array of 128 entries.
    var sums = [Int32](repeating: 0, count: rmBaseLen)

    var bitPos = 0
    for _ in 0..<multiplicity {
        for i in 0..<rmBaseLen {
            let wordIdx = bitPos / 64
            let bitIdx = bitPos % 64
            var bit: Int32 = 0
            if wordIdx < src.count {
                bit = Int32((src[wordIdx] >> bitIdx) & 1)
            }
            // Convert 0/1 to +1/-1 (0 -> +1, 1 -> -1)
            sums[i] += 1 - 2 * bit
            bitPos += 1
        }
    }

    // Step 2: Fast Walsh-Hadamard Transform (in-place, 7 passes)
    for pass in 0..<7 {
        let step = 1 << pass
        var i = 0
        while i < rmBaseLen {
            for j in i..<(i + step) {
                let a = sums[j]
                let b = sums[j + step]
                sums[j] = a + b
                sums[j + step] = a - b
            }
            i += 2 * step
        }
    }

    // Step 3: Find position with maximum absolute value
    var maxAbs: Int32 = 0
    var maxPos = 0
    var sign: Int32 = 1

    for i in 0..<rmBaseLen {
        let v = sums[i]
        let abs = v < 0 ? -v : v
        if abs > maxAbs {
            maxAbs = abs
            maxPos = i
            sign = v > 0 ? 1 : -1
        }
    }

    // Step 4: Recover the message byte
    var msg = UInt8(maxPos << 1)
    if sign < 0 {
        msg |= 1
    }
    return msg
}
