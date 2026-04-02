// Encode.swift — FIPS 206 key and signature encoding/decoding for FN-DSA.
//
// All bit-packing is LSB-first.

import Foundation

// MARK: - Public Key

/// Encode NTT public-key polynomial h into FIPS 206 format.
func encodePK(_ h: [Int32], _ p: Params) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: p.pkSize)
    out[0] = UInt8(0x00 | p.logN)
    packBits14(&out, offset: 1, src: h, n: p.n)
    return out
}

/// Decode a FIPS 206 public key. Returns nil on format error.
func decodePK(_ data: [UInt8], _ p: Params) -> [Int32]? {
    guard data.count == p.pkSize else { return nil }
    guard data[0] == UInt8(0x00 | p.logN) else { return nil }
    return unpackBits14(data, offset: 1, n: p.n)
}

// MARK: - Secret Key

/// Encode (f, g, F) into FIPS 206 secret-key format.
func encodeSK(_ f: [Int32], _ g: [Int32], _ F: [Int32], _ p: Params) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: p.skSize)
    out[0] = UInt8(0x50 | p.logN)
    let fgBits = p.fgBits
    var offset = 1
    packSignedBits(&out, offset: offset, src: f, n: p.n, bits: fgBits)
    offset += (p.n * fgBits) / 8
    packSignedBits(&out, offset: offset, src: g, n: p.n, bits: fgBits)
    offset += (p.n * fgBits) / 8
    packSignedBits(&out, offset: offset, src: F, n: p.n, bits: 8)
    return out
}

/// Decode a FIPS 206 secret key. Returns nil on format error.
func decodeSK(_ data: [UInt8], _ p: Params) -> (f: [Int32], g: [Int32], F: [Int32])? {
    guard data.count == p.skSize else { return nil }
    guard data[0] == UInt8(0x50 | p.logN) else { return nil }
    let fgBits = p.fgBits
    var offset = 1
    let f = unpackSignedBits(data, offset: offset, n: p.n, bits: fgBits)
    offset += (p.n * fgBits) / 8
    let g = unpackSignedBits(data, offset: offset, n: p.n, bits: fgBits)
    offset += (p.n * fgBits) / 8
    let F = unpackSignedBits(data, offset: offset, n: p.n, bits: 8)
    return (f, g, F)
}

// MARK: - Signature

/// lo parameter for s1 compression.
private func loBitsFor(_ p: Params) -> Int {
    return p.n == 1024 ? 7 : 6
}

/// Encode a signature into FIPS 206 format. Returns nil if compressed s1 is too large.
func encodeSig(_ salt: [UInt8], _ s1: [Int32], _ p: Params) -> [UInt8]? {
    let capacity = p.sigMaxLen - 41
    var compBuf = [UInt8](repeating: 0, count: capacity)
    guard let used = compressS1(&compBuf, s1: s1, n: p.n, lo: loBitsFor(p)) else {
        return nil
    }

    var out: [UInt8]
    if p.padded {
        out = [UInt8](repeating: 0, count: p.sigSize)
    } else {
        out = [UInt8](repeating: 0, count: 1 + 40 + used)
    }
    out[0] = UInt8(0x30 | p.logN)
    for i in 0..<40 { out[1 + i] = salt[i] }
    for i in 0..<used { out[41 + i] = compBuf[i] }
    return out
}

/// Decode a FIPS 206 signature. Returns nil on format error.
func decodeSig(_ data: [UInt8], _ p: Params) -> (salt: [UInt8], s1: [Int32])? {
    guard data.count >= 41 else { return nil }
    guard data[0] == UInt8(0x30 | p.logN) else { return nil }
    if p.padded {
        guard data.count == p.sigSize else { return nil }
    } else {
        guard data.count <= p.sigMaxLen else { return nil }
    }
    let salt = Array(data[1..<41])
    guard let s1 = decompressS1(Array(data[41...]), n: p.n, lo: loBitsFor(p)) else {
        return nil
    }
    return (salt, s1)
}

// MARK: - Internal bit-packing helpers

private func packBits14(_ dst: inout [UInt8], offset: Int, src: [Int32], n: Int) {
    var cursor = offset * 8
    for i in 0..<n {
        let v = UInt32(src[i]) & 0x3FFF
        let byteIdx = cursor >> 3
        let bitIdx = UInt32(cursor & 7)
        dst[byteIdx] |= UInt8(truncatingIfNeeded: v << bitIdx)
        if bitIdx == 0 {
            dst[byteIdx + 1] |= UInt8(truncatingIfNeeded: v >> 8)
        } else {
            dst[byteIdx + 1] |= UInt8(truncatingIfNeeded: v >> (8 - bitIdx))
            if bitIdx > 2 {
                dst[byteIdx + 2] |= UInt8(truncatingIfNeeded: v >> (16 - bitIdx))
            }
        }
        cursor += 14
    }
}

private func unpackBits14(_ src: [UInt8], offset: Int, n: Int) -> [Int32] {
    var out = [Int32](repeating: 0, count: n)
    var cursor = offset * 8
    for i in 0..<n {
        let byteIdx = cursor >> 3
        let bitIdx = UInt32(cursor & 7)
        var v: UInt32
        if bitIdx == 0 {
            v = UInt32(src[byteIdx]) | (UInt32(src[byteIdx + 1]) << 8)
        } else {
            v = UInt32(src[byteIdx]) >> bitIdx
            v |= UInt32(src[byteIdx + 1]) << (8 - bitIdx)
            if bitIdx > 2 {
                v |= UInt32(src[byteIdx + 2]) << (16 - bitIdx)
            }
        }
        out[i] = Int32(v & 0x3FFF)
        cursor += 14
    }
    return out
}

private func packSignedBits(_ dst: inout [UInt8], offset: Int, src: [Int32], n: Int, bits: Int) {
    let mask = UInt32((1 << bits) - 1)
    var cursor = offset * 8
    for i in 0..<n {
        var v = UInt32(bitPattern: src[i]) & mask
        var rem = bits
        var cur = cursor
        while rem > 0 {
            let byteIdx = cur >> 3
            let bitIdx = cur & 7
            let avail = 8 - bitIdx
            let chunk = min(rem, avail)
            dst[byteIdx] |= UInt8(truncatingIfNeeded: (v & UInt32((1 << chunk) - 1)) << UInt32(bitIdx))
            v >>= UInt32(chunk)
            cur += chunk
            rem -= chunk
        }
        cursor += bits
    }
}

private func unpackSignedBits(_ src: [UInt8], offset: Int, n: Int, bits: Int) -> [Int32] {
    var out = [Int32](repeating: 0, count: n)
    let mask = UInt32((1 << bits) - 1)
    let signBit = UInt32(1 << (bits - 1))
    var cursor = offset * 8
    for i in 0..<n {
        var v: UInt32 = 0
        var rem = bits
        var cur = cursor
        var shift = 0
        while rem > 0 {
            let byteIdx = cur >> 3
            let bitIdx = cur & 7
            let avail = 8 - bitIdx
            let chunk = min(rem, avail)
            var b = UInt32(src[byteIdx]) >> UInt32(bitIdx)
            b &= UInt32((1 << chunk) - 1)
            v |= b << UInt32(shift)
            shift += chunk
            cur += chunk
            rem -= chunk
        }
        v &= mask
        if v & signBit != 0 {
            v |= ~mask
        }
        out[i] = Int32(bitPattern: v)
        cursor += bits
    }
    return out
}

// MARK: - S1 compression/decompression

/// Compress s1 coefficients. Returns bytesUsed on success, nil on overflow.
private func compressS1(_ dst: inout [UInt8], s1: [Int32], n: Int, lo: Int) -> Int? {
    let loMask = Int32((1 << lo) - 1)
    var cursor = 0
    let capacity = dst.count * 8

    for i in 0..<n {
        let s = s1[i]
        let v = s < 0 ? -s : s
        let low = v & loMask
        let high = v >> lo

        // Emit lo bits of low, LSB-first.
        for b in 0..<lo {
            guard cursor < capacity else { return nil }
            if ((low >> b) & 1) != 0 {
                dst[cursor >> 3] |= UInt8(1 << (cursor & 7))
            }
            cursor += 1
        }
        // Emit high 1-bits.
        for _ in 0..<high {
            guard cursor < capacity else { return nil }
            dst[cursor >> 3] |= UInt8(1 << (cursor & 7))
            cursor += 1
        }
        // Emit terminating 0-bit.
        guard cursor < capacity else { return nil }
        cursor += 1
        // Emit sign bit.
        guard cursor < capacity else { return nil }
        if s < 0 {
            dst[cursor >> 3] |= UInt8(1 << (cursor & 7))
        }
        cursor += 1
    }
    return (cursor + 7) / 8
}

/// Decompress s1 coefficients. Returns nil on format error.
private func decompressS1(_ src: [UInt8], n: Int, lo: Int) -> [Int32]? {
    let totalBits = src.count * 8
    var cursor = 0

    var out = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        // Read lo bits.
        var low: Int32 = 0
        for b in 0..<lo {
            guard cursor < totalBits else { return nil }
            let bit = (src[cursor >> 3] >> (cursor & 7)) & 1
            low |= Int32(bit) << b
            cursor += 1
        }
        // Read unary-coded high.
        var high: Int32 = 0
        while true {
            guard cursor < totalBits else { return nil }
            let bit = (src[cursor >> 3] >> (cursor & 7)) & 1
            cursor += 1
            if bit == 0 { break }
            high += 1
        }
        // Read sign bit.
        guard cursor < totalBits else { return nil }
        let signBit = (src[cursor >> 3] >> (cursor & 7)) & 1
        cursor += 1

        var v = (high << lo) | low
        if signBit == 1 {
            if v == 0 { return nil } // Non-canonical zero with sign=1
            v = -v
        }
        out[i] = v
    }
    return out
}
