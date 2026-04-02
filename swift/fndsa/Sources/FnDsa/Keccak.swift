// Keccak.swift — Minimal SHAKE-256 XOF implementation for FN-DSA.
//
// Keccak-f[1600] permutation (24 rounds), rate = 136 bytes, domain sep = 0x1F.

import Foundation

// MARK: - Keccak-f[1600] round constants

private let keccakRC: [UInt64] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

// Rotation offsets for rho step.
private let keccakRotations: [Int] = [
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
]

// Pi step permutation indices.
private let keccakPi: [Int] = [
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4,
]

@inline(__always)
private func rotl64(_ x: UInt64, _ n: Int) -> UInt64 {
    return (x << n) | (x >> (64 - n))
}

/// Keccak-f[1600] permutation (24 rounds), in-place on a 25-element state.
private func keccakF1600(_ state: inout [UInt64]) {
    for round in 0..<24 {
        // Theta
        var c = [UInt64](repeating: 0, count: 5)
        for x in 0..<5 {
            c[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
        }
        var d = [UInt64](repeating: 0, count: 5)
        for x in 0..<5 {
            d[x] = c[(x+4)%5] ^ rotl64(c[(x+1)%5], 1)
        }
        for x in 0..<5 {
            for y in 0..<5 {
                state[y*5+x] ^= d[x]
            }
        }

        // Rho + Pi
        var tmp = [UInt64](repeating: 0, count: 25)
        for i in 0..<25 {
            tmp[keccakPi[i]] = rotl64(state[i], keccakRotations[i])
        }

        // Chi
        for y in 0..<5 {
            for x in 0..<5 {
                state[y*5+x] = tmp[y*5+x] ^ (~tmp[y*5+(x+1)%5] & tmp[y*5+(x+2)%5])
            }
        }

        // Iota
        state[0] ^= keccakRC[round]
    }
}

// MARK: - SHAKE-256 XOF

/// A streaming SHAKE-256 XOF.
public final class SHAKE256 {
    private var state = [UInt64](repeating: 0, count: 25)
    private var buf = [UInt8](repeating: 0, count: 136)  // rate = 136
    private var bufLen = 0
    private var squeezed = false
    private var squeezeOffset = 0

    private let rate = 136

    public init() {}

    /// Absorb input data. Must be called before any squeeze.
    public func absorb(_ data: [UInt8]) {
        precondition(!squeezed, "Cannot absorb after squeezing")
        var offset = 0
        while offset < data.count {
            let space = rate - bufLen
            let chunk = min(space, data.count - offset)
            for i in 0..<chunk {
                buf[bufLen + i] = data[offset + i]
            }
            bufLen += chunk
            offset += chunk
            if bufLen == rate {
                absorbBlock()
                bufLen = 0
            }
        }
    }

    /// Finalize absorption (pad and switch to squeeze mode).
    public func finalize() {
        guard !squeezed else { return }
        // SHAKE-256 domain separator = 0x1F, then pad10*1
        buf[bufLen] = 0x1F
        for i in (bufLen+1)..<rate {
            buf[i] = 0
        }
        buf[rate - 1] |= 0x80
        absorbBlock()
        bufLen = 0
        squeezed = true
        squeezeOffset = 0  // ready to squeeze from state
    }

    /// Squeeze output bytes.
    public func squeeze(_ count: Int) -> [UInt8] {
        if !squeezed { finalize() }
        var out = [UInt8](repeating: 0, count: count)
        var produced = 0
        while produced < count {
            if squeezeOffset >= rate {
                keccakF1600(&state)
                squeezeOffset = 0
            }
            let avail = rate - squeezeOffset
            let take = min(avail, count - produced)
            // Extract bytes from state
            for i in 0..<take {
                let byteIdx = squeezeOffset + i
                let wordIdx = byteIdx / 8
                let shift = (byteIdx % 8) * 8
                out[produced + i] = UInt8(truncatingIfNeeded: state[wordIdx] >> shift)
            }
            squeezeOffset += take
            produced += take
        }
        return out
    }

    private func absorbBlock() {
        // XOR buf into state (little-endian lanes).
        for i in 0..<(rate / 8) {
            var lane: UInt64 = 0
            for b in 0..<8 {
                lane |= UInt64(buf[i*8 + b]) << (b * 8)
            }
            state[i] ^= lane
        }
        keccakF1600(&state)
    }

    /// One-shot SHAKE-256.
    public static func hash(_ input: [UInt8], outputLength: Int) -> [UInt8] {
        let s = SHAKE256()
        s.absorb(input)
        return s.squeeze(outputLength)
    }
}
