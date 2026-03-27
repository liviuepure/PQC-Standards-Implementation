// ML-KEM Hash Functions using CryptoKit + custom Keccak for SHAKE
import Foundation
import CryptoKit

// MARK: - Keccak-f[1600] Sponge (pure Swift)

public struct KeccakState {
    var state: [UInt64] = [UInt64](repeating: 0, count: 25)

    static let roundConstants: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    static let rotationOffsets: [Int] = [
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ]

    static let piIndices: [Int] = [
         0, 10, 20,  5, 15,
        16,  1, 11, 21,  6,
         7, 17,  2, 12, 22,
        23,  8, 18,  3, 13,
        14, 24,  9, 19,  4,
    ]

    mutating func permute() {
        for round in 0..<24 {
            // Theta
            var c = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 {
                c[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
            }
            var d = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 {
                d[x] = c[(x+4)%5] ^ rotateLeft(c[(x+1)%5], by: 1)
            }
            for x in 0..<5 {
                for y in 0..<5 {
                    state[x + 5*y] ^= d[x]
                }
            }

            // Rho + Pi
            var b = [UInt64](repeating: 0, count: 25)
            for i in 0..<25 {
                b[KeccakState.piIndices[i]] = rotateLeft(state[i], by: KeccakState.rotationOffsets[i])
            }

            // Chi
            for y in 0..<5 {
                for x in 0..<5 {
                    state[x + 5*y] = b[x + 5*y] ^ ((~b[(x+1)%5 + 5*y]) & b[(x+2)%5 + 5*y])
                }
            }

            // Iota
            state[0] ^= KeccakState.roundConstants[round]
        }
    }

    @inline(__always)
    func rotateLeft(_ value: UInt64, by: Int) -> UInt64 {
        let n = by & 63
        return (value << n) | (value >> (64 - n))
    }
}

public struct Shake128 {
    private var keccak = KeccakState()
    private var absorbed = 0
    private let rate = 168 // bytes (1344 bits)
    private var buffer = [UInt8]()
    private var squeezed = false
    private var squeezeBuffer = [UInt8]()
    private var squeezePos = 0

    public init() {}

    public mutating func absorb(_ data: [UInt8]) {
        buffer.append(contentsOf: data)
    }

    public mutating func finalize() {
        // Pad: append 0x1F, then zeros, then 0x80 in last byte of rate block
        let r = rate
        buffer.append(0x1F)
        while buffer.count % r != 0 {
            buffer.append(0x00)
        }
        buffer[buffer.count - 1] |= 0x80

        // Absorb all blocks
        var offset = 0
        while offset < buffer.count {
            for i in 0..<(r / 8) {
                let byteOffset = offset + i * 8
                var lane: UInt64 = 0
                for b in 0..<8 {
                    lane |= UInt64(buffer[byteOffset + b]) << (b * 8)
                }
                keccak.state[i] ^= lane
            }
            keccak.permute()
            offset += r
        }
        squeezed = true
        squeezeBuffer = []
        squeezePos = 0
    }

    public mutating func squeeze(count: Int) -> [UInt8] {
        if !squeezed { finalize() }

        var output = [UInt8]()
        output.reserveCapacity(count)

        while output.count < count {
            if squeezePos >= squeezeBuffer.count {
                // Extract rate bytes
                squeezeBuffer = [UInt8](repeating: 0, count: rate)
                for i in 0..<(rate / 8) {
                    let lane = keccak.state[i]
                    for b in 0..<8 {
                        squeezeBuffer[i * 8 + b] = UInt8((lane >> (b * 8)) & 0xFF)
                    }
                }
                squeezePos = 0
                keccak.permute()
            }
            let available = min(squeezeBuffer.count - squeezePos, count - output.count)
            output.append(contentsOf: squeezeBuffer[squeezePos..<(squeezePos + available)])
            squeezePos += available
        }
        return output
    }
}

public struct Shake256 {
    private var keccak = KeccakState()
    private let rate = 136 // bytes (1088 bits)
    private var buffer = [UInt8]()
    private var squeezed = false
    private var squeezeBuffer = [UInt8]()
    private var squeezePos = 0

    public init() {}

    public mutating func absorb(_ data: [UInt8]) {
        buffer.append(contentsOf: data)
    }

    public mutating func finalize() {
        let r = rate
        buffer.append(0x1F)
        while buffer.count % r != 0 {
            buffer.append(0x00)
        }
        buffer[buffer.count - 1] |= 0x80

        var offset = 0
        while offset < buffer.count {
            for i in 0..<(r / 8) {
                let byteOffset = offset + i * 8
                var lane: UInt64 = 0
                for b in 0..<8 {
                    lane |= UInt64(buffer[byteOffset + b]) << (b * 8)
                }
                keccak.state[i] ^= lane
            }
            keccak.permute()
            offset += r
        }
        squeezed = true
        squeezeBuffer = []
        squeezePos = 0
    }

    public mutating func squeeze(count: Int) -> [UInt8] {
        if !squeezed { finalize() }

        var output = [UInt8]()
        output.reserveCapacity(count)

        while output.count < count {
            if squeezePos >= squeezeBuffer.count {
                squeezeBuffer = [UInt8](repeating: 0, count: rate)
                for i in 0..<(rate / 8) {
                    let lane = keccak.state[i]
                    for b in 0..<8 {
                        squeezeBuffer[i * 8 + b] = UInt8((lane >> (b * 8)) & 0xFF)
                    }
                }
                squeezePos = 0
                keccak.permute()
            }
            let available = min(squeezeBuffer.count - squeezePos, count - output.count)
            output.append(contentsOf: squeezeBuffer[squeezePos..<(squeezePos + available)])
            squeezePos += available
        }
        return output
    }
}

// MARK: - Convenience Hash Functions

public enum KemHash {
    /// SHA3-256 via Keccak (rate=136, suffix=0x06)
    public static func sha3_256(_ data: [UInt8]) -> [UInt8] {
        var keccak = KeccakState()
        let rate = 136
        var buf = data
        buf.append(0x06)
        while buf.count % rate != 0 {
            buf.append(0x00)
        }
        buf[buf.count - 1] |= 0x80

        var offset = 0
        while offset < buf.count {
            for i in 0..<(rate / 8) {
                let byteOffset = offset + i * 8
                var lane: UInt64 = 0
                for b in 0..<8 {
                    lane |= UInt64(buf[byteOffset + b]) << (b * 8)
                }
                keccak.state[i] ^= lane
            }
            keccak.permute()
            offset += rate
        }

        var output = [UInt8](repeating: 0, count: 32)
        for i in 0..<4 {
            let lane = keccak.state[i]
            for b in 0..<8 {
                output[i * 8 + b] = UInt8((lane >> (b * 8)) & 0xFF)
            }
        }
        return output
    }

    /// SHA3-512 via Keccak (rate=72, suffix=0x06)
    public static func sha3_512(_ data: [UInt8]) -> [UInt8] {
        var keccak = KeccakState()
        let rate = 72
        var buf = data
        buf.append(0x06)
        while buf.count % rate != 0 {
            buf.append(0x00)
        }
        buf[buf.count - 1] |= 0x80

        var offset = 0
        while offset < buf.count {
            for i in 0..<(rate / 8) {
                let byteOffset = offset + i * 8
                var lane: UInt64 = 0
                for b in 0..<8 {
                    lane |= UInt64(buf[byteOffset + b]) << (b * 8)
                }
                keccak.state[i] ^= lane
            }
            keccak.permute()
            offset += rate
        }

        var output = [UInt8](repeating: 0, count: 64)
        for i in 0..<8 {
            let lane = keccak.state[i]
            for b in 0..<8 {
                output[i * 8 + b] = UInt8((lane >> (b * 8)) & 0xFF)
            }
        }
        return output
    }

    /// SHA-256 using CryptoKit
    public static func sha256(_ data: [UInt8]) -> [UInt8] {
        let digest = SHA256.hash(data: Data(data))
        return Array(digest)
    }

    /// SHA-512 using CryptoKit
    public static func sha512(_ data: [UInt8]) -> [UInt8] {
        let digest = SHA512.hash(data: Data(data))
        return Array(digest)
    }

    /// SHAKE-128 convenience
    public static func shake128(_ data: [UInt8], outputLen: Int) -> [UInt8] {
        var shake = Shake128()
        shake.absorb(data)
        return shake.squeeze(count: outputLen)
    }

    /// SHAKE-256 convenience
    public static func shake256(_ data: [UInt8], outputLen: Int) -> [UInt8] {
        var shake = Shake256()
        shake.absorb(data)
        return shake.squeeze(count: outputLen)
    }

    /// G function: SHA3-512
    public static func g(_ data: [UInt8]) -> ([UInt8], [UInt8]) {
        let hash = sha3_512(data)
        return (Array(hash[0..<32]), Array(hash[32..<64]))
    }

    /// H function: SHA3-256
    public static func h(_ data: [UInt8]) -> [UInt8] {
        return sha3_256(data)
    }

    /// J function: SHAKE-256 with 32-byte output
    public static func j(_ data: [UInt8]) -> [UInt8] {
        return shake256(data, outputLen: 32)
    }

    /// PRF: SHAKE-256 with variable output
    public static func prf(_ s: [UInt8], b: UInt8, eta: Int) -> [UInt8] {
        return shake256(s + [b], outputLen: 64 * eta)
    }

    /// XOF: SHAKE-128 streaming
    public static func xof(_ rho: [UInt8], i: UInt8, j: UInt8) -> Shake128 {
        var shake = Shake128()
        shake.absorb(rho + [i, j])
        return shake
    }
}
