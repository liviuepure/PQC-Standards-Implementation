// ML-DSA Hash Functions

import Foundation
import CryptoKit

public enum DsaHash {
    /// H (SHAKE-256, variable output)
    public static func h(_ data: [UInt8], outputLen: Int) -> [UInt8] {
        return KemHash.shake256(data, outputLen: outputLen)
    }

    /// Sample in ball: produce a polynomial c with exactly tau +/-1 coefficients
    public static func sampleInBall(seed: [UInt8], tau: Int) -> [Int32] {
        var shake = Shake256()
        shake.absorb(seed)
        var bytes = shake.squeeze(count: 8)

        var signs: UInt64 = 0
        for i in 0..<8 {
            signs |= UInt64(bytes[i]) << (8 * i)
        }

        var c = [Int32](repeating: 0, count: 256)
        for i in (256 - tau)..<256 {
            var j: Int
            repeat {
                let b = shake.squeeze(count: 1)
                j = Int(b[0])
            } while j > i

            c[i] = c[j]
            c[j] = (signs & 1) == 0 ? 1 : DsaField.q - 1
            signs >>= 1
        }
        return c
    }

    /// ExpandA: generate matrix A from seed rho
    public static func expandA(rho: [UInt8], k: Int, l: Int) -> [[[Int32]]] {
        var a = [[[Int32]]]()
        for r in 0..<k {
            var row = [[Int32]]()
            for s in 0..<l {
                row.append(rejNttPoly(rho: rho, r: UInt8(r), s: UInt8(s)))
            }
            a.append(row)
        }
        return a
    }

    /// Rejection sample NTT polynomial from SHAKE-128
    public static func rejNttPoly(rho: [UInt8], r: UInt8, s: UInt8) -> [Int32] {
        var xof = Shake128()
        xof.absorb(rho + [s, r])
        var coeffs = [Int32]()
        coeffs.reserveCapacity(256)
        while coeffs.count < 256 {
            let bytes = xof.squeeze(count: 3)
            var val = Int32(bytes[0]) | (Int32(bytes[1]) << 8) | (Int32(bytes[2]) << 16)
            val &= 0x7FFFFF  // 23 bits
            if val < DsaField.q {
                coeffs.append(val)
            }
        }
        return Array(coeffs.prefix(256))
    }

    /// ExpandS: sample secret vectors s1, s2
    public static func expandS(rhoPrime: [UInt8], k: Int, l: Int, eta: Int) -> ([[Int32]], [[Int32]]) {
        var s1 = [[Int32]]()
        for r in 0..<l {
            s1.append(sampleEtaPoly(seed: rhoPrime, nonce: UInt16(r), eta: eta))
        }
        var s2 = [[Int32]]()
        for r in 0..<k {
            s2.append(sampleEtaPoly(seed: rhoPrime, nonce: UInt16(l + r), eta: eta))
        }
        return (s1, s2)
    }

    /// Sample polynomial with coefficients in [-eta, eta]
    public static func sampleEtaPoly(seed: [UInt8], nonce: UInt16, eta: Int) -> [Int32] {
        let input = seed + [UInt8(nonce & 0xFF), UInt8(nonce >> 8)]
        let bytes = KemHash.shake256(input, outputLen: eta == 2 ? 128 : 136)
        var coeffs = [Int32](repeating: 0, count: 256)

        if eta == 2 {
            for i in 0..<64 {
                let b = bytes[i]
                for j in 0..<2 {
                    let nibble = (b >> (4 * j)) & 0x0F
                    let t0 = Int32(nibble & 3)
                    let t1 = Int32(nibble >> 2)
                    let idx = 4 * i + 2 * j
                    if idx < 256 {
                        coeffs[idx] = DsaField.reduce(Int64(t0 - t1))
                    }
                    if idx + 1 < 256 {
                        // Re-extract for the next
                    }
                }
            }
            // Simpler: process half-bytes
            var ci = 0
            for i in 0..<128 {
                if ci >= 256 { break }
                let b = bytes[i]
                let lo = b & 0x0F
                let t0 = Int32(lo % 5)
                coeffs[ci] = DsaField.reduce(Int64(t0 - Int32(eta)))
                ci += 1
                if ci >= 256 { break }
                let hi = b >> 4
                let t1 = Int32(hi % 5)
                coeffs[ci] = DsaField.reduce(Int64(t1 - Int32(eta)))
                ci += 1
            }
        } else { // eta == 4
            var ci = 0
            for i in 0..<136 {
                if ci >= 256 { break }
                let b = bytes[i]
                let lo = b & 0x0F
                if lo < 9 {
                    coeffs[ci] = DsaField.reduce(Int64(Int32(lo) - 4))
                    ci += 1
                }
                if ci >= 256 { break }
                let hi = b >> 4
                if hi < 9 {
                    coeffs[ci] = DsaField.reduce(Int64(Int32(hi) - 4))
                    ci += 1
                }
            }
        }
        return coeffs
    }

    /// ExpandMask: sample polynomial with coefficients in [-(gamma1-1), gamma1]
    public static func expandMask(rhoPrime: [UInt8], kappa: UInt16, gamma1: Int32) -> [Int32] {
        let input = rhoPrime + [UInt8(kappa & 0xFF), UInt8(kappa >> 8)]
        let gamma1Bits = gamma1 == (1 << 17) ? 18 : 20
        let byteLen = 256 * gamma1Bits / 8
        let bytes = KemHash.shake256(input, outputLen: byteLen)

        var poly = [Int32](repeating: 0, count: 256)
        if gamma1Bits == 18 {
            // 18 bits per coefficient, 4 coefficients per 9 bytes
            for i in 0..<64 {
                let off = 9 * i
                var vals = [Int32](repeating: 0, count: 4)
                let b0 = Int32(bytes[off]); let b1 = Int32(bytes[off+1])
                let b2 = Int32(bytes[off+2]); let b3 = Int32(bytes[off+3])
                let b4 = Int32(bytes[off+4]); let b5 = Int32(bytes[off+5])
                let b6 = Int32(bytes[off+6]); let b7 = Int32(bytes[off+7])
                let b8 = Int32(bytes[off+8])
                vals[0] = b0 | (b1 << 8) | ((b2 & 0x03) << 16)
                vals[1] = (b2 >> 2) | (b3 << 6) | ((b4 & 0x0F) << 14)
                vals[2] = (b4 >> 4) | (b5 << 4) | ((b6 & 0x3F) << 12)
                vals[3] = (b6 >> 6) | (b7 << 2) | (b8 << 10)
                for j in 0..<4 {
                    vals[j] &= ((1 << 18) - 1)
                    poly[4*i + j] = DsaField.reduce(Int64(gamma1 - vals[j]))
                }
            }
        } else {
            // 20 bits per coefficient, 2 coefficients per 5 bytes
            for i in 0..<128 {
                let off = 5 * (i / 2)
                if i % 2 == 0 {
                    let lo = Int32(bytes[off]) | (Int32(bytes[off+1]) << 8) | ((Int32(bytes[off+2]) & 0x0F) << 16)
                    poly[i] = DsaField.reduce(Int64(gamma1 - (lo & ((1 << 20) - 1))))
                } else {
                    let hi = (Int32(bytes[off+2]) >> 4) | (Int32(bytes[off+3]) << 4) | (Int32(bytes[off+4]) << 12)
                    poly[i] = DsaField.reduce(Int64(gamma1 - (hi & ((1 << 20) - 1))))
                }
            }
        }
        return poly
    }
}
