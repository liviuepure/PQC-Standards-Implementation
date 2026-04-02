// Gaussian.swift — Discrete Gaussian sampler for FN-DSA (FIPS 206).
//
// RCDT-based base sampler with sigma0 = 1.8205, plus rejection step for
// arbitrary sigma >= sigma0.

import Foundation
import Security

// MARK: - Secure random bytes

func secureRandomBytes(_ count: Int) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
    return bytes
}

// MARK: - RCDT table

private let sigma0: Double = 1.8205

private struct RCDT72 {
    let hi: UInt8
    let lo: UInt64
}

private let rcdtTable: [RCDT72] = [
    RCDT72(hi: 199, lo: 16610441552002023424),
    RCDT72(hi: 103, lo: 7624082642567692288),
    RCDT72(hi: 42,  lo: 919243735747002368),
    RCDT72(hi: 13,  lo: 3484267233246674944),
    RCDT72(hi: 3,   lo: 2772878652510347264),
    RCDT72(hi: 0,   lo: 10479598105528201216),
    RCDT72(hi: 0,   lo: 1418221736465465344),
    RCDT72(hi: 0,   lo: 143439473028577328),
    RCDT72(hi: 0,   lo: 10810581864167812),
    RCDT72(hi: 0,   lo: 605874652027744),
    RCDT72(hi: 0,   lo: 25212870589170),
    RCDT72(hi: 0,   lo: 778215157694),
    RCDT72(hi: 0,   lo: 17802250993),
    RCDT72(hi: 0,   lo: 301647562),
    RCDT72(hi: 0,   lo: 3784361),
    RCDT72(hi: 0,   lo: 35141),
    RCDT72(hi: 0,   lo: 241),
    RCDT72(hi: 0,   lo: 1),
]

// Branchless comparisons.
@inline(__always)
private func lt64(_ a: UInt64, _ b: UInt64) -> UInt64 {
    return ((~a & b) | (~(a ^ b) & (a &- b))) >> 63
}

@inline(__always)
private func eq8(_ a: UInt8, _ b: UInt8) -> UInt64 {
    let x = UInt64(a) ^ UInt64(b)
    return (x &- 1) >> 63
}

// MARK: - Base Gaussian sampler

/// Sample from D_{Z, sigma0} using the RCDT table.
func sampleBaseGaussian() -> Int {
    let buf = secureRandomBytes(9)
    let sampleLo = buf.withUnsafeBufferPointer { ptr -> UInt64 in
        var v: UInt64 = 0
        for i in 0..<8 {
            v |= UInt64(ptr[i]) << (i * 8)
        }
        return v
    }
    let sampleHi = buf[8]

    var z = 0
    for i in 0..<rcdtTable.count {
        let tHi = rcdtTable[i].hi
        let tLo = rcdtTable[i].lo
        let hiLT = lt64(UInt64(sampleHi), UInt64(tHi))
        let hiEQ = eq8(sampleHi, tHi)
        let loLT = lt64(sampleLo, tLo)
        let lt72 = hiLT | (hiEQ & loLT)
        z += Int(lt72)
    }

    // Sign bit from 1 random byte.
    let signBuf = secureRandomBytes(1)
    let signBit = Int(signBuf[0] & 1)
    let mask = -signBit
    return (z ^ mask) - mask
}

// MARK: - General Gaussian sampler

/// Sample from D_{Z, sigma} using rejection sampling.
func sampleGaussian(sigma: Double) -> Int {
    let sigma2 = sigma * sigma
    let sigma02 = sigma0 * sigma0
    let c = (sigma2 - sigma02) / (2 * sigma2 * sigma02)

    while true {
        let z = sampleBaseGaussian()
        let fz = Double(z)
        let logProb = -fz * fz * c

        // Sample u uniformly in [0, 1) using 53 random bits.
        let ubuf = secureRandomBytes(8)
        var u64: UInt64 = 0
        for i in 0..<8 { u64 |= UInt64(ubuf[i]) << (i * 8) }
        let u53 = u64 >> 11
        let u = Double(u53) / Double(UInt64(1) << 53)

        if u < exp(logProb) {
            return z
        }
    }
}
