// ReedSolomon.swift -- Reed-Solomon encoding and decoding over GF(2^8) for HQC.
//
// RS(n1, k) with minimum distance d = n1 - k + 1 = 2*delta + 1.
// The generator polynomial g(x) = prod(x - alpha^i) for i = 1..2*delta.
// alpha = 2, using polynomial 0x11D.

import Foundation

/// Compute the RS generator polynomial.
/// Returns coefficients [g0, g1, ..., g_{2*delta}] where g_{2*delta} = 1.
func rsGeneratorPoly(_ delta: Int) -> [UInt8] {
    let deg = 2 * delta
    var g = [UInt8](repeating: 0, count: deg + 1)
    g[0] = 1 // g(x) = 1

    // Multiply by (x - alpha^i) for i = 1..2*delta
    for i in 1...deg {
        let alphai = gf256Pow(gfGenConst, i)
        var prev: UInt8 = 0
        for j in 0...deg {
            let tmp = g[j]
            g[j] = gf256Mul(g[j], alphai) ^ prev
            prev = tmp
        }
    }

    return g
}

/// Systematic RS encoding.
/// Input: msg of length k bytes.
/// Output: codeword of length n1 bytes (parity || msg).
func rsEncode(_ msg: [UInt8], _ p: HqcParams) -> [UInt8] {
    let k = p.k
    let n1 = p.n1
    let delta = p.delta
    let g = rsGeneratorPoly(delta)
    let parityLen = 2 * delta

    // Linear feedback shift register encoding
    var feedback = [UInt8](repeating: 0, count: parityLen)

    for i in stride(from: k - 1, through: 0, by: -1) {
        let coeff = gf256Add(msg[i], feedback[parityLen - 1])
        for j in stride(from: parityLen - 1, through: 1, by: -1) {
            feedback[j] = gf256Add(feedback[j - 1], gf256Mul(coeff, g[j]))
        }
        feedback[0] = gf256Mul(coeff, g[0])
    }

    // Codeword = [parity bytes] [message bytes]
    var codeword = [UInt8](repeating: 0, count: n1)
    for i in 0..<parityLen { codeword[i] = feedback[i] }
    for i in 0..<k { codeword[parityLen + i] = msg[i] }

    return codeword
}

/// Decode a received RS codeword.
/// Returns (decoded message, success).
func rsDecode(_ received: [UInt8], _ p: HqcParams) -> ([UInt8]?, Bool) {
    let n1 = p.n1
    let k = p.k
    let delta = p.delta

    var r = [UInt8](repeating: 0, count: n1)
    for i in 0..<min(received.count, n1) { r[i] = received[i] }

    // Step 1: Compute syndromes S[1..2*delta]
    var syndromes = [UInt8](repeating: 0, count: 2 * delta + 1)
    var allZero = true
    for i in 1...(2 * delta) {
        let alphai = gf256Pow(gfGenConst, i)
        var s: UInt8 = 0
        for j in stride(from: n1 - 1, through: 0, by: -1) {
            s = gf256Add(gf256Mul(s, alphai), r[j])
        }
        syndromes[i] = s
        if s != 0 { allZero = false }
    }

    if allZero {
        var msg = [UInt8](repeating: 0, count: k)
        for i in 0..<k { msg[i] = r[2 * delta + i] }
        return (msg, true)
    }

    // Step 2: Berlekamp-Massey to find error locator polynomial sigma
    let sigma = berlekampMassey(syndromes, delta)
    var sigDeg = 0
    for i in stride(from: delta, through: 0, by: -1) {
        if sigma[i] != 0 {
            sigDeg = i
            break
        }
    }
    if sigDeg > delta {
        return (nil, false)
    }

    // Step 3: Chien search to find roots
    var errorPositions = [Int]()
    for i in 0..<n1 {
        let alphaInv = gf256Pow(gfGenConst, 255 - i)
        var val: UInt8 = 0
        var alphaPow: UInt8 = 1
        for j in 0...sigDeg {
            val ^= gf256Mul(sigma[j], alphaPow)
            alphaPow = gf256Mul(alphaPow, alphaInv)
        }
        if val == 0 {
            errorPositions.append(i)
        }
    }

    if errorPositions.count != sigDeg {
        return (nil, false)
    }

    // Step 4: Forney's algorithm - compute error values
    // omega(x) = S(x) * sigma(x) mod x^(2*delta+1)
    var omega = [UInt8](repeating: 0, count: 2 * delta + 1)
    for i in 0..<(2 * delta) {
        for j in 0...min(sigDeg, i) {
            omega[i + 1] ^= gf256Mul(sigma[j], syndromes[i + 1 - j])
        }
    }

    // sigma'(x) = formal derivative of sigma
    var sigmaPrime = [UInt8](repeating: 0, count: delta + 1)
    for i in stride(from: 1, through: sigDeg, by: 2) {
        sigmaPrime[i - 1] = sigma[i]
    }

    // Correct errors
    for pos in errorPositions {
        let alphaInvI = gf256Inv(gf256Pow(gfGenConst, pos))

        // Evaluate omega(alpha^(-pos))
        var omegaVal: UInt8 = 0
        var alphaPow: UInt8 = 1
        for j in 0...(2 * delta) {
            omegaVal ^= gf256Mul(omega[j], alphaPow)
            alphaPow = gf256Mul(alphaPow, alphaInvI)
        }

        // Evaluate sigma'(alpha^(-pos))
        var sigPrimeVal: UInt8 = 0
        alphaPow = 1
        for j in 0..<sigmaPrime.count {
            sigPrimeVal ^= gf256Mul(sigmaPrime[j], alphaPow)
            alphaPow = gf256Mul(alphaPow, alphaInvI)
        }

        if sigPrimeVal == 0 {
            return (nil, false)
        }

        // Forney's formula: e_j = X_j * omega(X_j^{-1}) / sigma'(X_j^{-1})
        let xj = gf256Pow(gfGenConst, pos)
        let errorVal = gf256Mul(gf256Mul(xj, omegaVal), gf256Inv(sigPrimeVal))
        r[pos] ^= errorVal
    }

    // Extract message
    var msg = [UInt8](repeating: 0, count: k)
    for i in 0..<k { msg[i] = r[2 * delta + i] }
    return (msg, true)
}

/// Berlekamp-Massey algorithm.
/// Returns the error locator polynomial sigma[0..delta].
private func berlekampMassey(_ syndromes: [UInt8], _ delta: Int) -> [UInt8] {
    let n = 2 * delta
    var sigma = [UInt8](repeating: 0, count: delta + 2)
    sigma[0] = 1
    var b = [UInt8](repeating: 0, count: delta + 2)
    b[0] = 1
    var L = 0
    var m = 1
    var deltaN: UInt8 = 1

    for kk in 1...n {
        // Compute discrepancy d
        var d = syndromes[kk]
        if L > 0 {
            for i in 1...L {
                d ^= gf256Mul(sigma[i], syndromes[kk - i])
            }
        }

        if d == 0 {
            m += 1
            continue
        }

        // t(x) = sigma(x) - (d/deltaN) * x^m * b(x)
        var t = [UInt8](repeating: 0, count: delta + 2)
        for i in 0..<sigma.count { t[i] = sigma[i] }
        let coeff = gf256Mul(d, gf256Inv(deltaN))
        let upperBound = delta + 1 - m
        if upperBound >= 0 {
            for i in 0...upperBound {
                if i + m <= delta + 1 {
                    t[i + m] ^= gf256Mul(coeff, b[i])
                }
            }
        }

        if 2 * L < kk {
            for i in 0..<sigma.count { b[i] = sigma[i] }
            L = kk - L
            deltaN = d
            m = 1
        } else {
            m += 1
        }
        for i in 0..<t.count { sigma[i] = t[i] }
    }

    return Array(sigma[0..<(delta + 1)])
}
