// FFT.swift — Complex FFT/IFFT/SplitFFT/MergeFFT for FN-DSA (FIPS 206 / FALCON).
//
// These operate over C[x]/(x^n+1), evaluating polynomials at the 2n-th
// primitive roots of unity.

import Foundation

// MARK: - Complex64

struct Complex64 {
    var re: Double
    var im: Double

    init(_ re: Double, _ im: Double) { self.re = re; self.im = im }
    init(_ re: Double) { self.re = re; self.im = 0 }

    static func + (lhs: Complex64, rhs: Complex64) -> Complex64 {
        Complex64(lhs.re + rhs.re, lhs.im + rhs.im)
    }
    static func - (lhs: Complex64, rhs: Complex64) -> Complex64 {
        Complex64(lhs.re - rhs.re, lhs.im - rhs.im)
    }
    static func * (lhs: Complex64, rhs: Complex64) -> Complex64 {
        Complex64(lhs.re * rhs.re - lhs.im * rhs.im,
                  lhs.re * rhs.im + lhs.im * rhs.re)
    }
    static func / (lhs: Complex64, rhs: Complex64) -> Complex64 {
        let d = rhs.re * rhs.re + rhs.im * rhs.im
        return Complex64((lhs.re * rhs.re + lhs.im * rhs.im) / d,
                         (lhs.im * rhs.re - lhs.re * rhs.im) / d)
    }
    static func * (lhs: Double, rhs: Complex64) -> Complex64 {
        Complex64(lhs * rhs.re, lhs * rhs.im)
    }

    var conjugate: Complex64 { Complex64(re, -im) }
    var normSq: Double { re * re + im * im }
}

// MARK: - Helper

private func fftLogN(_ n: Int) -> Int {
    var logn = 0
    var t = n
    while t > 1 { t >>= 1; logn += 1 }
    return logn
}

private func fftBitRev(_ k: Int, _ logn: Int) -> Int {
    var r = 0
    var kk = k
    for _ in 0..<logn {
        r = (r << 1) | (kk & 1)
        kk >>= 1
    }
    return r
}

/// exp(i * angle) as Complex64.
private func cexp(_ angle: Double) -> Complex64 {
    Complex64(cos(angle), sin(angle))
}

// MARK: - FFT / IFFT

/// In-place forward negacyclic complex FFT over C[x]/(x^n+1).
func fftForward(_ f: inout [Complex64], _ n: Int) {
    let logn = fftLogN(n)
    var k = 0
    var length = n >> 1
    while length >= 1 {
        var start = 0
        while start < n {
            k += 1
            let brk = fftBitRev(k, logn)
            let w = cexp(Double.pi * Double(brk) / Double(n))
            for j in start..<(start + length) {
                let t = w * f[j + length]
                f[j + length] = f[j] - t
                f[j] = f[j] + t
            }
            start += 2 * length
        }
        length >>= 1
    }
}

/// In-place inverse negacyclic complex FFT. Result scaled by 1/n.
func fftInverse(_ f: inout [Complex64], _ n: Int) {
    let logn = fftLogN(n)
    var k = n
    var length = 1
    while length < n {
        var start = n - 2 * length
        while start >= 0 {
            k -= 1
            let brk = fftBitRev(k, logn)
            let wInv = cexp(-Double.pi * Double(brk) / Double(n))
            for j in start..<(start + length) {
                let t = f[j]
                f[j] = t + f[j + length]
                f[j + length] = wInv * (t - f[j + length])
            }
            start -= 2 * length
        }
        length <<= 1
    }
    let invN = 1.0 / Double(n)
    for i in 0..<n {
        f[i] = Complex64(f[i].re * invN, f[i].im * invN)
    }
}

/// Split an n-element FFT-domain polynomial into two (n/2)-element ones.
func splitFFT(_ f: [Complex64], _ n: Int) -> (f0: [Complex64], f1: [Complex64]) {
    let logn = fftLogN(n)
    let h = n / 2
    var f0 = [Complex64](repeating: Complex64(0), count: h)
    var f1 = [Complex64](repeating: Complex64(0), count: h)
    for k in 0..<h {
        let j = fftBitRev(k, logn - 1)
        let omegaJ = cexp(Double.pi * Double(2 * j + 1) / Double(n))
        let a = f[2 * k]
        let b = f[2 * k + 1]
        f0[k] = 0.5 * (a + b)
        f1[k] = (a - b) / (2.0 * omegaJ)
    }
    return (f0, f1)
}

/// Merge two (n/2)-element FFT-domain polynomials into one n-element one.
func mergeFFT(_ f0: [Complex64], _ f1: [Complex64], _ n: Int) -> [Complex64] {
    let logn = fftLogN(n)
    let h = n / 2
    var f = [Complex64](repeating: Complex64(0), count: n)
    for k in 0..<h {
        let j = fftBitRev(k, logn - 1)
        let omegaJ = cexp(Double.pi * Double(2 * j + 1) / Double(n))
        let t = omegaJ * f1[k]
        f[2 * k] = f0[k] + t
        f[2 * k + 1] = f0[k] - t
    }
    return f
}
