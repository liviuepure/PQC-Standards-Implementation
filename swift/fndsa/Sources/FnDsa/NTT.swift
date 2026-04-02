// NTT.swift — NTT/INTT mod q=12289 for FN-DSA (FIPS 206 / FALCON).
//
// Negacyclic NTT over Z[x]/(x^n+1), n in {512, 1024}.
// Primitive root g=11, psi_n = 11^((Q-1)/(2n)) mod Q.

import Foundation

// MARK: - Modular arithmetic helpers

@inline(__always)
func nttMulModQ(_ a: Int64, _ b: Int64) -> Int32 {
    return Int32(a * b % Int64(Q))
}

@inline(__always)
func nttAddModQ(_ a: Int32, _ b: Int32) -> Int32 {
    let r = a + b
    return r >= Q ? r - Q : r
}

@inline(__always)
func nttSubModQ(_ a: Int32, _ b: Int32) -> Int32 {
    let r = a - b
    return r < 0 ? r + Q : r
}

func nttPow(_ base: Int64, _ exp: Int64) -> Int32 {
    var result: Int64 = 1
    var b = base % Int64(Q)
    if b < 0 { b += Int64(Q) }
    var e = exp
    while e > 0 {
        if e & 1 == 1 {
            result = result * b % Int64(Q)
        }
        e >>= 1
        b = b * b % Int64(Q)
    }
    return Int32(result)
}

func nttBitRev(_ k: Int, _ logn: Int) -> Int {
    var r = 0
    var kk = k
    for _ in 0..<logn {
        r = (r << 1) | (kk & 1)
        kk >>= 1
    }
    return r
}

// MARK: - Zeta table generation

/// Precomputed zeta tables for NTT.
private var zetaTablesInitialized = false
private var nttZetas512 = [Int32](repeating: 0, count: 512)
private var nttZetasInv512 = [Int32](repeating: 0, count: 512)
private var nttZetas1024 = [Int32](repeating: 0, count: 1024)
private var nttZetasInv1024 = [Int32](repeating: 0, count: 1024)

private func initZetaTables() {
    guard !zetaTablesInitialized else { return }

    // psi_512 = 11^((Q-1)/(2*512)) = 11^12 mod Q
    let psi512 = Int64(nttPow(11, Int64((Q - 1) / (2 * 512))))
    for k in 0..<512 {
        let br = nttBitRev(k, 9)
        let z = nttPow(psi512, Int64(br))
        nttZetas512[k] = z
        nttZetasInv512[k] = nttPow(Int64(z), Int64(Q - 2))
    }

    // psi_1024 = 11^((Q-1)/(2*1024)) = 11^6 mod Q
    let psi1024 = Int64(nttPow(11, Int64((Q - 1) / (2 * 1024))))
    for k in 0..<1024 {
        let br = nttBitRev(k, 10)
        let z = nttPow(psi1024, Int64(br))
        nttZetas1024[k] = z
        nttZetasInv1024[k] = nttPow(Int64(z), Int64(Q - 2))
    }

    zetaTablesInitialized = true
}

// MARK: - NTT / INTT

/// Forward negacyclic NTT in-place. n must be 512 or 1024.
/// Input coefficients must be in [0, Q).
func nttForward(_ f: inout [Int32], _ n: Int) {
    initZetaTables()
    let zetas = n == 512 ? nttZetas512 : nttZetas1024

    var k = 0
    var length = n >> 1
    while length >= 1 {
        var start = 0
        while start < n {
            k += 1
            let zeta = Int64(zetas[k])
            for j in start..<(start + length) {
                let t = nttMulModQ(zeta, Int64(f[j + length]))
                f[j + length] = nttSubModQ(f[j], t)
                f[j] = nttAddModQ(f[j], t)
            }
            start += 2 * length
        }
        length >>= 1
    }
}

/// Inverse negacyclic NTT in-place. n must be 512 or 1024.
func nttInverse(_ f: inout [Int32], _ n: Int) {
    initZetaTables()
    let zetasInv = n == 512 ? nttZetasInv512 : nttZetasInv1024
    let nInv = Int64(nttPow(Int64(n), Int64(Q - 2)))

    var k = n
    var length = 1
    while length < n {
        var start = n - 2 * length
        while start >= 0 {
            k -= 1
            let zetaInv = Int64(zetasInv[k])
            for j in start..<(start + length) {
                let t = f[j]
                f[j] = nttAddModQ(t, f[j + length])
                f[j + length] = nttMulModQ(zetaInv, Int64(nttSubModQ(t, f[j + length])))
            }
            start -= 2 * length
        }
        length <<= 1
    }

    // Scale by n^{-1} mod Q.
    for i in 0..<f.count {
        f[i] = nttMulModQ(nInv, Int64(f[i]))
    }
}

// MARK: - Polynomial operations via NTT

/// Multiply two polynomials mod (q, x^n+1) using NTT.
func polyMulNTT(_ a: [Int32], _ b: [Int32], n: Int) -> [Int32] {
    var aNTT = [Int32](repeating: 0, count: n)
    var bNTT = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        aNTT[i] = ((a[i] % Q) + Q) % Q
        bNTT[i] = ((b[i] % Q) + Q) % Q
    }
    nttForward(&aNTT, n)
    nttForward(&bNTT, n)
    var cNTT = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        cNTT[i] = Int32(Int64(aNTT[i]) * Int64(bNTT[i]) % Int64(Q))
    }
    nttInverse(&cNTT, n)
    return cNTT
}

/// Compute polynomial inverse mod (q, x^n+1). Returns nil if not invertible.
func polyInvNTT(_ f: [Int32], n: Int) -> [Int32]? {
    var fNTT = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        fNTT[i] = ((f[i] % Q) + Q) % Q
    }
    nttForward(&fNTT, n)
    for v in fNTT {
        if v == 0 { return nil }
    }
    var inv = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        inv[i] = nttPow(Int64(fNTT[i]), Int64(Q - 2))
    }
    nttInverse(&inv, n)
    return inv
}
