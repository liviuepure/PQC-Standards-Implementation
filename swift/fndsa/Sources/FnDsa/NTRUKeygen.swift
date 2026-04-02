// NTRUKeygen.swift — NTRU key generation for FN-DSA (FIPS 206).
//
// Recursive field-norm solver using BigInt for exact arithmetic,
// with Babai reduction using fixed-point BigInt FFT for high precision.

import Foundation
import BigInt

// MARK: - NTRU Keygen

func ntruKeyGen(_ p: Params) -> (f: [Int32], g: [Int32], F: [Int32], G: [Int32])? {
    let n = p.n
    let sigma = 1.17 * (Double(Q) / Double(2 * n)).squareRoot()

    for _ in 0..<1000 {
        var fCoeffs = [Int32](repeating: 0, count: n)
        var gCoeffs = [Int32](repeating: 0, count: n)
        for i in 0..<n {
            fCoeffs[i] = Int32(sampleGaussian(sigma: sigma))
            gCoeffs[i] = Int32(sampleGaussian(sigma: sigma))
        }

        var xorSum = 0
        for v in fCoeffs { xorSum ^= Int(v & 1) }
        if xorSum == 0 { continue }

        var fNTT = [Int32](repeating: 0, count: n)
        for i in 0..<n { fNTT[i] = ((fCoeffs[i] % Q) + Q) % Q }
        nttForward(&fNTT, n)
        if fNTT.contains(0) { continue }

        var normSqVal: Double = 0
        for v in fCoeffs { normSqVal += Double(v) * Double(v) }
        for v in gCoeffs { normSqVal += Double(v) * Double(v) }
        if normSqVal > 1.17 * 1.17 * Double(Q) * Double(n) { continue }

        guard let (FCoeffs, GCoeffs) = ntruSolve(n, fCoeffs, gCoeffs) else { continue }
        if !verifyNTRU(fCoeffs, gCoeffs, FCoeffs, GCoeffs, n) { continue }

        return (fCoeffs, gCoeffs, FCoeffs, GCoeffs)
    }
    return nil
}

func ntruPublicKey(_ f: [Int32], _ g: [Int32], _ p: Params) -> [Int32] {
    let n = p.n
    var fNTT = [Int32](repeating: 0, count: n)
    var gNTT = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        fNTT[i] = ((f[i] % Q) + Q) % Q
        gNTT[i] = ((g[i] % Q) + Q) % Q
    }
    nttForward(&fNTT, n)
    nttForward(&gNTT, n)
    var hNTT = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        let fInv = nttPow(Int64(fNTT[i]), Int64(Q - 2))
        hNTT[i] = Int32(Int64(gNTT[i]) * Int64(fInv) % Int64(Q))
    }
    nttInverse(&hNTT, n)
    return hNTT
}

// MARK: - Verification

private func verifyNTRU(_ f: [Int32], _ g: [Int32], _ F: [Int32], _ G: [Int32], _ n: Int) -> Bool {
    let fG = polyMulIntZ(f, G, n)
    let gF = polyMulIntZ(g, F, n)
    if fG[0] - gF[0] != Int64(Q) { return false }
    for i in 1..<n { if fG[i] - gF[i] != 0 { return false } }
    return true
}

private func polyMulIntZ(_ a: [Int32], _ b: [Int32], _ n: Int) -> [Int64] {
    var c = [Int64](repeating: 0, count: n)
    for i in 0..<n {
        let ai = Int64(a[i])
        for j in 0..<n {
            let prod = ai * Int64(b[j])
            let idx = i + j
            if idx < n { c[idx] += prod } else { c[idx - n] -= prod }
        }
    }
    return c
}

// MARK: - NTRU Solver

private func ntruSolve(_ n: Int, _ f: [Int32], _ g: [Int32]) -> (F: [Int32], G: [Int32])? {
    let fBig = f.map { BigInt($0) }
    let gBig = g.map { BigInt($0) }
    guard let (FBig, GBig) = ntruSolveBig(n, fBig, gBig) else { return nil }
    var Fout = [Int32](repeating: 0, count: n)
    var Gout = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        guard let fv = Int32(exactly: FBig[i]), let gv = Int32(exactly: GBig[i]) else { return nil }
        Fout[i] = fv; Gout[i] = gv
    }
    return (Fout, Gout)
}

private func ntruSolveBig(_ n: Int, _ fBig: [BigInt], _ gBig: [BigInt]) -> (F: [BigInt], G: [BigInt])? {
    if n == 1 {
        let (gcdVal, u, v) = extGCD(fBig[0], gBig[0])
        let qBig = BigInt(Q)
        guard qBig % gcdVal == 0 else { return nil }
        let scale = qBig / gcdVal
        return ([-(v * scale)], [u * scale])
    }

    let fNorm = fieldNormBig(fBig, n)
    let gNorm = fieldNormBig(gBig, n)
    guard let (Fp, Gp) = ntruSolveBig(n / 2, fNorm, gNorm) else { return nil }

    var (FLifted, GLifted) = liftBig(Fp, Gp, fBig, gBig, n)
    dbg("  level n=\(n): after lift FBits=\(maxBitLen(FLifted))")

    // Babai reduction (2 rounds).
    for round in 0..<2 {
        let k = babaiReduce(FLifted, GLifted, fBig, gBig, n)
        dbg("  level n=\(n) round=\(round): kBits=\(maxBitLen(k))")
        let kf = polyMulBig(k, fBig, n)
        let kg = polyMulBig(k, gBig, n)
        for i in 0..<n { FLifted[i] -= kf[i]; GLifted[i] -= kg[i] }
        dbg("  level n=\(n) round=\(round): after reduce FBits=\(maxBitLen(FLifted))")
    }

    return (FLifted, GLifted)
}

// MARK: - BigInt polynomial helpers

private func polyMulBig(_ a: [BigInt], _ b: [BigInt], _ n: Int) -> [BigInt] {
    let maxBitsA = maxBitLen(a)
    let maxBitsB = maxBitLen(b)
    let logn = 64 - n.leadingZeroBitCount
    if maxBitsA + maxBitsB + logn <= 62 {
        return polyMulInt64(a, b, n)
    }
    var c = [BigInt](repeating: 0, count: n)
    for i in 0..<n {
        let ai = a[i]; if ai == 0 { continue }
        for j in 0..<n {
            let bj = b[j]; if bj == 0 { continue }
            let idx = i + j; let prod = ai * bj
            if idx < n { c[idx] += prod } else { c[idx - n] -= prod }
        }
    }
    return c
}

private func polyMulInt64(_ a: [BigInt], _ b: [BigInt], _ n: Int) -> [BigInt] {
    let a64 = a.map { Int64($0) }
    let b64 = b.map { Int64($0) }
    var c = [Int64](repeating: 0, count: n)
    for i in 0..<n {
        let ai = a64[i]; if ai == 0 { continue }
        for j in 0..<n {
            let bj = b64[j]; if bj == 0 { continue }
            let idx = i + j; let prod = ai * bj
            if idx < n { c[idx] += prod } else { c[idx - n] -= prod }
        }
    }
    return c.map { BigInt($0) }
}

private func fieldNormBig(_ f: [BigInt], _ n: Int) -> [BigInt] {
    let h = n / 2
    let f0 = (0..<h).map { f[2 * $0] }
    let f1 = (0..<h).map { f[2 * $0 + 1] }
    let f0sq = polyMulBig(f0, f0, h)
    let f1sq = polyMulBig(f1, f1, h)
    var result = [BigInt](repeating: 0, count: h)
    result[0] = f0sq[0] + f1sq[h - 1]
    for i in 1..<h { result[i] = f0sq[i] - f1sq[i - 1] }
    return result
}

private func towerConjugateBig(_ f: [BigInt]) -> [BigInt] {
    (0..<f.count).map { $0 % 2 == 0 ? f[$0] : -f[$0] }
}

private func liftBig(_ Fp: [BigInt], _ Gp: [BigInt], _ f: [BigInt], _ g: [BigInt], _ n: Int) -> ([BigInt], [BigInt]) {
    let h = n / 2
    var FpLift = [BigInt](repeating: 0, count: n)
    var GpLift = [BigInt](repeating: 0, count: n)
    for i in 0..<h { FpLift[2*i] = Fp[i]; GpLift[2*i] = Gp[i] }
    return (polyMulBig(towerConjugateBig(g), FpLift, n),
            polyMulBig(towerConjugateBig(f), GpLift, n))
}

private func maxBitLen(_ vs: [BigInt]) -> Int {
    vs.reduce(0) { max($0, $1.bitWidth) }
}

// MARK: - Extended GCD

private func extGCD(_ a: BigInt, _ b: BigInt) -> (BigInt, BigInt, BigInt) {
    if b == 0 { return (a < 0 ? -a : a, a < 0 ? -1 : 1, 0) }
    var (oldR, r) = (a, b)
    var (oldS, s) = (BigInt(1), BigInt(0))
    var (oldT, t) = (BigInt(0), BigInt(1))
    while r != 0 {
        let (q, rem) = oldR.quotientAndRemainder(dividingBy: r)
        (oldR, r) = (r, rem); (oldS, s) = (s, oldS - q * s); (oldT, t) = (t, oldT - q * t)
    }
    if oldR < 0 { return (-oldR, -oldS, -oldT) }
    return (oldR, oldS, oldT)
}

// MARK: - Babai reduction

private func babaiReduce(_ F: [BigInt], _ G: [BigInt], _ f: [BigInt], _ g: [BigInt], _ n: Int) -> [BigInt] {
    let maxAll = max(maxBitLen(f), maxBitLen(g), maxBitLen(F), maxBitLen(G))
    if maxAll <= 50 {
        return babaiFloat64(F, G, f, g, n)
    }
    return babaiViaAdjoint(F, G, f, g, n)
}

/// Babai via adjoint: compute N = F*f* + G*g* and D = f*f* + g*g* exactly,
/// then divide N/D using float64 FFT (shifts cancel since both are in same ring).
private func babaiViaAdjoint(_ F: [BigInt], _ G: [BigInt], _ f: [BigInt], _ g: [BigInt], _ n: Int) -> [BigInt] {
    // Ring adjoint: f*[0] = f[0], f*[i] = -f[n-i]
    var fAdj = [BigInt](repeating: 0, count: n)
    var gAdj = [BigInt](repeating: 0, count: n)
    fAdj[0] = f[0]; gAdj[0] = g[0]
    for i in 1..<n { fAdj[i] = -f[n-i]; gAdj[i] = -g[n-i] }

    // N = F*f* + G*g* (exact BigInt multiplication)
    let Ff = polyMulBig(F, fAdj, n)
    let Gg = polyMulBig(G, gAdj, n)
    var N = [BigInt](repeating: 0, count: n)
    for i in 0..<n { N[i] = Ff[i] + Gg[i] }

    // D = f*f* + g*g* (exact)
    let ff = polyMulBig(f, fAdj, n)
    let gg = polyMulBig(g, gAdj, n)
    var D = [BigInt](repeating: 0, count: n)
    for i in 0..<n { D[i] = ff[i] + gg[i] }

    // k = round(N / D) in the polynomial ring.
    // D is fixed; iterate on N, extracting ~targetBits of k per iteration.
    let logn = 64 - n.leadingZeroBitCount
    let targetBits = max(5, (50 - 2 * logn) / 2)
    let maxD = maxBitLen(D)
    let dShift = max(0, maxD - targetBits)

    // Precompute shifted D FFT (same for all iterations).
    var DC = D.map { v -> Complex64 in
        let sv = dShift == 0 ? v : (v < 0 ? -((-v) >> dShift) : v >> dShift)
        return Complex64(Double(sv))
    }
    fftForward(&DC, n)

    var kTotal = [BigInt](repeating: 0, count: n)
    var Ncur = N

    for _ in 0..<500 {
        let curBits = maxBitLen(Ncur)
        if curBits <= 10 { break }

        let nShift = max(0, curBits - targetBits)
        let kShiftCorr = nShift - dShift

        var NC = Ncur.map { v -> Complex64 in
            let sv = nShift == 0 ? v : (v < 0 ? -((-v) >> nShift) : v >> nShift)
            return Complex64(Double(sv))
        }
        fftForward(&NC, n)

        var kC = [Complex64](repeating: Complex64(0), count: n)
        for j in 0..<n {
            let dm = DC[j].normSq
            if dm != 0 && NC[j].re.isFinite && NC[j].im.isFinite {
                kC[j] = NC[j] / DC[j]
            }
        }
        fftInverse(&kC, n)

        var kRound = [BigInt](repeating: 0, count: n)
        var anyNonzero = false
        for i in 0..<n {
            guard kC[i].re.isFinite else { continue }
            var kv = BigInt(Int64(kC[i].re.rounded()))
            if kv == 0 { continue }
            if kShiftCorr > 0 { kv <<= kShiftCorr }
            else if kShiftCorr < 0 { kv >>= -kShiftCorr }
            kTotal[i] += kv; kRound[i] = kv; anyNonzero = true
        }
        if !anyNonzero { break }

        // N -= k * D (to get the residual for the next iteration)
        let kD = polyMulBig(kRound, D, n)
        for i in 0..<n { Ncur[i] -= kD[i] }
    }

    return kTotal
}

/// Exact Babai for n=1 or n=2 using BigInt rational arithmetic.
private func babaiExact2(_ F: [BigInt], _ G: [BigInt], _ f: [BigInt], _ g: [BigInt], _ n: Int) -> [BigInt] {
    if n == 1 {
        let num = F[0] * f[0] + G[0] * g[0]
        let den = f[0] * f[0] + g[0] * g[0]
        return [roundDiv(num, den)]
    }
    // n == 2: The FFT of [a,b] at n=2 gives [a+b*i, a-b*i].
    // k = IFFT((F_fft*conj(f_fft) + G_fft*conj(g_fft)) / (|f_fft|^2 + |g_fft|^2))
    //
    // For n=2:
    // f_fft[0] = f0 + f1*i, f_fft[1] = f0 - f1*i
    // F_fft[0] = F0 + F1*i, F_fft[1] = F0 - F1*i
    //
    // num_fft[j] = F_fft[j]*conj(f_fft[j]) + G_fft[j]*conj(g_fft[j])
    // den_fft[j] = |f_fft[j]|^2 + |g_fft[j]|^2
    //
    // Since f_fft[1] = conj(f_fft[0]) for real inputs, and den_fft[0] == den_fft[1]:
    // den = f0^2 + f1^2 + g0^2 + g1^2
    //
    // num_fft[0] = (F0+F1i)(f0-f1i) + (G0+G1i)(g0-g1i)
    //            = (F0f0+F1f1) + (F1f0-F0f1)i + (G0g0+G1g1) + (G1g0-G0g1)i
    // num_re0 = F0f0 + F1f1 + G0g0 + G1g1
    // num_im0 = F1f0 - F0f1 + G1g0 - G0g1
    //
    // k_fft[0] = (num_re0 + num_im0*i) / den
    // k_fft[1] = conj(k_fft[0]) (because inputs are real)
    //
    // IFFT: k[0] = Re(k_fft[0] + k_fft[1]) / 2 = Re(k_fft[0])  (Re part already divided by n=2)
    //        Actually IFFT([a,b], n=2) = [(a+b)/2, (a-b)/(2i)]
    //        k_fft[0] + k_fft[1] = 2*Re(k_fft[0])
    //        k[0] = Re(k_fft[0])
    //        k_fft[0] - k_fft[1] = 2i*Im(k_fft[0])
    //        k[1] = Im(k_fft[0]) / i = Im(k_fft[0]) (but IFFT divides by n=2)
    //
    // Wait, let me redo: IFFT for n=2 with our specific butterfly structure.
    // Our FFT: k=0, length=1. One butterfly at k=1:
    //   w = exp(i*pi*bitrev(1,1)/2) = exp(i*pi/2) = i
    //   FFT([a,b]) = [a + i*b, a - i*b]
    //
    // Our IFFT: reverses this and divides by n.
    //   k=2, length=1: start=0
    //     k=1, w_inv = exp(-i*pi/2) = -i
    //     t = a
    //     a = t + b
    //     b = -i * (t - b)
    //   Then divide by 2.
    //
    // If k_fft = [x, y]:
    //   a = x + y
    //   b = -i * (x - y)
    //   k[0] = (x + y) / 2
    //   k[1] = -i * (x - y) / 2
    //
    // Since k_fft[1] = conj(k_fft[0]):
    //   x + y = k_fft[0] + conj(k_fft[0]) = 2*Re(k_fft[0])
    //   x - y = k_fft[0] - conj(k_fft[0]) = 2i*Im(k_fft[0])
    //   k[0] = Re(k_fft[0])
    //   k[1] = -i * 2i * Im(k_fft[0]) / 2 = Im(k_fft[0])
    //
    // So: k[0] = round(num_re0 / den), k[1] = round(num_im0 / den)

    let (f0, f1) = (f[0], f[1])
    let (g0, g1) = (g[0], g[1])
    let (F0, F1) = (F[0], F[1])
    let (G0, G1) = (G[0], G[1])

    let den = f0*f0 + f1*f1 + g0*g0 + g1*g1
    let numRe = F0*f0 + F1*f1 + G0*g0 + G1*g1
    let numIm = F1*f0 - F0*f1 + G1*g0 - G0*g1

    return [roundDiv(numRe, den), roundDiv(numIm, den)]
}

/// Float64 Babai when all coefficients fit.
private func babaiFloat64(_ F: [BigInt], _ G: [BigInt], _ f: [BigInt], _ g: [BigInt], _ n: Int) -> [BigInt] {
    var fC = f.map { Complex64(Double($0)) }
    var gC = g.map { Complex64(Double($0)) }
    var FC = F.map { Complex64(Double($0)) }
    var GC = G.map { Complex64(Double($0)) }
    fftForward(&fC, n); fftForward(&gC, n); fftForward(&FC, n); fftForward(&GC, n)
    var kC = [Complex64](repeating: Complex64(0), count: n)
    for i in 0..<n {
        let d = fC[i].normSq + gC[i].normSq
        if d != 0 {
            let num = FC[i] * fC[i].conjugate + GC[i] * gC[i].conjugate
            kC[i] = Complex64(num.re / d, num.im / d)
        }
    }
    fftInverse(&kC, n)
    return kC.map { BigInt(Int64($0.re.rounded())) }
}

/// Babai for large coefficients using iterative float64 FFT with separate shifts.
/// Each iteration reduces F, G by ~20 bits. Iterates until convergence.
private func babaiBigIntFFT(_ F: [BigInt], _ G: [BigInt], _ f: [BigInt], _ g: [BigInt], _ n: Int) -> [BigInt] {
    let logn = 64 - n.leadingZeroBitCount
    // Each input to FFT should be at most targetBits so that after FFT (logn levels)
    // and product (two FFT values), the result fits in float64.
    let targetBits = max(5, (50 - 2 * logn) / 2)

    // Precompute shifted f, g FFTs (same for all iterations).
    let fgBits = max(maxBitLen(f), maxBitLen(g))
    let fgShift = max(0, fgBits - targetBits)

    var fC = f.map { v -> Complex64 in
        let sv = fgShift == 0 ? v : (v < 0 ? -((-v) >> fgShift) : v >> fgShift)
        return Complex64(Double(sv))
    }
    var gC = g.map { v -> Complex64 in
        let sv = fgShift == 0 ? v : (v < 0 ? -((-v) >> fgShift) : v >> fgShift)
        return Complex64(Double(sv))
    }
    fftForward(&fC, n); fftForward(&gC, n)

    var denomArr = [Double](repeating: 0, count: n)
    for j in 0..<n { denomArr[j] = fC[j].normSq + gC[j].normSq }

    var kTotal = [BigInt](repeating: 0, count: n)
    var Fcur = F; var Gcur = G

    for _ in 0..<500 {
        let FGBits = max(maxBitLen(Fcur), maxBitLen(Gcur))
        if FGBits <= 10 { break }

        let FGShift = max(0, FGBits - targetBits)
        // resultShift = FGShift - fgShift: how much to shift k to get true value.
        let resultShift = FGShift - fgShift

        var FC = Fcur.map { v -> Complex64 in
            let sv = FGShift == 0 ? v : (v < 0 ? -((-v) >> FGShift) : v >> FGShift)
            return Complex64(Double(sv))
        }
        var GC = Gcur.map { v -> Complex64 in
            let sv = FGShift == 0 ? v : (v < 0 ? -((-v) >> FGShift) : v >> FGShift)
            return Complex64(Double(sv))
        }
        fftForward(&FC, n); fftForward(&GC, n)

        var kC = [Complex64](repeating: Complex64(0), count: n)
        for j in 0..<n {
            if denomArr[j] != 0 {
                let num = FC[j] * fC[j].conjugate + GC[j] * gC[j].conjugate
                if num.re.isFinite && num.im.isFinite {
                    kC[j] = Complex64(num.re / denomArr[j], num.im / denomArr[j])
                }
            }
        }
        fftInverse(&kC, n)

        var kRound = [BigInt](repeating: 0, count: n)
        var anyNonzero = false
        for i in 0..<n {
            let re = kC[i].re
            guard re.isFinite else { continue }
            var kv = BigInt(Int64(re.rounded()))
            if kv == 0 { continue }
            if resultShift > 0 { kv <<= resultShift }
            else if resultShift < 0 { kv >>= -resultShift }
            kTotal[i] += kv; kRound[i] = kv; anyNonzero = true
        }
        if !anyNonzero { break }

        let kf = polyMulBig(kRound, f, n)
        let kg = polyMulBig(kRound, g, n)
        for i in 0..<n { Fcur[i] -= kf[i]; Gcur[i] -= kg[i] }
    }

    return kTotal
}

private func roundDiv(_ a: BigInt, _ b: BigInt) -> BigInt {
    let (q, r) = a.quotientAndRemainder(dividingBy: b)
    let ar = r < 0 ? -r : r; let ab = b < 0 ? -b : b
    return 2 * ar >= ab ? (r < 0 ? q - 1 : q + 1) : q
}

