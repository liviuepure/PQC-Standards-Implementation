// Sign.swift — FN-DSA signing (FIPS 206).
//
// HashToPoint, Babai nearest-plane, and the full signing pipeline.

import Foundation

// MARK: - HashToPoint

/// Hash msg (salt||message) to a polynomial c in Z_q[x]/(x^n+1) with coefficients in [0, Q).
/// Uses SHAKE-256 extended output, rejection-sampling 16-bit values mod Q.
func hashToPoint(_ msg: [UInt8], _ p: Params) -> [Int32] {
    let n = p.n
    var out = [Int32](repeating: 0, count: n)
    let shake = SHAKE256()
    shake.absorb(msg)
    shake.finalize()

    var count = 0
    while count < n {
        let buf = shake.squeeze(2)
        let v = Int32(UInt16(buf[0]) | (UInt16(buf[1]) << 8))
        if v < 5 * Q {
            out[count] = v % Q
            count += 1
        }
    }
    return out
}

// MARK: - Helpers

/// Center v mod Q into (-Q/2, Q/2].
func centerModQ(_ v: Int32) -> Int32 {
    var r = ((v % Q) + Q) % Q
    if r > Q / 2 { r -= Q }
    return r
}

/// Convert integer polynomial to FFT domain.
private func int32sToFFT(_ a: [Int32], _ n: Int) -> [Complex64] {
    var f = a.map { Complex64(Double($0)) }
    fftForward(&f, n)
    return f
}

/// Apply IFFT and round to integer polynomial.
private func roundFFTToInt32s(_ fft: [Complex64], _ n: Int) -> [Int32] {
    var tmp = fft
    fftInverse(&tmp, n)
    return tmp.map { Int32($0.re.rounded()) }
}

// MARK: - Recover G

/// Recover G from (f, g, F) using the NTRU equation fG - gF = Q.
func recoverG(_ f: [Int32], _ g: [Int32], _ F: [Int32], _ n: Int) -> [Int32]? {
    // Compute gF = g*F mod q via NTT.
    var gModQ = [Int32](repeating: 0, count: n)
    var FModQ = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        gModQ[i] = ((g[i] % Q) + Q) % Q
        FModQ[i] = ((F[i] % Q) + Q) % Q
    }
    let gF = polyMulNTT(gModQ, FModQ, n: n)

    // Compute f^{-1} mod q.
    var fModQ = [Int32](repeating: 0, count: n)
    for i in 0..<n { fModQ[i] = ((f[i] % Q) + Q) % Q }
    var fNTT = fModQ
    nttForward(&fNTT, n)
    for v in fNTT { if v == 0 { return nil } }
    var fInvNTT = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        fInvNTT[i] = nttPow(Int64(fNTT[i]), Int64(Q - 2))
    }
    nttInverse(&fInvNTT, n)

    let G = polyMulNTT(gF, fInvNTT, n: n)
    var result = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        var v = G[i]
        if v > Q / 2 { v -= Q }
        result[i] = v
    }
    return result
}

// MARK: - Babai nearest-plane

/// Two-step Babai nearest-plane for FN-DSA signing.
/// This is a simplified Babai approximation (not the full FIPS 206 ffSampling).
func ffSamplingBabai(_ c: [Int32], _ f: [Int32], _ g: [Int32], _ F: [Int32], _ G: [Int32], _ n: Int) -> (s1: [Int32], s2: [Int32]) {
    let cFFT = int32sToFFT(c, n)
    let fFFT = int32sToFFT(f, n)
    let gFFT = int32sToFFT(g, n)
    let FFFT = int32sToFFT(F, n)
    let GFFT = int32sToFFT(G, n)

    // Gram-Schmidt: b0 = (g, -f), b1 = (G, -F)
    // mu10_j = (G_j*conj(g_j) + F_j*conj(f_j)) / (|g_j|^2 + |f_j|^2)
    // b1*_j = (G_j - mu10*g_j, -F_j + mu10*f_j)
    var b1Star = [(Complex64, Complex64)](repeating: (Complex64(0), Complex64(0)), count: n)
    var b1StarNormSq = [Double](repeating: 0, count: n)

    for j in 0..<n {
        let gj = gFFT[j]
        let fj = fFFT[j]
        let Gj = GFFT[j]
        let Fj = FFFT[j]
        let b0NormSq = gj.normSq + fj.normSq
        var mu10 = Complex64(0)
        if b0NormSq != 0 {
            let num = Gj * gj.conjugate + Fj * fj.conjugate
            mu10 = Complex64(num.re / b0NormSq, num.im / b0NormSq)
        }
        let b1s0 = Gj - mu10 * gj
        let b1s1 = Complex64(0) - Fj + mu10 * fj
        b1Star[j] = (b1s0, b1s1)
        b1StarNormSq[j] = b1s0.normSq + b1s1.normSq
    }

    // Step 1: project (c, 0) along b1*
    var tau1FFT = [Complex64](repeating: Complex64(0), count: n)
    for j in 0..<n {
        let bsNorm = b1StarNormSq[j]
        if bsNorm != 0 {
            let bs0 = b1Star[j].0
            let num = cFFT[j] * bs0.conjugate
            tau1FFT[j] = Complex64(num.re / bsNorm, num.im / bsNorm)
        }
    }
    let z1 = roundFFTToInt32s(tau1FFT, n)
    let z1FFT = int32sToFFT(z1, n)

    // Update target: t' = (c - z1*G, z1*F)
    var cPrimeFFT = [Complex64](repeating: Complex64(0), count: n)
    var xPrimeFFT = [Complex64](repeating: Complex64(0), count: n)
    for j in 0..<n {
        cPrimeFFT[j] = cFFT[j] - z1FFT[j] * GFFT[j]
        xPrimeFFT[j] = z1FFT[j] * FFFT[j]
    }

    // Step 2: project t' along b0* = (g, -f)
    var tau0FFT = [Complex64](repeating: Complex64(0), count: n)
    for j in 0..<n {
        let gj = gFFT[j]
        let fj = fFFT[j]
        let b0NormSq = gj.normSq + fj.normSq
        if b0NormSq != 0 {
            let num = cPrimeFFT[j] * gj.conjugate - xPrimeFFT[j] * fj.conjugate
            tau0FFT[j] = Complex64(num.re / b0NormSq, num.im / b0NormSq)
        }
    }
    let z0 = roundFFTToInt32s(tau0FFT, n)
    let z0FFT = int32sToFFT(z0, n)

    // s1 = z0*f + z1*F, s2 = c - z0*g - z1*G
    var s1FFT = [Complex64](repeating: Complex64(0), count: n)
    var s2FFT = [Complex64](repeating: Complex64(0), count: n)
    for j in 0..<n {
        s1FFT[j] = z0FFT[j] * fFFT[j] + z1FFT[j] * FFFT[j]
        s2FFT[j] = cFFT[j] - z0FFT[j] * gFFT[j] - z1FFT[j] * GFFT[j]
    }

    let s1Raw = roundFFTToInt32s(s1FFT, n)
    let s2Raw = roundFFTToInt32s(s2FFT, n)

    let s1 = s1Raw.map { centerModQ($0) }
    let s2 = s2Raw.map { centerModQ($0) }
    return (s1, s2)
}

// MARK: - Norm check

/// Squared Euclidean norm of two integer slices.
func normSq(_ s1: [Int32], _ s2: [Int32]) -> Int64 {
    var n: Int64 = 0
    for v in s1 { n += Int64(v) * Int64(v) }
    for v in s2 { n += Int64(v) * Int64(v) }
    return n
}

// MARK: - SignInternal

/// Sign msg using secret key sk under parameter set p.
func signInternal(_ sk: [UInt8], _ msg: [UInt8], _ p: Params) -> [UInt8]? {
    guard let decoded = decodeSK(sk, p) else { return nil }
    let (f, g, F) = decoded
    let n = p.n

    guard let G = recoverG(f, g, F, n) else { return nil }

    // Pre-compute h for verification check.
    let h = ntruPublicKey(f, g, p)

    let maxAttempts = 1000
    for _ in 0..<maxAttempts {
        let salt = secureRandomBytes(40)

        // c = HashToPoint(salt || msg)
        var hashInput = [UInt8](repeating: 0, count: 40 + msg.count)
        hashInput[0..<40] = salt[0..<40]
        hashInput[40...] = msg[0...]
        let c = hashToPoint(hashInput, p)

        let cCentered = c.map { centerModQ($0) }

        let (s1, s2) = ffSamplingBabai(cCentered, f, g, F, G, n)

        // Verify s1*h + s2 = c (mod q).
        var s1ModQ = [Int32](repeating: 0, count: n)
        for i in 0..<n { s1ModQ[i] = ((s1[i] % Q) + Q) % Q }
        let s1h = polyMulNTT(s1ModQ, h, n: n)
        var valid = true
        for i in 0..<n {
            let sum = ((Int32((Int64(s1h[i]) + Int64(s2[i])) % Int64(Q)) + Q) % Q)
            if sum != c[i] { valid = false; break }
        }
        if !valid { continue }

        // Norm bound check.
        let ns = normSq(s1, s2)
        if ns > p.betaSq { continue }

        // Encode signature.
        guard let sig = encodeSig(salt, s1, p) else { continue }
        return sig
    }
    return nil
}
