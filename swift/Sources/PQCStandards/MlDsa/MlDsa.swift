// ML-DSA (FIPS 204) - Digital Signature Algorithm

import Foundation

public struct MlDsaKeyPair {
    public let publicKey: [UInt8]
    public let secretKey: [UInt8]
}

public enum MlDsa {
    /// Key Generation
    public static func keyGen(params: MlDsaParams) -> MlDsaKeyPair {
        var rng = SystemRandomNumberGenerator()
        var xi = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { xi[i] = UInt8.random(in: 0...255, using: &rng) }
        return keyGenInternal(params: params, xi: xi)
    }

    /// Deterministic keygen
    public static func keyGenInternal(params: MlDsaParams, xi: [UInt8]) -> MlDsaKeyPair {
        let k = params.k, l = params.l
        // Expand seed
        let expanded = KemHash.shake256(xi + [UInt8(k), UInt8(l)], outputLen: 128)
        let rho = Array(expanded[0..<32])
        let rhoPrime = Array(expanded[32..<96])
        let key = Array(expanded[96..<128])

        // Expand A
        let aHat = DsaHash.expandA(rho: rho, k: k, l: l)

        // Sample s1, s2
        let (s1, s2) = DsaHash.expandS(rhoPrime: rhoPrime, k: k, l: l, eta: params.eta)

        // NTT(s1)
        var s1Hat = s1
        for i in 0..<l { DsaNtt.ntt(&s1Hat[i]) }

        // t = A * s1 + s2
        var t = [[Int32]]()
        for i in 0..<k {
            var ti = [Int32](repeating: 0, count: 256)
            for j in 0..<l {
                let prod = DsaNtt.pointwiseMul(aHat[i][j], s1Hat[j])
                ti = DsaNtt.polyAdd(ti, prod)
            }
            DsaNtt.invNtt(&ti)
            ti = DsaNtt.polyAdd(ti, s2[i])
            t.append(ti)
        }

        // Power2Round: t = t1 * 2^d + t0
        var t1 = [[Int32]]()
        var t0 = [[Int32]]()
        for i in 0..<k {
            var t1i = [Int32](repeating: 0, count: 256)
            var t0i = [Int32](repeating: 0, count: 256)
            for j in 0..<256 {
                var r = t[i][j] % DsaField.q
                if r < 0 { r += DsaField.q }
                t1i[j] = r >> params.d
                t0i[j] = r - (t1i[j] << params.d)
                if t0i[j] > (1 << (params.d - 1)) {
                    t0i[j] -= (1 << params.d)
                    t1i[j] += 1
                }
            }
            t1.append(t1i)
            t0.append(t0i)
        }

        // pk = rho || encode(t1)
        let pk = rho + DsaEncode.encodeT1(t1)

        // tr = H(pk, 64)
        let tr = KemHash.shake256(pk, outputLen: 64)

        // sk = rho || key || tr || encode(s1) || encode(s2) || encode(t0)
        var sk = rho + key + tr
        for i in 0..<l {
            sk.append(contentsOf: DsaEncode.encodeEta(s1[i], eta: params.eta))
        }
        for i in 0..<k {
            sk.append(contentsOf: DsaEncode.encodeEta(s2[i], eta: params.eta))
        }
        sk.append(contentsOf: DsaEncode.encodeT0(t0))

        return MlDsaKeyPair(publicKey: pk, secretKey: sk)
    }

    /// Sign a message
    public static func sign(params: MlDsaParams, sk: [UInt8], message: [UInt8]) -> [UInt8]? {
        var rng = SystemRandomNumberGenerator()
        var rnd = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { rnd[i] = UInt8.random(in: 0...255, using: &rng) }
        return signInternal(params: params, sk: sk, message: message, rnd: rnd)
    }

    /// Deterministic sign
    public static func signInternal(params: MlDsaParams, sk: [UInt8], message: [UInt8], rnd: [UInt8]) -> [UInt8]? {
        let k = params.k, l = params.l

        // Decode sk
        let rho = Array(sk[0..<32])
        let key = Array(sk[32..<64])
        let tr = Array(sk[64..<128])

        var offset = 128
        let etaBytes = params.eta == 2 ? 96 : 128

        var s1 = [[Int32]]()
        for _ in 0..<l {
            s1.append(DsaEncode.decodeEta(Array(sk[offset..<(offset + etaBytes)]), eta: params.eta))
            offset += etaBytes
        }
        var s2 = [[Int32]]()
        for _ in 0..<k {
            s2.append(DsaEncode.decodeEta(Array(sk[offset..<(offset + etaBytes)]), eta: params.eta))
            offset += etaBytes
        }
        let t0 = DsaEncode.decodeT0(Array(sk[offset...]), k: k)

        // Expand A
        let aHat = DsaHash.expandA(rho: rho, k: k, l: l)

        // NTT transforms
        var s1Hat = s1
        var s2Hat = s2
        var t0Hat = t0
        for i in 0..<l { DsaNtt.ntt(&s1Hat[i]) }
        for i in 0..<k { DsaNtt.ntt(&s2Hat[i]); DsaNtt.ntt(&t0Hat[i]) }

        // mu = H(tr || msg)
        let mu = KemHash.shake256(tr + message, outputLen: 64)

        // rhoPrime = H(key || rnd || mu)
        let rhoPrime = KemHash.shake256(key + rnd + mu, outputLen: 64)

        var kappa: UInt16 = 0
        let maxAttempts = 1000

        for _ in 0..<maxAttempts {
            // Sample y
            var y = [[Int32]]()
            for i in 0..<l {
                y.append(DsaHash.expandMask(rhoPrime: rhoPrime, kappa: kappa + UInt16(i), gamma1: params.gamma1))
            }
            kappa += UInt16(l)

            // w = A * NTT(y)
            var yHat = y
            for i in 0..<l { DsaNtt.ntt(&yHat[i]) }

            var w = [[Int32]]()
            for i in 0..<k {
                var wi = [Int32](repeating: 0, count: 256)
                for j in 0..<l {
                    let prod = DsaNtt.pointwiseMul(aHat[i][j], yHat[j])
                    wi = DsaNtt.polyAdd(wi, prod)
                }
                DsaNtt.invNtt(&wi)
                w.append(wi)
            }

            // w1 = HighBits(w)
            var w1 = [[Int32]]()
            for i in 0..<k {
                var w1i = [Int32](repeating: 0, count: 256)
                for j in 0..<256 {
                    w1i[j] = DsaDecompose.highBits(w[i][j], gamma2: params.gamma2)
                }
                w1.append(w1i)
            }

            // Encode w1 and hash
            var w1Encoded = [UInt8]()
            let w1Bits = params.gamma2 == (DsaField.q - 1) / 88 ? 6 : 4
            for i in 0..<k {
                w1Encoded.append(contentsOf: KemEncode.byteEncode(w1[i], d: w1Bits))
            }

            let cTilde = KemHash.shake256(mu + w1Encoded, outputLen: params.lambda / 4)
            let c = DsaHash.sampleInBall(seed: cTilde, tau: params.tau)
            var cHat = c
            DsaNtt.ntt(&cHat)

            // z = y + c*s1
            var z = [[Int32]]()
            for i in 0..<l {
                var cs1 = DsaNtt.pointwiseMul(cHat, s1Hat[i])
                DsaNtt.invNtt(&cs1)
                z.append(DsaNtt.polyAdd(y[i], cs1))
            }

            // Check norm of z
            if DsaDecompose.vecNorm(z) >= params.gamma1 - params.beta {
                continue
            }

            // r0 = LowBits(w - c*s2)
            var cs2 = [[Int32]]()
            for i in 0..<k {
                var v = DsaNtt.pointwiseMul(cHat, s2Hat[i])
                DsaNtt.invNtt(&v)
                cs2.append(v)
            }

            var wMinusCs2 = [[Int32]]()
            for i in 0..<k {
                wMinusCs2.append(DsaNtt.polySub(w[i], cs2[i]))
            }

            var r0Norm: Int32 = 0
            for i in 0..<k {
                for j in 0..<256 {
                    let r0 = DsaDecompose.lowBits(wMinusCs2[i][j], gamma2: params.gamma2)
                    var v = r0
                    if v < 0 { v += DsaField.q }
                    if v > DsaField.q / 2 { v = DsaField.q - v }
                    if v > r0Norm { r0Norm = v }
                }
            }
            if r0Norm >= params.gamma2 - params.beta {
                continue
            }

            // Compute hint
            var ct0 = [[Int32]]()
            for i in 0..<k {
                var v = DsaNtt.pointwiseMul(cHat, t0Hat[i])
                DsaNtt.invNtt(&v)
                ct0.append(v)
            }

            if DsaDecompose.vecNorm(ct0) >= params.gamma2 {
                continue
            }

            var h = [[Bool]](repeating: [Bool](repeating: false, count: 256), count: k)
            var hintCount = 0
            for i in 0..<k {
                for j in 0..<256 {
                    let wcs2 = wMinusCs2[i][j]
                    let wcs2ct0 = DsaField.add(wcs2, ct0[i][j])
                    let h1 = DsaDecompose.highBits(wcs2, gamma2: params.gamma2)
                    let h2 = DsaDecompose.highBits(wcs2ct0, gamma2: params.gamma2)
                    if h1 != h2 {
                        h[i][j] = true
                        hintCount += 1
                    }
                }
            }

            if hintCount > params.omega { continue }

            // Encode signature
            var sig = cTilde
            sig.append(contentsOf: DsaEncode.encodeZ(z, gamma1: params.gamma1))
            sig.append(contentsOf: DsaEncode.encodeHint(h, omega: params.omega, k: k))
            return sig
        }

        return nil // Failed after max attempts
    }

    /// Verify a signature
    public static func verify(params: MlDsaParams, pk: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
        let k = params.k, l = params.l

        // Decode pk
        let rho = Array(pk[0..<32])
        let t1 = DsaEncode.decodeT1(Array(pk[32...]), k: k)

        // Decode signature
        let cTildeLen = params.lambda / 4
        let cTilde = Array(signature[0..<cTildeLen])

        let zBits = params.gamma1 == (1 << 17) ? 18 : 20
        let zPolyBytes = zBits * 256 / 8
        let zBytes = Array(signature[cTildeLen..<(cTildeLen + l * zPolyBytes)])
        let z = DsaEncode.decodeZ(zBytes, l: l, gamma1: params.gamma1)

        let hintBytes = Array(signature[(cTildeLen + l * zPolyBytes)...])
        guard let h = DsaEncode.decodeHint(hintBytes, omega: params.omega, k: k) else {
            return false
        }

        // Check z norm
        if DsaDecompose.vecNorm(z) >= params.gamma1 - params.beta {
            return false
        }

        // Expand A
        let aHat = DsaHash.expandA(rho: rho, k: k, l: l)

        // tr = H(pk)
        let tr = KemHash.shake256(pk, outputLen: 64)
        let mu = KemHash.shake256(tr + message, outputLen: 64)

        // c = SampleInBall(cTilde)
        let c = DsaHash.sampleInBall(seed: cTilde, tau: params.tau)
        var cHat = c
        DsaNtt.ntt(&cHat)

        // NTT(z)
        var zHat = z
        for i in 0..<l { DsaNtt.ntt(&zHat[i]) }

        // NTT(t1 * 2^d)
        var t1Hat = t1.map { poly -> [Int32] in
            poly.map { DsaField.reduce(Int64($0) << params.d) }
        }
        for i in 0..<k { DsaNtt.ntt(&t1Hat[i]) }

        // w' = A*z - c*t1*2^d
        var wPrime = [[Int32]]()
        for i in 0..<k {
            var wi = [Int32](repeating: 0, count: 256)
            for j in 0..<l {
                let prod = DsaNtt.pointwiseMul(aHat[i][j], zHat[j])
                wi = DsaNtt.polyAdd(wi, prod)
            }
            let ct1 = DsaNtt.pointwiseMul(cHat, t1Hat[i])
            wi = DsaNtt.polySub(wi, ct1)
            DsaNtt.invNtt(&wi)
            wPrime.append(wi)
        }

        // UseHint
        var w1Prime = [[Int32]]()
        for i in 0..<k {
            var w1i = [Int32](repeating: 0, count: 256)
            for j in 0..<256 {
                w1i[j] = DsaDecompose.useHint(h[i][j], wPrime[i][j], gamma2: params.gamma2)
            }
            w1Prime.append(w1i)
        }

        // Encode w1' and hash
        var w1Encoded = [UInt8]()
        let w1Bits = params.gamma2 == (DsaField.q - 1) / 88 ? 6 : 4
        for i in 0..<k {
            w1Encoded.append(contentsOf: KemEncode.byteEncode(w1Prime[i], d: w1Bits))
        }

        let cTildePrime = KemHash.shake256(mu + w1Encoded, outputLen: params.lambda / 4)
        return cTilde == cTildePrime
    }
}
