// ML-KEM K-PKE (Inner PKE scheme)

import Foundation

public enum Kpke {
    /// K-PKE KeyGen
    public static func keyGen(params: MlKemParams, d: [UInt8]) -> (ek: [UInt8], dk: [UInt8]) {
        let k = params.k
        let (rho, sigma) = KemHash.g(d + [UInt8(k)])

        // Generate A matrix in NTT domain
        var aHat = [[[Int32]]]()
        for i in 0..<k {
            var row = [[Int32]]()
            for j in 0..<k {
                row.append(KemSampling.sampleNtt(rho: rho, i: UInt8(j), j: UInt8(i)))
            }
            aHat.append(row)
        }

        // Sample secret and error
        let s = KemSampling.samplePolyVec(sigma: sigma, k: k, eta: params.eta1, offset: 0)
        let e = KemSampling.samplePolyVec(sigma: sigma, k: k, eta: params.eta1, offset: UInt8(k))

        // NTT(s) and NTT(e)
        var sHat = s
        var eHat = e
        for i in 0..<k {
            KemNtt.ntt(&sHat[i])
            KemNtt.ntt(&eHat[i])
        }

        // t = A * s + e in NTT domain
        var tHat = [[Int32]]()
        for i in 0..<k {
            var t = [Int32](repeating: 0, count: 256)
            for j in 0..<k {
                let prod = KemNtt.basemul(aHat[i][j], sHat[j])
                t = KemNtt.polyAdd(t, prod)
            }
            t = KemNtt.polyAdd(t, eHat[i])
            tHat.append(t)
        }

        // Encode ek = encode(t) || rho
        var ek = [UInt8]()
        for i in 0..<k {
            ek.append(contentsOf: KemEncode.encodePoly12(tHat[i]))
        }
        ek.append(contentsOf: rho)

        // Encode dk = encode(s)
        var dk = [UInt8]()
        for i in 0..<k {
            dk.append(contentsOf: KemEncode.encodePoly12(sHat[i]))
        }

        return (ek, dk)
    }

    /// K-PKE Encrypt
    public static func encrypt(params: MlKemParams, ek: [UInt8], m: [UInt8], r: [UInt8]) -> [UInt8] {
        let k = params.k

        // Decode ek
        var tHat = [[Int32]]()
        for i in 0..<k {
            let start = 384 * i
            let polyBytes = Array(ek[start..<(start + 384)])
            tHat.append(KemEncode.decodePoly12(polyBytes))
        }
        let rho = Array(ek[(384 * k)...])

        // Generate A^T
        var aHat = [[[Int32]]]()
        for i in 0..<k {
            var row = [[Int32]]()
            for j in 0..<k {
                row.append(KemSampling.sampleNtt(rho: rho, i: UInt8(i), j: UInt8(j)))
            }
            aHat.append(row)
        }

        // Sample r, e1, e2
        let rv = KemSampling.samplePolyVec(sigma: r, k: k, eta: params.eta1, offset: 0)
        let e1 = KemSampling.samplePolyVec(sigma: r, k: k, eta: params.eta2, offset: UInt8(k))
        let e2Bytes = KemHash.prf(r, b: UInt8(2 * k), eta: params.eta2)
        let e2 = KemSampling.sampleCbd(bytes: e2Bytes, eta: params.eta2)

        // NTT(r)
        var rHat = rv
        for i in 0..<k {
            KemNtt.ntt(&rHat[i])
        }

        // u = A^T * r + e1
        var u = [[Int32]]()
        for i in 0..<k {
            var ui = [Int32](repeating: 0, count: 256)
            for j in 0..<k {
                let prod = KemNtt.basemul(aHat[i][j], rHat[j])
                ui = KemNtt.polyAdd(ui, prod)
            }
            KemNtt.invNtt(&ui)
            ui = KemNtt.polyAdd(ui, e1[i])
            u.append(ui)
        }

        // v = t^T * r + e2 + decode(m)
        var v = [Int32](repeating: 0, count: 256)
        for i in 0..<k {
            let prod = KemNtt.basemul(tHat[i], rHat[i])
            v = KemNtt.polyAdd(v, prod)
        }
        KemNtt.invNtt(&v)
        v = KemNtt.polyAdd(v, e2)

        // Decode message
        let mPoly = KemCompress.decompressPoly(KemEncode.byteDecode(m, d: 1), d: 1)
        v = KemNtt.polyAdd(v, mPoly)

        // Compress and encode
        var ct = [UInt8]()
        for i in 0..<k {
            let cu = KemCompress.compressPoly(u[i], d: params.du)
            ct.append(contentsOf: KemEncode.byteEncode(cu, d: params.du))
        }
        let cv = KemCompress.compressPoly(v, d: params.dv)
        ct.append(contentsOf: KemEncode.byteEncode(cv, d: params.dv))

        return ct
    }

    /// K-PKE Decrypt
    public static func decrypt(params: MlKemParams, dk: [UInt8], ct: [UInt8]) -> [UInt8] {
        let k = params.k

        // Decode u from ciphertext
        var u = [[Int32]]()
        for i in 0..<k {
            let start = params.du * 32 * i
            let uBytes = Array(ct[start..<(start + params.du * 32)])
            let uComp = KemEncode.byteDecode(uBytes, d: params.du)
            u.append(KemCompress.decompressPoly(uComp, d: params.du))
        }

        // Decode v from ciphertext
        let vStart = params.du * 32 * k
        let vBytes = Array(ct[vStart..<(vStart + params.dv * 32)])
        let vComp = KemEncode.byteDecode(vBytes, d: params.dv)
        let v = KemCompress.decompressPoly(vComp, d: params.dv)

        // Decode secret key
        var sHat = [[Int32]]()
        for i in 0..<k {
            let start = 384 * i
            let polyBytes = Array(dk[start..<(start + 384)])
            sHat.append(KemEncode.decodePoly12(polyBytes))
        }

        // w = v - s^T * NTT^{-1}(u)  -- actually s^T * u in NTT, then inv
        var w = [Int32](repeating: 0, count: 256)
        for i in 0..<k {
            var uNtt = u[i]
            KemNtt.ntt(&uNtt)
            let prod = KemNtt.basemul(sHat[i], uNtt)
            w = KemNtt.polyAdd(w, prod)
        }
        KemNtt.invNtt(&w)
        w = KemNtt.polySub(v, w)

        // Compress to 1-bit message
        let mPoly = KemCompress.compressPoly(w, d: 1)
        return KemEncode.byteEncode(mPoly, d: 1)
    }
}
