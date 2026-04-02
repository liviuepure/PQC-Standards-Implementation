// Verify.swift — FN-DSA verification (FIPS 206 Algorithm 4).

import Foundation

/// Verify an FN-DSA signature.
func verifyInternal(_ pk: [UInt8], _ msg: [UInt8], _ sig: [UInt8], _ p: Params) -> Bool {
    // 1. Decode and validate public key.
    guard let h = decodePK(pk, p) else { return false }

    // 2. Decode and validate signature.
    guard let (salt, s1) = decodeSig(sig, p) else { return false }

    // 3. Recompute c = HashToPoint(salt || msg).
    var hashInput = [UInt8](repeating: 0, count: 40 + msg.count)
    hashInput[0..<40] = salt[0..<40]
    hashInput[40...] = msg[0...]
    let c = hashToPoint(hashInput, p)

    // 4. Compute s2 = c - s1*h (mod q), centered.
    let n = p.n
    var s1ModQ = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        s1ModQ[i] = ((s1[i] % Q) + Q) % Q
    }
    let s1h = polyMulNTT(s1ModQ, h, n: n)
    var s2 = [Int32](repeating: 0, count: n)
    for i in 0..<n {
        s2[i] = centerModQ(c[i] - s1h[i])
    }

    // 5. Norm check: ||(s1, s2)||^2 <= beta^2.
    return normSq(s1, s2) <= p.betaSq
}
