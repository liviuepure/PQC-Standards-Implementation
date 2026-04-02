// HqcKem.swift -- HQC KEM: Key Generation, Encapsulation, Decapsulation.
//
// Public API following the Go reference implementation structure.

import Foundation

// MARK: - Seed Expander

/// SHAKE256-based seed expander.
final class SeedExpander {
    private let shake: SHAKE256

    init(_ seed: [UInt8]) {
        shake = SHAKE256()
        shake.absorb(seed)
    }

    func read(_ count: Int) -> [UInt8] {
        return shake.squeeze(count)
    }
}

// MARK: - Random vector generation

/// Generate a random vector of n bits using the seed expander.
func vectSetRandom(_ se: SeedExpander, _ n: Int) -> [UInt64] {
    let nWords = (n + 63) / 64
    let nBytes = nWords * 8
    let buf = se.read(nBytes)
    var v = vectFromBytes(buf, nWords)
    let rem = n % 64
    if rem != 0 {
        v[nWords - 1] &= (1 << rem) - 1
    }
    return v
}

/// Generate a random vector of n bits with exactly `weight` bits set.
/// Uses rejection sampling from sequential 4-byte chunks.
func vectSetRandomFixedWeight(_ se: SeedExpander, _ n: Int, _ weight: Int) -> [UInt64] {
    let nWords = (n + 63) / 64
    var v = [UInt64](repeating: 0, count: nWords)

    var positions = [UInt32](repeating: 0, count: weight)

    for i in 0..<weight {
        while true {
            let buf = se.read(4)
            let pos = (UInt32(buf[0]) | UInt32(buf[1]) << 8 |
                       UInt32(buf[2]) << 16 | UInt32(buf[3]) << 24) % UInt32(n)

            // Check for duplicates
            var duplicate = false
            for j in 0..<i {
                if positions[j] == pos {
                    duplicate = true
                    break
                }
            }
            if !duplicate {
                positions[i] = pos
                break
            }
        }
    }

    for pos in positions {
        vectSetBit(&v, Int(pos))
    }

    return v
}

// MARK: - Hash functions

/// Compute d = SHAKE256(H_domain || m), producing 64 bytes.
func computeD(_ m: [UInt8]) -> [UInt8] {
    let h = SHAKE256()
    h.absorb([hFctDomain])
    h.absorb(m)
    return h.squeeze(sharedSecretBytes)
}

/// Compute theta = SHAKE256(G_domain || m || pk || d).
func computeTheta(_ m: [UInt8], _ pk: [UInt8], _ d: [UInt8], _ p: HqcParams) -> [UInt8] {
    let h = SHAKE256()
    h.absorb([gFctDomain])
    h.absorb(m)
    h.absorb(pk)
    h.absorb(d)
    return h.squeeze(seedBytes)
}

/// Compute ss = SHAKE256(K_domain || m || u_bytes || v_bytes).
func computeSS(_ m: [UInt8], _ u: [UInt64], _ v: [UInt64], _ p: HqcParams) -> [UInt8] {
    let h = SHAKE256()
    h.absorb([kFctDomain])
    h.absorb(m)
    h.absorb(vectToBytes(u, p.vecNSizeBytes))
    h.absorb(vectToBytes(v, p.vecN1N2SizeBytes))
    return h.squeeze(sharedSecretBytes)
}

// MARK: - PKE Encrypt

/// Internal PKE encryption.
func pkeEncrypt(_ m: [UInt8], _ theta: [UInt8], _ pk: [UInt8],
                _ p: HqcParams) -> ([UInt64], [UInt64]) {
    // Parse public key
    let pkSeed = Array(pk[0..<seedBytes])
    let s = vectFromBytes(Array(pk[seedBytes...]), p.vecNSize64)

    // Generate h from pk_seed
    let pkExpander = SeedExpander(pkSeed)
    let h = vectSetRandom(pkExpander, p.n)

    // Generate r1, r2 with weight WR and e with weight WE from theta
    let thetaExpander = SeedExpander(theta)
    let r1 = vectSetRandomFixedWeight(thetaExpander, p.n, p.wr)
    let r2 = vectSetRandomFixedWeight(thetaExpander, p.n, p.wr)
    let e = vectSetRandomFixedWeight(thetaExpander, p.n, p.we)

    // u = r1 + h * r2 mod (x^n - 1)
    let hr2 = vectMul(h, r2, p.n)
    var u = vectAdd(hr2, r1)
    u = vectResize(u, p.n)

    // v = encode(m) + s * r2 + e
    let encoded = tensorEncode(m, p)

    // s * r2 in the ring, then truncate to n1*n2 bits
    let sr2 = vectMul(s, r2, p.n)
    var sr2Trunc = [UInt64](repeating: 0, count: p.vecN1N2Size64)
    for i in 0..<min(sr2.count, p.vecN1N2Size64) { sr2Trunc[i] = sr2[i] }
    if p.n1n2 % 64 != 0 && p.vecN1N2Size64 > 0 {
        sr2Trunc[p.vecN1N2Size64 - 1] &= (1 << (p.n1n2 % 64)) - 1
    }

    // Resize e to n1*n2
    var eResized = [UInt64](repeating: 0, count: p.vecN1N2Size64)
    for i in 0..<min(e.count, p.vecN1N2Size64) { eResized[i] = e[i] }
    if p.n1n2 % 64 != 0 && p.vecN1N2Size64 > 0 {
        eResized[p.vecN1N2Size64 - 1] &= (1 << (p.n1n2 % 64)) - 1
    }

    var v = vectAdd(encoded, sr2Trunc)
    v = vectAdd(v, eResized)
    v = vectResize(v, p.n1n2)

    return (u, v)
}

// MARK: - Public API

/// Generate an HQC key pair.
/// Returns (publicKey, secretKey).
public func hqcKeyGen(_ p: HqcParams) -> ([UInt8], [UInt8]) {
    initGF256Tables()

    // Generate random seeds
    var skSeed = [UInt8](repeating: 0, count: seedBytes)
    var pkSeed = [UInt8](repeating: 0, count: seedBytes)
    _ = SecRandomCopyBytes(kSecRandomDefault, seedBytes, &skSeed)
    _ = SecRandomCopyBytes(kSecRandomDefault, seedBytes, &pkSeed)

    // Generate secret vectors x, y from sk_seed
    let skExpander = SeedExpander(skSeed)
    let x = vectSetRandomFixedWeight(skExpander, p.n, p.w)
    let y = vectSetRandomFixedWeight(skExpander, p.n, p.w)

    // Generate random vector h from pk_seed
    let pkExpander = SeedExpander(pkSeed)
    let h = vectSetRandom(pkExpander, p.n)

    // Compute s = x + h * y mod (x^n - 1)
    let hy = vectMul(h, y, p.n)
    var s = vectAdd(hy, x)
    s = vectResize(s, p.n)

    // Serialize public key: [pk_seed (40 bytes)] [s (VecNSizeBytes bytes)]
    var pk = [UInt8](repeating: 0, count: p.pkSize)
    for i in 0..<seedBytes { pk[i] = pkSeed[i] }
    let sBytes = vectToBytes(s, p.vecNSizeBytes)
    for i in 0..<sBytes.count { pk[seedBytes + i] = sBytes[i] }

    // Serialize secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
    var sk = [UInt8](repeating: 0, count: p.skSize)
    for i in 0..<seedBytes { sk[i] = skSeed[i] }
    for i in 0..<pk.count { sk[seedBytes + i] = pk[i] }

    return (pk, sk)
}

/// Encapsulate a shared secret using the public key.
/// Returns (ciphertext, sharedSecret).
public func hqcEncaps(_ pk: [UInt8], _ p: HqcParams) -> ([UInt8], [UInt8]) {
    initGF256Tables()

    // Generate random message m
    var m = [UInt8](repeating: 0, count: p.vecKSizeBytes)
    _ = SecRandomCopyBytes(kSecRandomDefault, p.vecKSizeBytes, &m)

    // Compute d = H(m)
    let d = computeD(m)

    // Compute theta = SHAKE256(G_domain || m || pk || d)
    let theta = computeTheta(m, pk, d, p)

    // PKE Encrypt
    let (u, v) = pkeEncrypt(m, theta, pk, p)

    // Compute shared secret
    let ss = computeSS(m, u, v, p)

    // Serialize ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
    var ct = [UInt8](repeating: 0, count: p.ctSize)
    let uBytes = vectToBytes(u, p.vecNSizeBytes)
    let vBytes = vectToBytes(v, p.vecN1N2SizeBytes)
    for i in 0..<uBytes.count { ct[i] = uBytes[i] }
    for i in 0..<vBytes.count { ct[p.vecNSizeBytes + i] = vBytes[i] }
    for i in 0..<d.count { ct[p.vecNSizeBytes + p.vecN1N2SizeBytes + i] = d[i] }

    return (ct, ss)
}

/// Decapsulate a shared secret from a ciphertext using the secret key.
public func hqcDecaps(_ sk: [UInt8], _ ct: [UInt8], _ p: HqcParams) -> [UInt8] {
    initGF256Tables()

    // Parse secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
    let skSeed = Array(sk[0..<seedBytes])
    let pk = Array(sk[seedBytes...])

    // Parse ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
    let u = vectFromBytes(Array(ct[0..<p.vecNSizeBytes]), p.vecNSize64)
    let v = vectFromBytes(Array(ct[p.vecNSizeBytes..<(p.vecNSizeBytes + p.vecN1N2SizeBytes)]),
                          p.vecN1N2Size64)
    let d = Array(ct[(p.vecNSizeBytes + p.vecN1N2SizeBytes)...])

    // Regenerate secret vectors x, y and sigma from sk_seed
    let skExpander = SeedExpander(skSeed)
    let _ = vectSetRandomFixedWeight(skExpander, p.n, p.w)  // x (not needed for decrypt)
    let y = vectSetRandomFixedWeight(skExpander, p.n, p.w)
    // Generate sigma (rejection secret)
    let sigma = skExpander.read(p.vecKSizeBytes)

    // Compute v - u * y (which is v XOR u*y since we are in GF(2))
    let uy = vectMul(u, y, p.n)

    // Truncate uy to n1*n2 bits
    var uyTrunc = [UInt64](repeating: 0, count: p.vecN1N2Size64)
    for i in 0..<min(uy.count, p.vecN1N2Size64) { uyTrunc[i] = uy[i] }
    if p.n1n2 % 64 != 0 && p.vecN1N2Size64 > 0 {
        uyTrunc[p.vecN1N2Size64 - 1] &= (1 << (p.n1n2 % 64)) - 1
    }

    let vMinusUY = vectAdd(v, uyTrunc)

    // Decode using tensor product code
    var mPrime: [UInt8]
    let (decoded, ok) = tensorDecode(vMinusUY, p)
    if ok, let decodedMsg = decoded {
        mPrime = decodedMsg
    } else {
        // Decoding failed - use sigma
        mPrime = [UInt8](repeating: 0, count: p.vecKSizeBytes)
        for i in 0..<p.vecKSizeBytes { mPrime[i] = sigma[i] }
    }

    // Re-encrypt to verify
    let thetaPrime = computeTheta(mPrime, pk, d, p)
    let (u2, v2) = pkeEncrypt(mPrime, thetaPrime, pk, p)

    // Constant-time comparison
    let u2Trunc = vectResize(u2, p.n)
    let uOrig = vectResize(u, p.n)
    let uMatch = vectEqual(u2Trunc, uOrig)

    let v2Trunc = vectResize(v2, p.n1n2)
    let vOrig = vectResize(v, p.n1n2)
    let vMatch = vectEqual(v2Trunc, vOrig)

    let match = uMatch & vMatch

    // Constant-time selection of message or sigma
    var mc = [UInt8](repeating: 0, count: p.vecKSizeBytes)
    let maskOK = UInt8(0) &- UInt8(match)         // 0xFF if match, 0x00 otherwise
    let maskFail = UInt8(0) &- UInt8(1 - match)   // 0x00 if match, 0xFF otherwise
    for i in 0..<p.vecKSizeBytes {
        mc[i] = (mPrime[i] & maskOK) | (sigma[i] & maskFail)
    }

    // Compute shared secret
    let ss = computeSS(mc, u, v, p)
    return ss
}
