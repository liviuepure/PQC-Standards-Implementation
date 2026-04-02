// HqcParams.swift -- HQC parameter sets (128/192/256).

import Foundation

/// Holds the parameter set for an HQC security level.
public struct HqcParams {
    public let name: String
    public let n: Int          // ring dimension (poly degree mod x^n - 1)
    public let n1: Int         // Reed-Solomon codeword length
    public let n2: Int         // Reed-Muller codeword length (with repetition)
    public let n1n2: Int       // concatenated code length in bits = n1 * n2
    public let k: Int          // message size in bytes (RS information symbols)
    public let delta: Int      // RS error correction capability
    public let g: Int          // RS generator polynomial degree = 2*delta + 1
    public let w: Int          // weight of secret key vectors x, y
    public let wr: Int         // weight of encryption vectors r1, r2
    public let we: Int         // weight of ephemeral error vector e
    public let pkSize: Int     // public key size in bytes
    public let skSize: Int     // secret key size in bytes
    public let ctSize: Int     // ciphertext size in bytes
    public let ssSize: Int     // shared secret size in bytes

    // Derived sizes (in uint64 words and bytes)
    public let vecNSize64: Int         // ceil(n / 64)
    public let vecNSizeBytes: Int      // ceil(n / 8)
    public let vecN1N2Size64: Int
    public let vecN1N2SizeBytes: Int
    public let vecKSizeBytes: Int      // k bytes

    // GF(2^8) parameters
    public let gfPoly: UInt16          // irreducible polynomial for GF(2^8)
    public let gfMulOrder: Int         // multiplicative order = 255

    // Reed-Muller parameters
    public let rmOrder: Int            // RM(1, rmOrder), base codeword length = 2^rmOrder = 128
    public let multiplicity: Int       // number of repetitions: n2 / 128
}

// MARK: - Constants

/// Seed size used for key generation.
public let seedBytes = 40
/// Size of d = H(m) included in the ciphertext (SHAKE256 output).
public let hashBytes = 64
/// Shared secret size (SHAKE256-512 output).
public let sharedSecretBytes = 64

/// Domain separation bytes for SHAKE256 hashing.
public let gFctDomain: UInt8 = 3   // domain for theta = G(m || pk || salt)
public let hFctDomain: UInt8 = 4   // domain for d = H(m)
public let kFctDomain: UInt8 = 5   // domain for ss = K(m || ct)

// MARK: - Parameter sets

/// HQC-128 targets NIST security level 1.
public let hqc128 = HqcParams(
    name: "HQC-128",
    n: 17669,
    n1: 46,
    n2: 384,
    n1n2: 17664,       // 46 * 384
    k: 16,
    delta: 15,
    g: 31,             // 2*15 + 1
    w: 66,
    wr: 77,
    we: 77,
    pkSize: 2249,
    skSize: 2289,
    ctSize: 4481,
    ssSize: sharedSecretBytes,
    vecNSize64: 277,           // ceil(17669/64)
    vecNSizeBytes: 2209,       // ceil(17669/8)
    vecN1N2Size64: 276,        // ceil(17664/64)
    vecN1N2SizeBytes: 2208,    // ceil(17664/8)
    vecKSizeBytes: 16,
    gfPoly: 0x11D,
    gfMulOrder: 255,
    rmOrder: 7,
    multiplicity: 3            // 384 / 128
)

/// HQC-192 targets NIST security level 3.
public let hqc192 = HqcParams(
    name: "HQC-192",
    n: 35851,
    n1: 56,
    n2: 640,
    n1n2: 35840,       // 56 * 640
    k: 24,
    delta: 16,
    g: 33,             // 2*16 + 1
    w: 100,
    wr: 117,
    we: 117,
    pkSize: 4522,
    skSize: 4562,
    ctSize: 9026,
    ssSize: sharedSecretBytes,
    vecNSize64: 561,
    vecNSizeBytes: 4482,
    vecN1N2Size64: 560,
    vecN1N2SizeBytes: 4480,
    vecKSizeBytes: 24,
    gfPoly: 0x11D,
    gfMulOrder: 255,
    rmOrder: 7,
    multiplicity: 5            // 640 / 128
)

/// HQC-256 targets NIST security level 5.
public let hqc256 = HqcParams(
    name: "HQC-256",
    n: 57637,
    n1: 90,
    n2: 640,
    n1n2: 57600,       // 90 * 640
    k: 32,
    delta: 29,
    g: 59,             // 2*29 + 1
    w: 131,
    wr: 153,
    we: 153,
    pkSize: 7245,
    skSize: 7285,
    ctSize: 14469,
    ssSize: sharedSecretBytes,
    vecNSize64: 901,
    vecNSizeBytes: 7205,
    vecN1N2Size64: 900,
    vecN1N2SizeBytes: 7200,
    vecKSizeBytes: 32,
    gfPoly: 0x11D,
    gfMulOrder: 255,
    rmOrder: 7,
    multiplicity: 5            // 640 / 128
)

/// All supported HQC parameter sets.
public let allParams: [HqcParams] = [hqc128, hqc192, hqc256]
