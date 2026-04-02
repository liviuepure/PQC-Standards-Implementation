/// Parameters for HQC key encapsulation mechanism.
///
/// HQC supports three security levels corresponding to NIST levels 1, 3, and 5.

/// Domain separation bytes for SHAKE256 hashing.
pub const GF_CT_DOMAIN: u8 = 3; // theta = G(m || pk || salt)
pub const HF_CT_DOMAIN: u8 = 4; // d = H(m)
pub const KF_CT_DOMAIN: u8 = 5; // ss = K(m || ct)

/// Seed size used for key generation and seed expansion.
pub const SEED_BYTES: usize = 40;

/// Size of d = H(m) included in the ciphertext (SHAKE256 output).
pub const HASH_BYTES: usize = 64;

/// Shared secret size (SHAKE256-512 output).
pub const SHARED_SECRET_BYTES: usize = 64;

/// HQC parameter set for a given security level.
#[derive(Debug, Clone)]
pub struct Params {
    pub name: &'static str,
    /// Ring dimension (polynomial degree mod x^n - 1).
    pub n: usize,
    /// Reed-Solomon codeword length.
    pub n1: usize,
    /// Reed-Muller codeword length (with duplication).
    pub n2: usize,
    /// Concatenated code length in bits = n1 * n2.
    pub n1n2: usize,
    /// Message size in bytes (RS information symbols).
    pub k: usize,
    /// RS error correction capability.
    pub delta: usize,
    /// RS generator polynomial degree = 2*delta + 1.
    pub g: usize,
    /// Weight of secret key vectors x, y.
    pub w: usize,
    /// Weight of encryption vectors r1, r2.
    pub wr: usize,
    /// Weight of ephemeral error vector e.
    pub we: usize,
    /// Public key size in bytes.
    pub pk_size: usize,
    /// Secret key size in bytes.
    pub sk_size: usize,
    /// Ciphertext size in bytes.
    pub ct_size: usize,
    /// Shared secret size in bytes.
    pub ss_size: usize,
    /// ceil(n / 64) -- number of u64 words for an n-bit vector.
    pub vec_n_size64: usize,
    /// ceil(n / 8) -- number of bytes for an n-bit vector.
    pub vec_n_size_bytes: usize,
    /// ceil(n1n2 / 64).
    pub vec_n1n2_size64: usize,
    /// ceil(n1n2 / 8).
    pub vec_n1n2_size_bytes: usize,
    /// K bytes (message size).
    pub vec_k_size_bytes: usize,
    /// GF(2^8) irreducible polynomial.
    pub gf_poly: u16,
    /// Multiplicative order of GF(2^8) = 255.
    pub gf_mul_order: usize,
    /// RM(1, rm_order), base codeword length = 2^rm_order = 128.
    pub rm_order: usize,
    /// Number of RM repetitions: n2 / 128.
    pub multiplicity: usize,
}

/// HQC-128: NIST security level 1 (128-bit).
pub const HQC128: Params = Params {
    name: "HQC-128",
    n: 17669,
    n1: 46,
    n2: 384,
    n1n2: 17664, // 46 * 384
    k: 16,
    delta: 15,
    g: 31, // 2*15 + 1
    w: 66,
    wr: 77,
    we: 77,
    pk_size: 2249,
    sk_size: 2289,
    ct_size: 4481,
    ss_size: SHARED_SECRET_BYTES,
    vec_n_size64: 277,   // ceil(17669/64)
    vec_n_size_bytes: 2209, // ceil(17669/8)
    vec_n1n2_size64: 276,   // ceil(17664/64)
    vec_n1n2_size_bytes: 2208, // ceil(17664/8)
    vec_k_size_bytes: 16,
    gf_poly: 0x11D,
    gf_mul_order: 255,
    rm_order: 7,
    multiplicity: 3, // 384 / 128
};

/// HQC-192: NIST security level 3 (192-bit).
pub const HQC192: Params = Params {
    name: "HQC-192",
    n: 35851,
    n1: 56,
    n2: 640,
    n1n2: 35840, // 56 * 640
    k: 24,
    delta: 16,
    g: 33, // 2*16 + 1
    w: 100,
    wr: 117,
    we: 117,
    pk_size: 4522,
    sk_size: 4562,
    ct_size: 9026,
    ss_size: SHARED_SECRET_BYTES,
    vec_n_size64: 561,    // ceil(35851/64)
    vec_n_size_bytes: 4482, // ceil(35851/8)
    vec_n1n2_size64: 560,    // ceil(35840/64)
    vec_n1n2_size_bytes: 4480, // ceil(35840/8)
    vec_k_size_bytes: 24,
    gf_poly: 0x11D,
    gf_mul_order: 255,
    rm_order: 7,
    multiplicity: 5, // 640 / 128
};

/// HQC-256: NIST security level 5 (256-bit).
pub const HQC256: Params = Params {
    name: "HQC-256",
    n: 57637,
    n1: 90,
    n2: 640,
    n1n2: 57600, // 90 * 640
    k: 32,
    delta: 29,
    g: 59, // 2*29 + 1
    w: 131,
    wr: 153,
    we: 153,
    pk_size: 7245,
    sk_size: 7285,
    ct_size: 14469,
    ss_size: SHARED_SECRET_BYTES,
    vec_n_size64: 901,    // ceil(57637/64)
    vec_n_size_bytes: 7205, // ceil(57637/8)
    vec_n1n2_size64: 900,    // ceil(57600/64)
    vec_n1n2_size_bytes: 7200, // ceil(57600/8)
    vec_k_size_bytes: 32,
    gf_poly: 0x11D,
    gf_mul_order: 255,
    rm_order: 7,
    multiplicity: 5, // 640 / 128
};

/// Returns all supported HQC parameter sets.
pub fn all_params() -> [&'static Params; 3] {
    [&HQC128, &HQC192, &HQC256]
}
