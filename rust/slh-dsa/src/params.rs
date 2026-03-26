//! SLH-DSA (FIPS 205) parameter sets.
//!
//! Defines the twelve standardized parameter sets across two hash families
//! (SHA2 and SHAKE) and three security levels (128, 192, 256), each with
//! a fast (f) and small (s) variant.


/// Winternitz parameter (shared by all SLH-DSA instances).
pub const W: usize = 16;

/// Log base 2 of the Winternitz parameter.
pub const LG_W: usize = 4;

/// Trait describing an SLH-DSA parameter set.
///
/// Implementors provide the constants that vary between security levels and
/// hash families. All sizes are in bytes unless otherwise noted.
pub trait ParamSet {
    /// Security parameter in bytes (16, 24, or 32).
    const N: usize;

    /// Total tree height: h = d * hp.
    const H: usize;

    /// Number of hypertree layers.
    const D: usize;

    /// Height of each XMSS tree within a hypertree layer: hp = h / d.
    const HP: usize;

    /// Number of FORS tree leaves (log2): each FORS tree has 2^a leaves.
    const A: usize;

    /// Number of FORS trees.
    const K: usize;

    /// WOTS+ chain count: len = len1 + len2.
    const LEN: usize;

    /// WOTS+ message blocks: len1 = ceil(8*n / lg_w) = 2*n (when lg_w = 4).
    const LEN1: usize;

    /// WOTS+ checksum blocks: len2 = floor(log_w(len1 * (w - 1))) + 1 = 3.
    const LEN2: usize;

    /// Public key size in bytes: 2 * n (PK.seed || PK.root).
    const PK_SIZE: usize = 2 * Self::N;

    /// Secret key size in bytes: 4 * n (SK.seed || SK.prf || PK.seed || PK.root).
    const SK_SIZE: usize = 4 * Self::N;

    /// Signature size in bytes.
    ///
    /// sig = R (n bytes randomizer)
    ///     + SIG_FORS (k * (1 + a) * n bytes)
    ///     + SIG_HT (d * (len + hp) * n bytes)
    const SIG_SIZE: usize =
        Self::N + Self::K * (1 + Self::A) * Self::N + Self::D * (Self::LEN + Self::HP) * Self::N;
}

// ---------------------------------------------------------------------------
// SHA2 parameter sets
// ---------------------------------------------------------------------------

/// SLH-DSA-SHA2-128f: fast variant, 128-bit security, SHA-256 based.
pub struct Sha2_128f;

impl ParamSet for Sha2_128f {
    const N: usize = 16;
    const H: usize = 66;
    const D: usize = 22;
    const HP: usize = 3;
    const A: usize = 6;
    const K: usize = 33;
    const LEN: usize = 35;
    const LEN1: usize = 32;
    const LEN2: usize = 3;
}

/// SLH-DSA-SHA2-128s: small variant, 128-bit security, SHA-256 based.
pub struct Sha2_128s;

impl ParamSet for Sha2_128s {
    const N: usize = 16;
    const H: usize = 63;
    const D: usize = 7;
    const HP: usize = 9;
    const A: usize = 12;
    const K: usize = 14;
    const LEN: usize = 35;
    const LEN1: usize = 32;
    const LEN2: usize = 3;
}

/// SLH-DSA-SHA2-192f: fast variant, 192-bit security, SHA-512 based.
pub struct Sha2_192f;

impl ParamSet for Sha2_192f {
    const N: usize = 24;
    const H: usize = 66;
    const D: usize = 22;
    const HP: usize = 3;
    const A: usize = 8;
    const K: usize = 33;
    const LEN: usize = 51;
    const LEN1: usize = 48;
    const LEN2: usize = 3;
}

/// SLH-DSA-SHA2-192s: small variant, 192-bit security, SHA-512 based.
pub struct Sha2_192s;

impl ParamSet for Sha2_192s {
    const N: usize = 24;
    const H: usize = 63;
    const D: usize = 7;
    const HP: usize = 9;
    const A: usize = 14;
    const K: usize = 17;
    const LEN: usize = 51;
    const LEN1: usize = 48;
    const LEN2: usize = 3;
}

/// SLH-DSA-SHA2-256f: fast variant, 256-bit security, SHA-512 based.
pub struct Sha2_256f;

impl ParamSet for Sha2_256f {
    const N: usize = 32;
    const H: usize = 68;
    const D: usize = 17;
    const HP: usize = 4;
    const A: usize = 9;
    const K: usize = 35;
    const LEN: usize = 67;
    const LEN1: usize = 64;
    const LEN2: usize = 3;
}

/// SLH-DSA-SHA2-256s: small variant, 256-bit security, SHA-512 based.
pub struct Sha2_256s;

impl ParamSet for Sha2_256s {
    const N: usize = 32;
    const H: usize = 64;
    const D: usize = 8;
    const HP: usize = 8;
    const A: usize = 14;
    const K: usize = 22;
    const LEN: usize = 67;
    const LEN1: usize = 64;
    const LEN2: usize = 3;
}

// ---------------------------------------------------------------------------
// SHAKE parameter sets (identical structural parameters to SHA2 counterparts)
// ---------------------------------------------------------------------------

/// SLH-DSA-SHAKE-128f: fast variant, 128-bit security, SHAKE-256 based.
#[allow(non_camel_case_types)]
pub struct Shake_128f;

impl ParamSet for Shake_128f {
    const N: usize = 16;
    const H: usize = 66;
    const D: usize = 22;
    const HP: usize = 3;
    const A: usize = 6;
    const K: usize = 33;
    const LEN: usize = 35;
    const LEN1: usize = 32;
    const LEN2: usize = 3;
}

/// SLH-DSA-SHAKE-128s: small variant, 128-bit security, SHAKE-256 based.
#[allow(non_camel_case_types)]
pub struct Shake_128s;

impl ParamSet for Shake_128s {
    const N: usize = 16;
    const H: usize = 63;
    const D: usize = 7;
    const HP: usize = 9;
    const A: usize = 12;
    const K: usize = 14;
    const LEN: usize = 35;
    const LEN1: usize = 32;
    const LEN2: usize = 3;
}

/// SLH-DSA-SHAKE-192f: fast variant, 192-bit security, SHAKE-256 based.
#[allow(non_camel_case_types)]
pub struct Shake_192f;

impl ParamSet for Shake_192f {
    const N: usize = 24;
    const H: usize = 66;
    const D: usize = 22;
    const HP: usize = 3;
    const A: usize = 8;
    const K: usize = 33;
    const LEN: usize = 51;
    const LEN1: usize = 48;
    const LEN2: usize = 3;
}

/// SLH-DSA-SHAKE-192s: small variant, 192-bit security, SHAKE-256 based.
#[allow(non_camel_case_types)]
pub struct Shake_192s;

impl ParamSet for Shake_192s {
    const N: usize = 24;
    const H: usize = 63;
    const D: usize = 7;
    const HP: usize = 9;
    const A: usize = 14;
    const K: usize = 17;
    const LEN: usize = 51;
    const LEN1: usize = 48;
    const LEN2: usize = 3;
}

/// SLH-DSA-SHAKE-256f: fast variant, 256-bit security, SHAKE-256 based.
#[allow(non_camel_case_types)]
pub struct Shake_256f;

impl ParamSet for Shake_256f {
    const N: usize = 32;
    const H: usize = 68;
    const D: usize = 17;
    const HP: usize = 4;
    const A: usize = 9;
    const K: usize = 35;
    const LEN: usize = 67;
    const LEN1: usize = 64;
    const LEN2: usize = 3;
}

/// SLH-DSA-SHAKE-256s: small variant, 256-bit security, SHAKE-256 based.
#[allow(non_camel_case_types)]
pub struct Shake_256s;

impl ParamSet for Shake_256s {
    const N: usize = 32;
    const H: usize = 64;
    const D: usize = 8;
    const HP: usize = 8;
    const A: usize = 14;
    const K: usize = 22;
    const LEN: usize = 67;
    const LEN1: usize = 64;
    const LEN2: usize = 3;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify WOTS+ length derivation: len1 = 2*n (when lg_w=4), len = len1 + len2.
    fn check_wots_len<P: ParamSet>() {
        assert_eq!(P::LEN1, 2 * P::N, "len1 mismatch for n={}", P::N);
        assert_eq!(P::LEN2, 3, "len2 should be 3 for all param sets");
        assert_eq!(P::LEN, P::LEN1 + P::LEN2, "len mismatch for n={}", P::N);
    }

    /// Verify h = d * hp.
    fn check_tree_height<P: ParamSet>() {
        assert_eq!(P::H, P::D * P::HP, "h != d*hp for n={}", P::N);
    }

    /// Verify key and signature sizes.
    fn check_sizes<P: ParamSet>(expected_pk: usize, expected_sk: usize, expected_sig: usize) {
        assert_eq!(P::PK_SIZE, expected_pk, "pk_size mismatch");
        assert_eq!(P::SK_SIZE, expected_sk, "sk_size mismatch");
        assert_eq!(P::SIG_SIZE, expected_sig, "sig_size mismatch");
    }

    #[test]
    fn test_wots_lengths() {
        check_wots_len::<Sha2_128f>();
        check_wots_len::<Sha2_128s>();
        check_wots_len::<Sha2_192f>();
        check_wots_len::<Sha2_192s>();
        check_wots_len::<Sha2_256f>();
        check_wots_len::<Sha2_256s>();
        check_wots_len::<Shake_128f>();
        check_wots_len::<Shake_128s>();
        check_wots_len::<Shake_192f>();
        check_wots_len::<Shake_192s>();
        check_wots_len::<Shake_256f>();
        check_wots_len::<Shake_256s>();
    }

    #[test]
    fn test_tree_heights() {
        check_tree_height::<Sha2_128f>();
        check_tree_height::<Sha2_128s>();
        check_tree_height::<Sha2_192f>();
        check_tree_height::<Sha2_192s>();
        check_tree_height::<Sha2_256f>();
        check_tree_height::<Sha2_256s>();
    }

    #[test]
    fn test_key_sizes() {
        // pk = 2*n, sk = 4*n
        assert_eq!(Sha2_128f::PK_SIZE, 32);
        assert_eq!(Sha2_128f::SK_SIZE, 64);
        assert_eq!(Sha2_192f::PK_SIZE, 48);
        assert_eq!(Sha2_192f::SK_SIZE, 96);
        assert_eq!(Sha2_256f::PK_SIZE, 64);
        assert_eq!(Sha2_256f::SK_SIZE, 128);
    }

    #[test]
    fn test_sig_sizes_128() {
        // FIPS 205 Table 1 values
        check_sizes::<Sha2_128f>(32, 64, 17_088);
        check_sizes::<Sha2_128s>(32, 64, 7_856);
    }

    #[test]
    fn test_sig_sizes_192() {
        check_sizes::<Sha2_192f>(48, 96, 35_664);
        check_sizes::<Sha2_192s>(48, 96, 16_224);
    }

    #[test]
    fn test_sig_sizes_256() {
        check_sizes::<Sha2_256f>(64, 128, 49_856);
        check_sizes::<Sha2_256s>(64, 128, 29_792);
    }

    #[test]
    fn test_shake_matches_sha2() {
        // SHAKE variants have identical structural parameters
        assert_eq!(Shake_128f::SIG_SIZE, Sha2_128f::SIG_SIZE);
        assert_eq!(Shake_128s::SIG_SIZE, Sha2_128s::SIG_SIZE);
        assert_eq!(Shake_192f::SIG_SIZE, Sha2_192f::SIG_SIZE);
        assert_eq!(Shake_192s::SIG_SIZE, Sha2_192s::SIG_SIZE);
        assert_eq!(Shake_256f::SIG_SIZE, Sha2_256f::SIG_SIZE);
        assert_eq!(Shake_256s::SIG_SIZE, Sha2_256s::SIG_SIZE);
    }

    #[test]
    fn test_len2_values() {
        // For all param sets, len2 = 3 (when lg_w = 4)
        assert_eq!(Sha2_128f::LEN2, 3);
        assert_eq!(Sha2_192f::LEN2, 3);
        assert_eq!(Sha2_256f::LEN2, 3);
    }
}
