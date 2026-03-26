//! ML-KEM parameter sets as defined in FIPS 203, Table 1.
//!
//! Three parameter sets are defined, offering NIST security levels 1, 3, and 5.

/// Trait defining an ML-KEM parameter set.
///
/// Each parameter set determines the module rank, noise distribution parameters,
/// and compression bit widths that collectively define the security/performance
/// trade-off.
pub trait ParameterSet {
    /// Module rank (number of polynomials in vectors).
    const K: usize;
    /// CBD parameter for secret/noise in KeyGen.
    const ETA1: usize;
    /// CBD parameter for noise in Encrypt.
    const ETA2: usize;
    /// Compression bits for vector u in ciphertext.
    const DU: usize;
    /// Compression bits for polynomial v in ciphertext.
    const DV: usize;
    /// Encapsulation key size in bytes: 384*k + 32.
    const EK_SIZE: usize = 384 * Self::K + 32;
    /// Decapsulation key size in bytes: 768*k + 96.
    const DK_SIZE: usize = 768 * Self::K + 96;
    /// Ciphertext size in bytes: 32*(du*k + dv).
    const CT_SIZE: usize = 32 * (Self::DU * Self::K + Self::DV);
}

/// ML-KEM-512: NIST Security Level 1 (128-bit classical security).
pub struct MlKem512;

impl ParameterSet for MlKem512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

/// ML-KEM-768: NIST Security Level 3 (192-bit classical security).
///
/// This is the recommended parameter set for most applications.
pub struct MlKem768;

impl ParameterSet for MlKem768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

/// ML-KEM-1024: NIST Security Level 5 (256-bit classical security).
pub struct MlKem1024;

impl ParameterSet for MlKem1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem512_params() {
        assert_eq!(MlKem512::K, 2);
        assert_eq!(MlKem512::ETA1, 3);
        assert_eq!(MlKem512::ETA2, 2);
        assert_eq!(MlKem512::DU, 10);
        assert_eq!(MlKem512::DV, 4);
        assert_eq!(MlKem512::EK_SIZE, 800);
        assert_eq!(MlKem512::DK_SIZE, 1632);
        assert_eq!(MlKem512::CT_SIZE, 768);
    }

    #[test]
    fn test_mlkem768_params() {
        assert_eq!(MlKem768::K, 3);
        assert_eq!(MlKem768::ETA1, 2);
        assert_eq!(MlKem768::ETA2, 2);
        assert_eq!(MlKem768::DU, 10);
        assert_eq!(MlKem768::DV, 4);
        assert_eq!(MlKem768::EK_SIZE, 1184);
        assert_eq!(MlKem768::DK_SIZE, 2400);
        assert_eq!(MlKem768::CT_SIZE, 1088);
    }

    #[test]
    fn test_mlkem1024_params() {
        assert_eq!(MlKem1024::K, 4);
        assert_eq!(MlKem1024::ETA1, 2);
        assert_eq!(MlKem1024::ETA2, 2);
        assert_eq!(MlKem1024::DU, 11);
        assert_eq!(MlKem1024::DV, 5);
        assert_eq!(MlKem1024::EK_SIZE, 1568);
        assert_eq!(MlKem1024::DK_SIZE, 3168);
        assert_eq!(MlKem1024::CT_SIZE, 1568);
    }
}
