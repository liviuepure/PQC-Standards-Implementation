//! Byte encoding and decoding for ML-KEM polynomials.
//!
//! FIPS 203, Algorithms 5 (ByteEncode) and 6 (ByteDecode).
//!
//! ByteEncode_d packs 256 d-bit integers into 32*d bytes.
//! ByteDecode_d unpacks 32*d bytes into 256 integers.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use pqc_common::field::{FieldElement, Q};

/// Encodes 256 field elements into 32*d bytes. FIPS 203, Algorithm 5.
///
/// Each coefficient is treated as a d-bit integer and bit-packed
/// sequentially into the output byte array.
pub fn byte_encode<const D: usize>(f: &[FieldElement; 256]) -> Vec<u8> {
    let mut output = vec![0u8; 32 * D];
    let mut bit_index = 0usize;
    for i in 0..256 {
        let mut val = f[i].value() as u32;
        for _ in 0..D {
            if val & 1 == 1 {
                output[bit_index / 8] |= 1 << (bit_index % 8);
            }
            bit_index += 1;
            val >>= 1;
        }
    }
    output
}

/// Decodes 32*d bytes into 256 field elements. FIPS 203, Algorithm 6.
///
/// For d < 12, output values are in [0, 2^d).
/// For d = 12, output values are reduced modulo q = 3329.
pub fn byte_decode<const D: usize>(bytes: &[u8]) -> [FieldElement; 256] {
    debug_assert_eq!(bytes.len(), 32 * D);
    let mut f = [FieldElement::ZERO; 256];
    let mut bit_index = 0usize;
    for i in 0..256 {
        let mut val = 0u32;
        for b in 0..D {
            let bit = (bytes[bit_index / 8] >> (bit_index % 8)) & 1;
            val |= (bit as u32) << b;
            bit_index += 1;
        }
        if D == 12 {
            f[i] = FieldElement::new((val % Q as u32) as u16);
        } else {
            f[i] = FieldElement::new(val as u16);
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip_d1() {
        let coeffs: [FieldElement; 256] =
            core::array::from_fn(|i| FieldElement::new((i & 1) as u16));
        let encoded = byte_encode::<1>(&coeffs);
        assert_eq!(encoded.len(), 32);
        let decoded = byte_decode::<1>(&encoded);
        for i in 0..256 {
            assert_eq!(decoded[i].value(), coeffs[i].value(), "d=1 mismatch at {i}");
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_d4() {
        let coeffs: [FieldElement; 256] =
            core::array::from_fn(|i| FieldElement::new((i % 16) as u16));
        let encoded = byte_encode::<4>(&coeffs);
        assert_eq!(encoded.len(), 128);
        let decoded = byte_decode::<4>(&encoded);
        for i in 0..256 {
            assert_eq!(decoded[i].value(), coeffs[i].value(), "d=4 mismatch at {i}");
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_d10() {
        let coeffs: [FieldElement; 256] =
            core::array::from_fn(|i| FieldElement::new(((i * 4) % 1024) as u16));
        let encoded = byte_encode::<10>(&coeffs);
        assert_eq!(encoded.len(), 320);
        let decoded = byte_decode::<10>(&encoded);
        for i in 0..256 {
            assert_eq!(decoded[i].value(), coeffs[i].value(), "d=10 mismatch at {i}");
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_d12() {
        let coeffs: [FieldElement; 256] =
            core::array::from_fn(|i| FieldElement::new(((i * 13) % 3329) as u16));
        let encoded = byte_encode::<12>(&coeffs);
        assert_eq!(encoded.len(), 384);
        let decoded = byte_decode::<12>(&encoded);
        for i in 0..256 {
            assert_eq!(decoded[i].value(), coeffs[i].value(), "d=12 mismatch at {i}");
        }
    }

    #[test]
    fn test_encode_zero() {
        let zero = [FieldElement::ZERO; 256];
        let encoded = byte_encode::<12>(&zero);
        assert!(encoded.iter().all(|&b| b == 0));
    }
}
