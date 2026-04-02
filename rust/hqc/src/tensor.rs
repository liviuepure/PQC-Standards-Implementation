/// Tensor product code: concatenated RS (outer) x RM (inner) code.
///
/// Encoding: message m (k bytes) -> RS encode to n1 bytes -> each byte RM-encoded
/// to n2 bits -> total n1*n2 bits.
///
/// Decoding: received n1*n2 bits -> split into n1 blocks of n2 bits each ->
/// RM-decode each block to get n1 bytes -> RS-decode to get k bytes.

use crate::params::Params;
use crate::rm::{rm_decode, rm_encode_into};
use crate::rs::{rs_decode, rs_encode};

/// Encodes a k-byte message into an n1*n2-bit codeword.
pub fn tensor_encode(msg: &[u8], p: &Params) -> Vec<u64> {
    // Step 1: RS encode the message
    let rs_codeword = rs_encode(msg, p);

    // Step 2: RM encode each RS symbol
    let mut out = vec![0u64; p.vec_n1n2_size64];

    for i in 0..p.n1 {
        rm_encode_into(&mut out, rs_codeword[i], i * p.n2, p.multiplicity);
    }

    out
}

/// Decodes a received n1*n2-bit word back to a k-byte message.
pub fn tensor_decode(received: &[u64], p: &Params) -> (Vec<u8>, bool) {
    // Step 1: RM-decode each block of n2 bits to get one byte
    let mut rs_received = vec![0u8; p.n1];

    for i in 0..p.n1 {
        let block = extract_bits(received, i * p.n2, p.n2);
        rs_received[i] = rm_decode(&block, p.n2, p.multiplicity);
    }

    // Step 2: RS-decode the n1-byte received word to get k bytes
    rs_decode(&rs_received, p)
}

/// Extracts `n_bits` bits from `src` starting at `bit_offset`,
/// returning them as a `Vec<u64>` vector.
fn extract_bits(src: &[u64], bit_offset: usize, n_bits: usize) -> Vec<u64> {
    let n_words = (n_bits + 63) / 64;
    let mut out = vec![0u64; n_words];

    let src_word = bit_offset / 64;
    let src_bit = bit_offset % 64;

    if src_bit == 0 {
        for i in 0..n_words {
            if src_word + i < src.len() {
                out[i] = src[src_word + i];
            }
        }
    } else {
        for i in 0..n_words {
            let idx = src_word + i;
            if idx < src.len() {
                out[i] = src[idx] >> src_bit;
            }
            if idx + 1 < src.len() {
                out[i] |= src[idx + 1] << (64 - src_bit);
            }
        }
    }

    // Mask last word
    let rem = n_bits % 64;
    if rem != 0 && n_words > 0 {
        out[n_words - 1] &= (1u64 << rem) - 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::*;

    #[test]
    fn test_tensor_roundtrip() {
        for p in all_params() {
            let mut msg = vec![0u8; p.k];
            for i in 0..p.k {
                msg[i] = (i + 42) as u8;
            }
            let encoded = tensor_encode(&msg, p);
            let (decoded, ok) = tensor_decode(&encoded, p);
            assert!(ok, "{}: tensor decode failed", p.name);
            assert_eq!(decoded, msg, "{}: tensor roundtrip mismatch", p.name);
        }
    }
}
