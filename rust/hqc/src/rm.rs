/// Reed-Muller code RM(1, 7) for HQC.
///
/// The first-order Reed-Muller code RM(1, 7) encodes 8 bits (1 byte)
/// into 128 bits (16 bytes). The encoding uses the generator matrix
/// of RM(1, 7), which consists of the all-ones word and the 7 rows
/// of the Walsh-Hadamard basis vectors.
///
/// For HQC, the RM codeword is then duplicated (`multiplicity` times)
/// to form an n2-bit codeword for additional error correction.

/// Base Reed-Muller codeword length = 2^7 = 128 bits.
const RM_BASE_LEN: usize = 128;

/// Encodes a single byte (8 bits) into a 128-bit RM(1,7) codeword.
/// Returns `[lo, hi]` representing 128 bits.
pub fn rm_encode_base(msg: u8) -> [u64; 2] {
    let expand = |bit: u32| -> u64 {
        -(((msg >> bit) & 1) as i64) as u64
    };

    let mut lo = 0u64;
    let mut hi = 0u64;

    // Bit 0: constant row (all-ones if set)
    lo ^= expand(0);
    hi ^= expand(0);

    // Bit 1: pattern 0xAAAAAAAAAAAAAAAA
    lo ^= expand(1) & 0xAAAAAAAAAAAAAAAA;
    hi ^= expand(1) & 0xAAAAAAAAAAAAAAAA;

    // Bit 2: pattern 0xCCCCCCCCCCCCCCCC
    lo ^= expand(2) & 0xCCCCCCCCCCCCCCCC;
    hi ^= expand(2) & 0xCCCCCCCCCCCCCCCC;

    // Bit 3: pattern 0xF0F0F0F0F0F0F0F0
    lo ^= expand(3) & 0xF0F0F0F0F0F0F0F0;
    hi ^= expand(3) & 0xF0F0F0F0F0F0F0F0;

    // Bit 4: pattern 0xFF00FF00FF00FF00
    lo ^= expand(4) & 0xFF00FF00FF00FF00;
    hi ^= expand(4) & 0xFF00FF00FF00FF00;

    // Bit 5: pattern 0xFFFF0000FFFF0000
    lo ^= expand(5) & 0xFFFF0000FFFF0000;
    hi ^= expand(5) & 0xFFFF0000FFFF0000;

    // Bit 6: pattern 0xFFFFFFFF00000000
    lo ^= expand(6) & 0xFFFFFFFF00000000;
    hi ^= expand(6) & 0xFFFFFFFF00000000;

    // Bit 7: (0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
    hi ^= expand(7);

    [lo, hi]
}

/// Encodes a byte into the dst vector starting at `bit_offset`,
/// repeating the base codeword `multiplicity` times.
pub fn rm_encode_into(dst: &mut [u64], msg: u8, bit_offset: usize, multiplicity: usize) {
    let base = rm_encode_base(msg);

    let mut bit_pos = bit_offset;
    for _rep in 0..multiplicity {
        for w in 0..2 {
            let word = base[w];
            let dst_word = bit_pos / 64;
            let dst_bit = bit_pos % 64;

            if dst_bit == 0 && dst_word < dst.len() {
                dst[dst_word] ^= word;
                bit_pos += 64;
            } else {
                for bit in 0..64 {
                    if word & (1u64 << bit) != 0 {
                        let idx = bit_pos / 64;
                        let off = bit_pos % 64;
                        if idx < dst.len() {
                            dst[idx] ^= 1u64 << off;
                        }
                    }
                    bit_pos += 1;
                }
            }
        }
    }
}

/// Decodes an n2-bit received codeword (with duplicated RM(1,7))
/// to a single byte using Walsh-Hadamard transform.
pub fn rm_decode(src: &[u64], n2: usize, multiplicity: usize) -> u8 {
    // Step 1: Accumulate all copies into signed sums
    let mut sums = [0i32; RM_BASE_LEN];

    let mut bit_pos = 0usize;
    for _rep in 0..multiplicity {
        for i in 0..RM_BASE_LEN {
            let word_idx = bit_pos / 64;
            let bit_idx = bit_pos % 64;
            let bit = if word_idx < src.len() {
                ((src[word_idx] >> bit_idx) & 1) as i32
            } else {
                0
            };
            // Convert 0/1 to +1/-1 (0 -> +1, 1 -> -1)
            sums[i] += 1 - 2 * bit;
            bit_pos += 1;
        }
    }
    let _ = n2; // n2 is implicitly multiplicity * 128

    // Step 2: Fast Walsh-Hadamard Transform (in-place, 7 passes)
    for pass in 0..7 {
        let step = 1 << pass;
        let mut i = 0;
        while i < RM_BASE_LEN {
            for j in i..i + step {
                let a = sums[j];
                let b = sums[j + step];
                sums[j] = a + b;
                sums[j + step] = a - b;
            }
            i += 2 * step;
        }
    }

    // Step 3: Find position with maximum absolute value
    let mut max_abs = 0i32;
    let mut max_pos = 0usize;
    let mut sign = 1i32;

    for i in 0..RM_BASE_LEN {
        let v = sums[i];
        let abs = v.abs();
        if abs > max_abs {
            max_abs = abs;
            max_pos = i;
            sign = if v > 0 { 1 } else { -1 };
        }
    }

    // Step 4: Recover message byte
    let mut msg = (max_pos << 1) as u8;
    if sign < 0 {
        msg |= 1;
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rm_roundtrip_all_bytes() {
        for m in 0..=255u8 {
            for &mult in &[3, 5] {
                let n2 = mult * 128;
                let n_words = (n2 + 63) / 64;
                let mut cw = vec![0u64; n_words];
                rm_encode_into(&mut cw, m, 0, mult);
                let decoded = rm_decode(&cw, n2, mult);
                assert_eq!(decoded, m, "RM mult={} msg={}: got {}", mult, m, decoded);
            }
        }
    }
}
