// FIPS 206 key and signature encoding/decoding for FN-DSA.
// Ported from the Go reference. All bit-packing is LSB-first.

use crate::params::Params;

// --- Public key encoding (14 bits per NTT coefficient) ---

/// Encodes NTT public-key polynomial h into FIPS 206 format.
/// byte 0: 0x00 | log_n, bytes 1..: 14-bit packed coefficients LSB-first.
pub fn encode_pk(h: &[i32], p: Params) -> Vec<u8> {
    let mut out = vec![0u8; p.pk_size];
    out[0] = (0x00 | p.log_n) as u8;
    pack_bits14(&mut out[1..], h, p.n);
    out
}

/// Decodes a FIPS 206 public key. Returns None if format is wrong.
pub fn decode_pk(data: &[u8], p: Params) -> Option<Vec<i32>> {
    if data.len() != p.pk_size {
        return None;
    }
    if data[0] != (0x00 | p.log_n) as u8 {
        return None;
    }
    Some(unpack_bits14(&data[1..], p.n))
}

// --- Secret key encoding ---

fn fg_bits_for(p: Params) -> usize {
    if p.n == 1024 { 5 } else { 6 }
}

/// Encodes (f, g, F) into FIPS 206 secret-key format.
pub fn encode_sk(f: &[i32], g: &[i32], cap_f: &[i32], p: Params) -> Vec<u8> {
    let mut out = vec![0u8; p.sk_size];
    out[0] = (0x50 | p.log_n) as u8;
    let fg_bits = fg_bits_for(p);
    let mut offset = 1usize;
    pack_signed_bits(&mut out[offset..], f, p.n, fg_bits);
    offset += (p.n * fg_bits) / 8;
    pack_signed_bits(&mut out[offset..], g, p.n, fg_bits);
    offset += (p.n * fg_bits) / 8;
    pack_signed_bits(&mut out[offset..], cap_f, p.n, 8);
    out
}

/// Decodes a FIPS 206 secret key. Returns None on format error.
pub fn decode_sk(data: &[u8], p: Params) -> Option<(Vec<i32>, Vec<i32>, Vec<i32>)> {
    if data.len() != p.sk_size {
        return None;
    }
    if data[0] != (0x50 | p.log_n) as u8 {
        return None;
    }
    let fg_bits = fg_bits_for(p);
    let mut offset = 1usize;
    let f = unpack_signed_bits(&data[offset..], p.n, fg_bits);
    offset += (p.n * fg_bits) / 8;
    let g = unpack_signed_bits(&data[offset..], p.n, fg_bits);
    offset += (p.n * fg_bits) / 8;
    let cap_f = unpack_signed_bits(&data[offset..], p.n, 8);
    Some((f, g, cap_f))
}

// --- Signature encoding ---

fn lo_bits_for(p: Params) -> usize {
    if p.n == 1024 { 7 } else { 6 }
}

/// Encodes a signature into FIPS 206 format.
/// Returns None if compressed s1 exceeds capacity.
pub fn encode_sig(salt: &[u8], s1: &[i32], p: Params) -> Option<Vec<u8>> {
    let capacity = p.sig_max_len - 41;
    let mut comp_buf = vec![0u8; capacity];
    let used = compress_s1(&mut comp_buf, s1, p.n, lo_bits_for(p))?;

    let mut out = if p.padded {
        vec![0u8; p.sig_size]
    } else {
        vec![0u8; 1 + 40 + used]
    };
    out[0] = (0x30 | p.log_n) as u8;
    out[1..41].copy_from_slice(salt);
    out[41..41 + used].copy_from_slice(&comp_buf[..used]);
    Some(out)
}

/// Decodes a FIPS 206 signature. Returns None on format error.
pub fn decode_sig(data: &[u8], p: Params) -> Option<(Vec<u8>, Vec<i32>)> {
    if data.len() < 41 {
        return None;
    }
    if data[0] != (0x30 | p.log_n) as u8 {
        return None;
    }
    if p.padded {
        if data.len() != p.sig_size {
            return None;
        }
    } else {
        if data.len() > p.sig_max_len {
            return None;
        }
    }
    let mut salt = vec![0u8; 40];
    salt.copy_from_slice(&data[1..41]);
    let s1 = decompress_s1(&data[41..], p.n, lo_bits_for(p))?;
    Some((salt, s1))
}

// --- Internal bit-packing helpers ---

/// Packs n 14-bit coefficients LSB-first into dst.
fn pack_bits14(dst: &mut [u8], src: &[i32], n: usize) {
    let mut cursor = 0usize;
    for i in 0..n {
        let v = src[i] as u32 & 0x3FFF;
        let byte_idx = cursor >> 3;
        let bit_idx = (cursor & 7) as u32;
        dst[byte_idx] |= (v << bit_idx) as u8;
        if bit_idx == 0 {
            dst[byte_idx + 1] |= (v >> 8) as u8;
        } else {
            dst[byte_idx + 1] |= (v >> (8 - bit_idx)) as u8;
            if bit_idx > 2 {
                dst[byte_idx + 2] |= (v >> (16 - bit_idx)) as u8;
            }
        }
        cursor += 14;
    }
}

/// Unpacks n 14-bit coefficients LSB-first from src.
fn unpack_bits14(src: &[u8], n: usize) -> Vec<i32> {
    let mut out = vec![0i32; n];
    let mut cursor = 0usize;
    for i in 0..n {
        let byte_idx = cursor >> 3;
        let bit_idx = (cursor & 7) as u32;
        let v: u32 = if bit_idx == 0 {
            (src[byte_idx] as u32) | (src[byte_idx + 1] as u32) << 8
        } else {
            let mut val = (src[byte_idx] as u32) >> bit_idx;
            val |= (src[byte_idx + 1] as u32) << (8 - bit_idx);
            if bit_idx > 2 {
                val |= (src[byte_idx + 2] as u32) << (16 - bit_idx);
            }
            val
        };
        out[i] = (v & 0x3FFF) as i32;
        cursor += 14;
    }
    out
}

/// Packs n signed integers at `bits` bits each, two's complement, LSB-first, into dst.
fn pack_signed_bits(dst: &mut [u8], src: &[i32], n: usize, bits: usize) {
    let mask = ((1u32 << bits) - 1) as u32;
    let mut cursor = 0usize;
    for i in 0..n {
        let mut v = src[i] as u32 & mask;
        let mut rem = bits;
        let mut cur = cursor;
        while rem > 0 {
            let byte_idx = cur >> 3;
            let bit_idx = cur & 7;
            let avail = 8 - bit_idx;
            let chunk = rem.min(avail);
            dst[byte_idx] |= ((v & ((1 << chunk) - 1)) << bit_idx) as u8;
            v >>= chunk;
            cur += chunk;
            rem -= chunk;
        }
        cursor += bits;
    }
}

/// Reads n signed integers of `bits` bits each, two's complement, LSB-first, sign-extended to i32.
fn unpack_signed_bits(src: &[u8], n: usize, bits: usize) -> Vec<i32> {
    let mut out = vec![0i32; n];
    let mask = ((1u32 << bits) - 1) as u32;
    let sign_bit = 1u32 << (bits - 1);
    let mut cursor = 0usize;
    for i in 0..n {
        let mut v = 0u32;
        let mut rem = bits;
        let mut cur = cursor;
        let mut shift = 0usize;
        while rem > 0 {
            let byte_idx = cur >> 3;
            let bit_idx = cur & 7;
            let avail = 8 - bit_idx;
            let chunk = rem.min(avail);
            let b = (src[byte_idx] >> bit_idx) as u32 & ((1 << chunk) - 1);
            v |= b << shift;
            shift += chunk;
            cur += chunk;
            rem -= chunk;
        }
        v &= mask;
        if v & sign_bit != 0 {
            v |= !mask;
        }
        out[i] = v as i32;
        cursor += bits;
    }
    out
}

/// Encodes s1 using FIPS 206 variable-length scheme with parameter lo.
/// Returns Some(bytes_used) on success, None if capacity exceeded.
fn compress_s1(dst: &mut [u8], s1: &[i32], n: usize, lo: usize) -> Option<usize> {
    let lo_mask = ((1i32 << lo) - 1) as i32;
    let mut cursor = 0usize;
    let capacity = dst.len() * 8;

    let write_bit = |dst: &mut [u8], bit: u8, cursor: &mut usize| -> bool {
        if *cursor >= capacity {
            return false;
        }
        if bit != 0 {
            dst[*cursor >> 3] |= 1 << (*cursor & 7);
        }
        *cursor += 1;
        true
    };

    for i in 0..n {
        let s = s1[i];
        let v = s.abs();
        let low = v & lo_mask;
        let high = v >> lo;

        // Emit lo bits of low, LSB-first.
        for b in 0..lo {
            if !write_bit(dst, ((low >> b) & 1) as u8, &mut cursor) {
                return None;
            }
        }
        // Emit high 1-bits.
        for _ in 0..high {
            if !write_bit(dst, 1, &mut cursor) {
                return None;
            }
        }
        // Emit terminating 0-bit.
        if !write_bit(dst, 0, &mut cursor) {
            return None;
        }
        // Emit sign bit (1 if negative, 0 otherwise).
        let sign_bit = if s < 0 { 1 } else { 0 };
        if !write_bit(dst, sign_bit, &mut cursor) {
            return None;
        }
    }

    Some((cursor + 7) / 8)
}

/// Decodes n coefficients from src using FIPS 206 variable-length scheme with parameter lo.
fn decompress_s1(src: &[u8], n: usize, lo: usize) -> Option<Vec<i32>> {
    let total_bits = src.len() * 8;
    let mut cursor = 0usize;

    let read_bit = |cursor: &mut usize| -> Option<u8> {
        if *cursor >= total_bits {
            return None;
        }
        let bit = (src[*cursor >> 3] >> (*cursor & 7)) & 1;
        *cursor += 1;
        Some(bit)
    };

    let mut out = vec![0i32; n];
    for i in 0..n {
        // Read lo bits of low, LSB-first.
        let mut low = 0i32;
        for b in 0..lo {
            let bit = read_bit(&mut cursor)?;
            low |= (bit as i32) << b;
        }
        // Read unary-coded high.
        let mut high = 0i32;
        loop {
            let bit = read_bit(&mut cursor)?;
            if bit == 0 {
                break;
            }
            high += 1;
        }
        // Read sign bit.
        let sign_bit = read_bit(&mut cursor)?;

        let v = (high << lo) | low;
        if sign_bit == 1 {
            if v == 0 {
                return None; // non-canonical
            }
            out[i] = -v;
        } else {
            out[i] = v;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::FNDSA512;

    #[test]
    fn test_pk_encode_decode_roundtrip() {
        let p = FNDSA512;
        let h: Vec<i32> = (0..512).map(|i| (i as i32 * 7 + 3) % 12289).collect();
        let encoded = encode_pk(&h, p);
        assert_eq!(encoded.len(), p.pk_size);
        let decoded = decode_pk(&encoded, p).expect("decode failed");
        assert_eq!(decoded, h);
    }

    #[test]
    fn test_sig_compress_decompress() {
        let n = 512;
        let lo = 6;
        let s1: Vec<i32> = (0..n).map(|i| (i as i32 % 21) - 10).collect();
        let mut buf = vec![0u8; 1000];
        let used = compress_s1(&mut buf, &s1, n, lo).expect("compress failed");
        let decoded = decompress_s1(&buf[..used], n, lo).expect("decompress failed");
        assert_eq!(decoded, s1);
    }
}
