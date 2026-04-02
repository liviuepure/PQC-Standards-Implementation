/// GF(2) polynomial arithmetic: polynomials over GF(2) packed into `Vec<u64>` words.
///
/// Each polynomial has at most n bits. Arithmetic is in GF(2)[x]/(x^n - 1).

/// Polynomial addition in GF(2): out = a XOR b.
pub fn vect_add(a: &[u64], b: &[u64]) -> Vec<u64> {
    let n = a.len().max(b.len());
    let mut out = vec![0u64; n];
    for i in 0..a.len() {
        out[i] = a[i];
    }
    for i in 0..b.len() {
        out[i] ^= b[i];
    }
    out
}

/// Set bit at position `pos` in the vector `v`.
pub fn vect_set_bit(v: &mut [u64], pos: usize) {
    v[pos / 64] |= 1u64 << (pos % 64);
}

/// Get bit at position `pos` in the vector `v`.
pub fn vect_get_bit(v: &[u64], pos: usize) -> u64 {
    (v[pos / 64] >> (pos % 64)) & 1
}

/// Returns the Hamming weight of a GF(2) vector.
pub fn vect_weight(v: &[u64]) -> usize {
    v.iter().map(|w| w.count_ones() as usize).sum()
}

/// Converts a u64 vector to bytes (little-endian).
pub fn vect_to_bytes(v: &[u64], n_bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; n_bytes];
    for i in 0..v.len() {
        let start = i * 8;
        if start >= n_bytes {
            break;
        }
        let bytes = v[i].to_le_bytes();
        let remaining = n_bytes - start;
        let copy_len = remaining.min(8);
        out[start..start + copy_len].copy_from_slice(&bytes[..copy_len]);
    }
    out
}

/// Converts bytes to a u64 vector (little-endian).
pub fn vect_from_bytes(data: &[u8], n_words: usize) -> Vec<u64> {
    let mut v = vec![0u64; n_words];
    for i in 0..n_words {
        let start = i * 8;
        if start >= data.len() {
            break;
        }
        let end = (start + 8).min(data.len());
        let mut buf = [0u8; 8];
        buf[..end - start].copy_from_slice(&data[start..end]);
        v[i] = u64::from_le_bytes(buf);
    }
    v
}

/// Returns a copy of v truncated/masked to exactly `n_bits` bits.
pub fn vect_resize(v: &[u64], n_bits: usize) -> Vec<u64> {
    let n_words = (n_bits + 63) / 64;
    let mut out = vec![0u64; n_words];
    let copy_len = out.len().min(v.len());
    out[..copy_len].copy_from_slice(&v[..copy_len]);
    let rem = n_bits % 64;
    if rem != 0 && n_words > 0 {
        out[n_words - 1] &= (1u64 << rem) - 1;
    }
    out
}

/// Constant-time equality: returns 1 if a == b, 0 otherwise.
pub fn vect_equal(a: &[u64], b: &[u64]) -> usize {
    let mut diff = 0u64;
    let n = a.len().min(b.len());
    for i in 0..n {
        diff |= a[i] ^ b[i];
    }
    for i in n..a.len() {
        diff |= a[i];
    }
    for i in n..b.len() {
        diff |= b[i];
    }
    let mut d = diff | (diff >> 32);
    d |= d >> 16;
    d |= d >> 8;
    d |= d >> 4;
    d |= d >> 2;
    d |= d >> 1;
    1 - (d & 1) as usize
}

/// Carryless multiplication of two 64-bit words.
/// Returns (lo, hi) such that a * b = hi<<64 | lo in GF(2).
fn base_mul(a: u64, b: u64) -> (u64, u64) {
    let mut lo = 0u64;
    let mut hi = 0u64;

    for i in 0..64 {
        if (a >> i) & 1 == 0 {
            continue;
        }
        if i == 0 {
            lo ^= b;
        } else {
            lo ^= b << i;
            hi ^= b >> (64 - i);
        }
    }

    (lo, hi)
}

/// Schoolbook polynomial multiplication of two GF(2) polynomials.
fn schoolbook_mul(a: &[u64], size_a: usize, b: &[u64], size_b: usize) -> Vec<u64> {
    let mut out = vec![0u64; size_a + size_b];
    for i in 0..size_a {
        if a[i] == 0 {
            continue;
        }
        for j in 0..size_b {
            if b[j] == 0 {
                continue;
            }
            let (lo, hi) = base_mul(a[i], b[j]);
            out[i + j] ^= lo;
            out[i + j + 1] ^= hi;
        }
    }
    out
}

/// Computes out = a * b mod (x^n - 1) in GF(2)[x].
pub fn vect_mul(a: &[u64], b: &[u64], n: usize) -> Vec<u64> {
    let n_words = (n + 63) / 64;

    // Pad and mask inputs
    let mut a_pad = vec![0u64; n_words];
    let mut b_pad = vec![0u64; n_words];
    let copy_a = a.len().min(n_words);
    let copy_b = b.len().min(n_words);
    a_pad[..copy_a].copy_from_slice(&a[..copy_a]);
    b_pad[..copy_b].copy_from_slice(&b[..copy_b]);

    let rem = n % 64;
    if rem != 0 {
        a_pad[n_words - 1] &= (1u64 << rem) - 1;
        b_pad[n_words - 1] &= (1u64 << rem) - 1;
    }

    // Full product
    let prod = schoolbook_mul(&a_pad, n_words, &b_pad, n_words);

    // Reduce mod (x^n - 1)
    let mut out = vec![0u64; n_words];
    out[..n_words].copy_from_slice(&prod[..n_words]);

    let word_off = n / 64;

    if rem == 0 {
        for i in 0..n_words {
            if word_off + i < 2 * n_words {
                out[i] ^= prod[word_off + i];
            }
        }
    } else {
        for i in 0..n_words {
            let idx = word_off + i;
            if idx < 2 * n_words {
                out[i] ^= prod[idx] >> rem;
            }
            if idx + 1 < 2 * n_words {
                out[i] ^= prod[idx + 1] << (64 - rem);
            }
        }
    }

    // Mask last word
    if rem != 0 {
        out[n_words - 1] &= (1u64 << rem) - 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vect_add() {
        let a = vec![0xAAAAu64, 0x5555];
        let b = vec![0x5555u64, 0xAAAA];
        let c = vect_add(&a, &b);
        assert_eq!(c[0], 0xFFFF);
        assert_eq!(c[1], 0xFFFF);
    }

    #[test]
    fn test_vect_mul_identity() {
        let one = vec![1u64, 0];
        let d = vec![0xDEADBEEFCAFEBABEu64, 0x1234567890ABCDEF];
        let r = vect_mul(&d, &one, 128);
        assert_eq!(r[0], d[0]);
        assert_eq!(r[1], d[1]);
    }

    #[test]
    fn test_vect_bytes_roundtrip() {
        let v = vec![0x0123456789ABCDEFu64, 0xFEDCBA9876543210];
        let bytes = vect_to_bytes(&v, 16);
        let v2 = vect_from_bytes(&bytes, 2);
        assert_eq!(v, v2);
    }
}
