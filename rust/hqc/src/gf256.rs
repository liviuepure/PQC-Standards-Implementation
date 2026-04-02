/// GF(2^8) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
///
/// This is the polynomial specified by the HQC specification for Reed-Solomon encoding/decoding.
/// Generator (primitive element): alpha = 2 (i.e., x).

const GF_POLY: u16 = 0x11D;
const GF_GEN: u8 = 2;

/// Precomputed log and exp tables for GF(2^8).
struct Gf256Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

/// Build the log/exp tables at compile time is not feasible with const fn restrictions,
/// so we use `lazy_static`-style initialization via a function.
fn build_tables() -> Gf256Tables {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];

    let mut x: u16 = 1;
    for i in 0..255 {
        exp[i] = x as u8;
        exp[i + 255] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x >= 256 {
            x ^= GF_POLY;
        }
    }
    log[0] = 0; // convention
    exp[510] = exp[0];

    Gf256Tables { exp, log }
}

/// Global tables, initialized once.
static GF256: std::sync::LazyLock<Gf256Tables> = std::sync::LazyLock::new(build_tables);

/// The primitive element of GF(2^8).
pub const GENERATOR: u8 = GF_GEN;

/// Addition in GF(2^8) (XOR).
#[inline]
pub fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in GF(2^8) via log/exp tables.
#[inline]
pub fn gf256_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = &*GF256;
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

/// Multiplicative inverse in GF(2^8). Returns 0 if a == 0.
#[inline]
pub fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let t = &*GF256;
    t.exp[255 - t.log[a as usize] as usize]
}

/// Exponentiation: a^n in GF(2^8).
pub fn gf256_pow(a: u8, n: i32) -> u8 {
    if a == 0 {
        return if n == 0 { 1 } else { 0 };
    }
    let t = &*GF256;
    let log_a = t.log[a as usize] as i32;
    let mut log_result = (log_a * n) % 255;
    if log_result < 0 {
        log_result += 255;
    }
    t.exp[log_result as usize]
}

/// Division: a / b in GF(2^8). Panics if b == 0.
#[inline]
pub fn gf256_div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "hqc: gf256 division by zero");
    if a == 0 {
        return 0;
    }
    let t = &*GF256;
    let mut log_diff = t.log[a as usize] as i32 - t.log[b as usize] as i32;
    if log_diff < 0 {
        log_diff += 255;
    }
    t.exp[log_diff as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exp_log_roundtrip() {
        let t = &*GF256;
        for i in 1..256u16 {
            let a = i as u8;
            let log_a = t.log[a as usize];
            let exp_log_a = t.exp[log_a as usize];
            assert_eq!(exp_log_a, a, "exp(log({})) = {}, want {}", a, exp_log_a, a);
        }
    }

    #[test]
    fn test_mul_identity() {
        for i in 0..256u16 {
            let a = i as u8;
            assert_eq!(gf256_mul(1, a), a);
        }
    }

    #[test]
    fn test_mul_inverse() {
        for i in 1..256u16 {
            let a = i as u8;
            assert_eq!(gf256_mul(a, gf256_inv(a)), 1, "{} * inv({}) != 1", a, a);
        }
    }
}
