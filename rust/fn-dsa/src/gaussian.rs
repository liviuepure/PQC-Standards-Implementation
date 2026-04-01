// Gaussian sampler for FN-DSA (FIPS 206 §3.12).
//
// Uses the RCDT table for base Gaussian sampling with sigma0 = 1.8205.
// Ported from the Go reference implementation.

use rand_core::RngCore;

const SIGMA0: f64 = 1.8205;

/// RCDT table entry: 72-bit value as (hi: u8, lo: u64).
struct Rcdt72 {
    hi: u8,
    lo: u64,
}

/// RCDT table: table[i] = floor(2^72 * Pr[|Z| >= i+1]) for Z ~ D_{Z,sigma0}.
static RCDT_TABLE: [Rcdt72; 18] = [
    Rcdt72 { hi: 199, lo: 16610441552002023424 },
    Rcdt72 { hi: 103, lo: 7624082642567692288 },
    Rcdt72 { hi: 42,  lo: 919243735747002368 },
    Rcdt72 { hi: 13,  lo: 3484267233246674944 },
    Rcdt72 { hi: 3,   lo: 2772878652510347264 },
    Rcdt72 { hi: 0,   lo: 10479598105528201216 },
    Rcdt72 { hi: 0,   lo: 1418221736465465344 },
    Rcdt72 { hi: 0,   lo: 143439473028577328 },
    Rcdt72 { hi: 0,   lo: 10810581864167812 },
    Rcdt72 { hi: 0,   lo: 605874652027744 },
    Rcdt72 { hi: 0,   lo: 25212870589170 },
    Rcdt72 { hi: 0,   lo: 778215157694 },
    Rcdt72 { hi: 0,   lo: 17802250993 },
    Rcdt72 { hi: 0,   lo: 301647562 },
    Rcdt72 { hi: 0,   lo: 3784361 },
    Rcdt72 { hi: 0,   lo: 35141 },
    Rcdt72 { hi: 0,   lo: 241 },
    Rcdt72 { hi: 0,   lo: 1 },
];

/// Branchless: 1 if a < b (unsigned 64-bit), 0 otherwise.
#[inline]
fn lt64(a: u64, b: u64) -> u64 {
    ((!a & b) | (!(a ^ b) & a.wrapping_sub(b))) >> 63
}

/// Branchless: 1 if a == b (u8), 0 otherwise.
#[inline]
fn eq8(a: u8, b: u8) -> u64 {
    let x = (a as u64) ^ (b as u64);
    x.wrapping_sub(1) >> 63
}

/// Samples from the base Gaussian D_{Z,sigma0}.
fn sample_base_gaussian<R: RngCore>(rng: &mut R) -> i32 {
    // Read 9 bytes (72 bits).
    let mut buf = [0u8; 9];
    rng.fill_bytes(&mut buf);

    let sample_lo = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let sample_hi = buf[8];

    // Count how many RCDT entries are strictly greater than the sample.
    let mut z = 0i32;
    for entry in &RCDT_TABLE {
        let t_hi = entry.hi;
        let t_lo = entry.lo;
        let hi_lt = lt64(sample_hi as u64, t_hi as u64);
        let hi_eq = eq8(sample_hi, t_hi);
        let lo_lt = lt64(sample_lo, t_lo);
        let lt72 = hi_lt | (hi_eq & lo_lt);
        z += lt72 as i32;
    }

    // Read sign bit.
    let mut sign_buf = [0u8; 1];
    rng.fill_bytes(&mut sign_buf);
    let sign_bit = (sign_buf[0] & 1) as i32;

    // Branchless conditional negate.
    let mask = -sign_bit;
    (z ^ mask) - mask
}

/// Samples an integer from D_{Z,sigma} centered at 0.
pub fn sample_gaussian<R: RngCore>(rng: &mut R, sigma: f64) -> i32 {
    let sigma2 = sigma * sigma;
    let sigma02 = SIGMA0 * SIGMA0;
    let c = (sigma2 - sigma02) / (2.0 * sigma2 * sigma02);

    loop {
        let z = sample_base_gaussian(rng);
        let fz = z as f64;
        let log_prob = -fz * fz * c;

        // Sample u in [0, 1) using 53 random bits.
        let mut ubuf = [0u8; 8];
        rng.fill_bytes(&mut ubuf);
        let u53 = u64::from_le_bytes(ubuf) >> 11;
        let u = u53 as f64 / (1u64 << 53) as f64;

        if u < log_prob.exp() {
            return z;
        }
    }
}

/// Returns sigma = 1.17 * sqrt(Q / (2*n)).
pub fn ntru_sigma(n: usize) -> f64 {
    1.17 * ((12289.0 / (2.0 * n as f64)) as f64).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gaussian_basic() {
        struct SimpleRng(u64);
        impl rand_core::RngCore for SimpleRng {
            fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
            fn next_u64(&mut self) -> u64 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                rand_core::impls::fill_bytes_via_next(self, dest);
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        let mut rng = SimpleRng(42);
        let sigma = ntru_sigma(512);
        for _ in 0..100 {
            let v = sample_gaussian(&mut rng, sigma);
            assert!(v.abs() < 100, "value {} seems unreasonably large", v);
        }
    }
}
