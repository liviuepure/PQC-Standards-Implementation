# Phase 1: ML-KEM (FIPS 203) in Rust — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Pure Rust implementation of ML-KEM-512, ML-KEM-768, ML-KEM-1024 per FIPS 203, with full KAT validation.

**Architecture:** Cargo workspace with `pqc-common` (shared math) and `ml-kem` crate. Type-level parameter sets via generics. `no_std` by default. Constant-time operations via `subtle` crate.

**Tech Stack:** Rust 2024 edition, sha3, subtle, zeroize, rand_core, criterion, serde_json (dev)

---

### Task 1: Rust Workspace Scaffolding

**Files:**
- Create: `rust/Cargo.toml` (workspace root)
- Create: `rust/pqc-common/Cargo.toml`
- Create: `rust/pqc-common/src/lib.rs`
- Create: `rust/ml-kem/Cargo.toml`
- Create: `rust/ml-kem/src/lib.rs`

**Step 1: Create workspace root Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "pqc-common",
    "ml-kem",
]

[workspace.package]
edition = "2021"
rust-version = "1.75"
license = "MIT"
repository = "https://github.com/baron-chain/PQC-Standards-Implementation"

[workspace.dependencies]
pqc-common = { path = "./pqc-common" }
sha3 = { version = "0.10", default-features = false }
sha2 = { version = "0.10", default-features = false }
digest = { version = "0.10", default-features = false }
subtle = { version = "2.6", default-features = false }
zeroize = { version = "1.8", default-features = false, features = ["zeroize_derive"] }
rand_core = { version = "0.6", default-features = false }
criterion = { version = "0.5", features = ["html_reports"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = { version = "0.4", features = ["serde"] }
rand = "0.8"
```

**Step 2: Create pqc-common crate**

`rust/pqc-common/Cargo.toml`:
```toml
[package]
name = "pqc-common"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "Shared primitives for PQC implementations"

[dependencies]
subtle = { workspace = true }
zeroize = { workspace = true, optional = true }
rand_core = { workspace = true }

[features]
default = []
std = ["subtle/std", "rand_core/std"]
zeroize = ["dep:zeroize"]
```

`rust/pqc-common/src/lib.rs`:
```rust
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Shared primitives for PQC standard implementations.

pub mod field;
```

**Step 3: Create ml-kem crate**

`rust/ml-kem/Cargo.toml`:
```toml
[package]
name = "ml-kem"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "Pure Rust implementation of ML-KEM (FIPS 203)"
categories = ["cryptography", "no-std"]
keywords = ["crypto", "post-quantum", "ml-kem", "kyber", "kem"]

[dependencies]
pqc-common = { workspace = true }
sha3 = { workspace = true }
digest = { workspace = true }
subtle = { workspace = true }
zeroize = { workspace = true, optional = true }
rand_core = { workspace = true }

[dev-dependencies]
criterion = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
hex = { workspace = true }
rand = { workspace = true }

[features]
default = []
std = ["pqc-common/std", "sha3/std", "subtle/std", "rand_core/std"]
zeroize = ["dep:zeroize", "pqc-common/zeroize"]

[[bench]]
name = "ml_kem_bench"
harness = false
```

`rust/ml-kem/src/lib.rs`:
```rust
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Pure Rust implementation of ML-KEM (FIPS 203).
//!
//! Implements ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key encapsulation
//! mechanisms as specified in NIST FIPS 203.
```

**Step 4: Verify workspace builds**

Run: `cd rust && cargo check`
Expected: compiles with no errors

**Step 5: Commit and push**

```
git add rust/
git commit -m "feat(rust): initialize Cargo workspace with pqc-common and ml-kem crates"
git push
```

---

### Task 2: Field Arithmetic (mod q = 3329)

**Files:**
- Create: `rust/pqc-common/src/field.rs`
- Create: `rust/pqc-common/tests/field_tests.rs`

**Step 1: Write tests for field arithmetic**

```rust
// rust/pqc-common/tests/field_tests.rs
use pqc_common::field::FieldElement;

#[test]
fn test_add() {
    let a = FieldElement::new(1000);
    let b = FieldElement::new(2000);
    assert_eq!((a + b).value(), 3000);
}

#[test]
fn test_add_wraps() {
    let a = FieldElement::new(3000);
    let b = FieldElement::new(1000);
    assert_eq!((a + b).value(), 671); // (3000 + 1000) mod 3329
}

#[test]
fn test_sub() {
    let a = FieldElement::new(1000);
    let b = FieldElement::new(500);
    assert_eq!((a - b).value(), 500);
}

#[test]
fn test_sub_wraps() {
    let a = FieldElement::new(100);
    let b = FieldElement::new(200);
    assert_eq!((a - b).value(), 3229); // (100 - 200 + 3329) mod 3329
}

#[test]
fn test_mul() {
    let a = FieldElement::new(100);
    let b = FieldElement::new(33);
    assert_eq!((a * b).value(), 3300);
}

#[test]
fn test_mul_wraps() {
    let a = FieldElement::new(1000);
    let b = FieldElement::new(1000);
    // 1000000 mod 3329 = 1000000 - 300*3329 = 1000000 - 998700 = 1300
    assert_eq!((a * b).value(), 1300);
}

#[test]
fn test_zero() {
    let z = FieldElement::ZERO;
    let a = FieldElement::new(42);
    assert_eq!((a + z).value(), 42);
    assert_eq!((a * z).value(), 0);
}

#[test]
fn test_reduce() {
    let a = FieldElement::new(3329);
    assert_eq!(a.value(), 0);
    let b = FieldElement::new(6658);
    assert_eq!(b.value(), 0);
}
```

**Step 2: Run tests to verify they fail**

Run: `cd rust && cargo test -p pqc-common`
Expected: FAIL — `FieldElement` not defined

**Step 3: Implement FieldElement**

```rust
// rust/pqc-common/src/field.rs

//! Finite field arithmetic over Z_q where q = 3329.

use core::ops::{Add, Sub, Mul, Neg};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The ML-KEM prime modulus.
pub const Q: u16 = 3329;

/// An element of the field Z_q where q = 3329.
///
/// All values are stored in the range [0, q).
/// Corresponds to elements used throughout FIPS 203.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(u16);

impl FieldElement {
    /// The zero element.
    pub const ZERO: Self = Self(0);

    /// The one element.
    pub const ONE: Self = Self(1);

    /// Creates a new field element, reducing modulo q.
    #[inline]
    pub fn new(value: u16) -> Self {
        Self(value % Q)
    }

    /// Creates a field element from a u32, reducing modulo q.
    #[inline]
    pub fn from_u32(value: u32) -> Self {
        Self((value % Q as u32) as u16)
    }

    /// Returns the canonical representative in [0, q).
    #[inline]
    pub fn value(self) -> u16 {
        self.0
    }
}

impl Add for FieldElement {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        let sum = self.0 as u32 + rhs.0 as u32;
        let reduced = sum - if sum >= Q as u32 { Q as u32 } else { 0 };
        Self(reduced as u16)
    }
}

impl Sub for FieldElement {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        let diff = self.0 as i32 - rhs.0 as i32;
        let reduced = diff + if diff < 0 { Q as i32 } else { 0 };
        Self(reduced as u16)
    }
}

impl Mul for FieldElement {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let product = self.0 as u32 * rhs.0 as u32;
        Self::from_u32(product)
    }
}

impl Neg for FieldElement {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        if self.0 == 0 {
            Self::ZERO
        } else {
            Self(Q - self.0)
        }
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u16::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for FieldElement {}
```

**Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test -p pqc-common`
Expected: All PASS

**Step 5: Commit and push**

```
git add rust/pqc-common/
git commit -m "feat(rust): add field arithmetic for Z_q (q=3329)"
git push
```

---

### Task 3: NTT Zeta Table and BitRev

**Files:**
- Create: `rust/ml-kem/src/ntt.rs`
- Create: `rust/ml-kem/tests/ntt_tests.rs`

**Step 1: Write tests for BitRev7 and zeta table**

```rust
// rust/ml-kem/tests/ntt_tests.rs
use ml_kem::ntt::{bitrev7, ZETAS};

#[test]
fn test_bitrev7() {
    assert_eq!(bitrev7(0), 0);
    assert_eq!(bitrev7(1), 64);
    assert_eq!(bitrev7(2), 32);
    assert_eq!(bitrev7(64), 1);
    assert_eq!(bitrev7(127), 127);
}

#[test]
fn test_zetas_first_few() {
    // zeta^BitRev7(0) = 17^0 = 1
    assert_eq!(ZETAS[0], 1);
    // zeta^BitRev7(1) = 17^64 mod 3329 = 1729
    assert_eq!(ZETAS[1], 1729);
}

#[test]
fn test_zetas_length() {
    assert_eq!(ZETAS.len(), 128);
}

#[test]
fn test_all_zetas_in_range() {
    for &z in ZETAS.iter() {
        assert!(z < 3329, "zeta {} out of range", z);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cd rust && cargo test -p ml-kem`
Expected: FAIL — module ntt not found

**Step 3: Implement BitRev7 and zeta table**

```rust
// rust/ml-kem/src/ntt.rs

//! Number Theoretic Transform for ML-KEM.
//!
//! Implements the NTT and inverse NTT over Z_q[X]/(X^256+1) as specified
//! in FIPS 203, Algorithms 9 and 10.

use pqc_common::field::{FieldElement, Q};

/// Reverses the 7 least significant bits of `x`.
///
/// FIPS 203, used in NTT butterfly index computation.
#[inline]
pub const fn bitrev7(x: u8) -> u8 {
    let mut result = 0u8;
    let mut i = 0;
    let mut val = x;
    while i < 7 {
        result = (result << 1) | (val & 1);
        val >>= 1;
        i += 1;
    }
    result
}

/// Precomputed zeta table: ZETAS[i] = 17^BitRev7(i) mod 3329.
///
/// 17 is a primitive 256th root of unity modulo 3329.
/// FIPS 203, Table in Section 4.4.
pub const ZETAS: [u16; 128] = compute_zetas();

const fn compute_zetas() -> [u16; 128] {
    let mut table = [0u16; 128];
    let mut i = 0u8;
    while (i as usize) < 128 {
        let exp = bitrev7(i) as u32;
        table[i as usize] = pow_mod(17, exp, Q as u32) as u16;
        i += 1;
    }
    table
}

const fn pow_mod(mut base: u32, mut exp: u32, modulus: u32) -> u32 {
    let mut result = 1u32;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    result
}
```

Update `rust/ml-kem/src/lib.rs`:
```rust
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Pure Rust implementation of ML-KEM (FIPS 203).

pub mod ntt;
```

**Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test -p ml-kem`
Expected: All PASS

**Step 5: Commit and push**

```
git add rust/ml-kem/
git commit -m "feat(rust): add NTT zeta table and BitRev7 for ML-KEM"
git push
```

---

### Task 4: NTT Forward and Inverse Transform

**Files:**
- Modify: `rust/ml-kem/src/ntt.rs`
- Modify: `rust/ml-kem/tests/ntt_tests.rs`

**Step 1: Write tests for NTT round-trip**

Add to `rust/ml-kem/tests/ntt_tests.rs`:
```rust
use ml_kem::ntt::{ntt, ntt_inverse};
use pqc_common::field::FieldElement;

#[test]
fn test_ntt_roundtrip() {
    let mut f = [FieldElement::ZERO; 256];
    for i in 0..256 {
        f[i] = FieldElement::new(i as u16);
    }
    let original = f;
    ntt(&mut f);
    ntt_inverse(&mut f);
    for i in 0..256 {
        assert_eq!(f[i].value(), original[i].value(), "mismatch at index {i}");
    }
}

#[test]
fn test_ntt_zero_polynomial() {
    let mut f = [FieldElement::ZERO; 256];
    ntt(&mut f);
    for i in 0..256 {
        assert_eq!(f[i].value(), 0, "NTT of zero should be zero at index {i}");
    }
}

#[test]
fn test_ntt_single_coefficient() {
    let mut f = [FieldElement::ZERO; 256];
    f[0] = FieldElement::new(1);
    let original = f;
    ntt(&mut f);
    ntt_inverse(&mut f);
    for i in 0..256 {
        assert_eq!(f[i].value(), original[i].value(), "mismatch at index {i}");
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cd rust && cargo test -p ml-kem`
Expected: FAIL — `ntt` and `ntt_inverse` not found

**Step 3: Implement NTT forward and inverse**

Add to `rust/ml-kem/src/ntt.rs`:
```rust
/// Forward NTT in-place. FIPS 203, Algorithm 9.
///
/// Transforms a polynomial f in Z_q[X]/(X^256+1) into its NTT representation.
pub fn ntt(f: &mut [FieldElement; 256]) {
    let mut i = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = FieldElement::new(ZETAS[i]);
            i += 1;
            for j in start..(start + len) {
                let t = zeta * f[j + len];
                f[j + len] = f[j] - t;
                f[j] = f[j] + t;
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Inverse NTT in-place. FIPS 203, Algorithm 10.
///
/// Transforms an NTT representation back to a polynomial in Z_q[X]/(X^256+1).
pub fn ntt_inverse(f: &mut [FieldElement; 256]) {
    let mut i = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = FieldElement::new(ZETAS[i]);
            i = i.wrapping_sub(1);
            for j in start..(start + len) {
                let t = f[j];
                f[j] = t + f[j + len];
                f[j + len] = zeta * (f[j + len] - t);
            }
            start += 2 * len;
        }
        len *= 2;
    }
    // Multiply by 128^{-1} mod 3329 = 3303
    let inv128 = FieldElement::new(3303);
    for coeff in f.iter_mut() {
        *coeff = *coeff * inv128;
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test -p ml-kem`
Expected: All PASS

**Step 5: Commit and push**

```
git add rust/ml-kem/
git commit -m "feat(rust): implement NTT forward and inverse transforms (FIPS 203 Alg 9-10)"
git push
```

---

### Task 5: NTT Polynomial Multiplication (BaseCaseMultiply)

**Files:**
- Modify: `rust/ml-kem/src/ntt.rs`
- Modify: `rust/ml-kem/tests/ntt_tests.rs`

**Step 1: Write tests for NTT multiplication**

Add to `rust/ml-kem/tests/ntt_tests.rs`:
```rust
use ml_kem::ntt::multiply_ntts;

#[test]
fn test_multiply_ntts_identity() {
    // Multiply by NTT(1) should return original
    let mut one = [FieldElement::ZERO; 256];
    one[0] = FieldElement::ONE;
    ntt(&mut one);

    let mut f = [FieldElement::ZERO; 256];
    for i in 0..256 {
        f[i] = FieldElement::new((i * 7 % 3329) as u16);
    }
    ntt(&mut f);

    let result = multiply_ntts(&f, &one);
    // result should equal f
    for i in 0..256 {
        assert_eq!(result[i].value(), f[i].value(), "mismatch at {i}");
    }
}

#[test]
fn test_multiply_ntts_commutative() {
    let mut a = [FieldElement::ZERO; 256];
    let mut b = [FieldElement::ZERO; 256];
    for i in 0..256 {
        a[i] = FieldElement::new((i * 3 % 3329) as u16);
        b[i] = FieldElement::new((i * 7 % 3329) as u16);
    }
    ntt(&mut a);
    ntt(&mut b);

    let ab = multiply_ntts(&a, &b);
    let ba = multiply_ntts(&b, &a);
    for i in 0..256 {
        assert_eq!(ab[i].value(), ba[i].value(), "not commutative at {i}");
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cd rust && cargo test -p ml-kem`
Expected: FAIL — `multiply_ntts` not found

**Step 3: Implement BaseCaseMultiply and MultiplyNTTs**

Add to `rust/ml-kem/src/ntt.rs`:
```rust
/// Multiply two polynomials in NTT domain. FIPS 203, Algorithm 11.
pub fn multiply_ntts(
    f_hat: &[FieldElement; 256],
    g_hat: &[FieldElement; 256],
) -> [FieldElement; 256] {
    let mut h_hat = [FieldElement::ZERO; 256];
    for i in 0..64 {
        let gamma = FieldElement::new(pow_mod(17, (2 * bitrev7(i as u8) as u32) + 1, Q as u32) as u16);
        let (c0, c1) = base_case_multiply(
            f_hat[4 * i],
            f_hat[4 * i + 1],
            g_hat[4 * i],
            g_hat[4 * i + 1],
            gamma,
        );
        h_hat[4 * i] = c0;
        h_hat[4 * i + 1] = c1;

        let (c0, c1) = base_case_multiply(
            f_hat[4 * i + 2],
            f_hat[4 * i + 3],
            g_hat[4 * i + 2],
            g_hat[4 * i + 3],
            -gamma,
        );
        h_hat[4 * i + 2] = c0;
        h_hat[4 * i + 3] = c1;
    }
    h_hat
}

/// FIPS 203, Algorithm 12.
#[inline]
fn base_case_multiply(
    a0: FieldElement,
    a1: FieldElement,
    b0: FieldElement,
    b1: FieldElement,
    gamma: FieldElement,
) -> (FieldElement, FieldElement) {
    let c0 = a0 * b0 + a1 * b1 * gamma;
    let c1 = a0 * b1 + a1 * b0;
    (c0, c1)
}
```

**Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test -p ml-kem`
Expected: All PASS

**Step 5: Commit and push**

```
git add rust/ml-kem/
git commit -m "feat(rust): implement NTT multiplication (FIPS 203 Alg 11-12)"
git push
```

---

### Task 6: Parameter Sets

**Files:**
- Create: `rust/ml-kem/src/params.rs`
- Create: `rust/ml-kem/tests/params_tests.rs`

**Step 1: Write tests for parameter sets**

```rust
// rust/ml-kem/tests/params_tests.rs
use ml_kem::params::{MlKem512, MlKem768, MlKem1024, ParameterSet};

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
```

**Step 2: Implement parameter sets**

```rust
// rust/ml-kem/src/params.rs

//! ML-KEM parameter sets as defined in FIPS 203, Table 1.

/// Trait defining an ML-KEM parameter set.
pub trait ParameterSet {
    /// Module rank (number of polynomials in vectors).
    const K: usize;
    /// CBD parameter for secret/noise in KeyGen.
    const ETA1: usize;
    /// CBD parameter for noise in Encrypt.
    const ETA2: usize;
    /// Compression bits for vector u.
    const DU: usize;
    /// Compression bits for polynomial v.
    const DV: usize;
    /// Encapsulation key size in bytes: 384*k + 32.
    const EK_SIZE: usize = 384 * Self::K + 32;
    /// Decapsulation key size in bytes: 768*k + 96.
    const DK_SIZE: usize = 768 * Self::K + 96;
    /// Ciphertext size in bytes: 32*(du*k + dv).
    const CT_SIZE: usize = 32 * (Self::DU * Self::K + Self::DV);
}

/// ML-KEM-512: NIST Security Level 1.
pub struct MlKem512;

impl ParameterSet for MlKem512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

/// ML-KEM-768: NIST Security Level 3.
pub struct MlKem768;

impl ParameterSet for MlKem768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

/// ML-KEM-1024: NIST Security Level 5.
pub struct MlKem1024;

impl ParameterSet for MlKem1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
}
```

**Step 3: Run tests, commit, push**

```
cargo test -p ml-kem
git add rust/ml-kem/
git commit -m "feat(rust): define ML-KEM parameter sets (FIPS 203 Table 1)"
git push
```

---

### Task 7: ByteEncode and ByteDecode

**Files:**
- Create: `rust/ml-kem/src/encode.rs`
- Create: `rust/ml-kem/tests/encode_tests.rs`

**Step 1: Write tests for encoding round-trip**

```rust
// rust/ml-kem/tests/encode_tests.rs
use ml_kem::encode::{byte_encode, byte_decode};
use pqc_common::field::FieldElement;

#[test]
fn test_encode_decode_roundtrip_d1() {
    let coeffs: [FieldElement; 256] = core::array::from_fn(|i| FieldElement::new((i & 1) as u16));
    let encoded = byte_encode::<1>(&coeffs);
    let decoded = byte_decode::<1>(&encoded);
    for i in 0..256 {
        assert_eq!(decoded[i].value(), coeffs[i].value(), "mismatch at {i}");
    }
}

#[test]
fn test_encode_decode_roundtrip_d10() {
    let coeffs: [FieldElement; 256] = core::array::from_fn(|i| FieldElement::new((i * 4) as u16 % 1024));
    let encoded = byte_encode::<10>(&coeffs);
    let decoded = byte_decode::<10>(&encoded);
    for i in 0..256 {
        assert_eq!(decoded[i].value(), coeffs[i].value(), "mismatch at {i}");
    }
}

#[test]
fn test_encode_decode_roundtrip_d12() {
    let coeffs: [FieldElement; 256] = core::array::from_fn(|i| FieldElement::new((i * 13) as u16 % 3329));
    let encoded = byte_encode::<12>(&coeffs);
    let decoded = byte_decode::<12>(&encoded);
    for i in 0..256 {
        assert_eq!(decoded[i].value(), coeffs[i].value(), "mismatch at {i}");
    }
}

#[test]
fn test_encode_output_length() {
    let coeffs = [FieldElement::ZERO; 256];
    let e1 = byte_encode::<1>(&coeffs);
    assert_eq!(e1.len(), 32); // 32*1
    let e10 = byte_encode::<10>(&coeffs);
    assert_eq!(e10.len(), 320); // 32*10
    let e12 = byte_encode::<12>(&coeffs);
    assert_eq!(e12.len(), 384); // 32*12
}
```

**Step 2: Implement ByteEncode/ByteDecode**

```rust
// rust/ml-kem/src/encode.rs

//! Byte encoding and decoding for ML-KEM polynomials.
//!
//! FIPS 203, Algorithms 5 (ByteEncode) and 6 (ByteDecode).

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use pqc_common::field::{FieldElement, Q};

/// Encodes 256 field elements into 32*d bytes. FIPS 203, Algorithm 5.
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
```

Update `rust/ml-kem/src/lib.rs` to add `extern crate alloc;` and `pub mod encode;`.

Update `rust/ml-kem/Cargo.toml` features:
```toml
[features]
default = ["alloc"]
std = ["alloc", "pqc-common/std", "sha3/std"]
alloc = []
```

**Step 3: Run tests, commit, push**

```
cargo test -p ml-kem
git add rust/ml-kem/
git commit -m "feat(rust): implement ByteEncode/ByteDecode (FIPS 203 Alg 5-6)"
git push
```

---

### Task 8: Compression and Decompression

**Files:**
- Create: `rust/ml-kem/src/compress.rs`
- Create: `rust/ml-kem/tests/compress_tests.rs`

**Step 1: Write tests**

```rust
// rust/ml-kem/tests/compress_tests.rs
use ml_kem::compress::{compress, decompress};
use pqc_common::field::FieldElement;

#[test]
fn test_compress_decompress_d1() {
    // 0 should compress to 0, q/2 ≈ 1665 should compress to 1
    assert_eq!(compress::<1>(FieldElement::new(0)), 0);
    assert_eq!(compress::<1>(FieldElement::new(1665)), 1);
}

#[test]
fn test_roundtrip_d4() {
    for x in 0..3329u16 {
        let c = compress::<4>(FieldElement::new(x));
        let d = decompress::<4>(c);
        // Decompressed should be close to original (lossy compression)
        let diff = if d.value() > x {
            d.value() - x
        } else {
            x - d.value()
        };
        let diff = core::cmp::min(diff, 3329 - diff);
        assert!(diff <= 3329 / 32 + 1, "too much error at x={x}: diff={diff}");
    }
}

#[test]
fn test_compress_range() {
    for x in 0..3329u16 {
        let c10 = compress::<10>(FieldElement::new(x));
        assert!(c10 < 1024, "compress<10>({x}) = {c10} out of range");
        let c4 = compress::<4>(FieldElement::new(x));
        assert!(c4 < 16, "compress<4>({x}) = {c4} out of range");
    }
}
```

**Step 2: Implement Compress/Decompress**

```rust
// rust/ml-kem/src/compress.rs

//! Compression and decompression for ML-KEM.
//!
//! FIPS 203, Section 4.2.1.

use pqc_common::field::{FieldElement, Q};

/// Compress: rounds (2^d / q) * x to the nearest integer mod 2^d.
/// FIPS 203, Equation 4.7.
#[inline]
pub fn compress<const D: usize>(x: FieldElement) -> u16 {
    let x = x.value() as u64;
    let shifted = (x << D) + (Q as u64 / 2); // add q/2 for rounding
    let result = shifted / Q as u64;
    (result & ((1u64 << D) - 1)) as u16
}

/// Decompress: rounds (q / 2^d) * y to the nearest integer.
/// FIPS 203, Equation 4.8.
#[inline]
pub fn decompress<const D: usize>(y: u16) -> FieldElement {
    let y = y as u64;
    let result = (y * Q as u64 + (1u64 << (D - 1))) >> D;
    FieldElement::new(result as u16)
}
```

**Step 3: Run tests, commit, push**

```
cargo test -p ml-kem
git add rust/ml-kem/
git commit -m "feat(rust): implement Compress/Decompress (FIPS 203 Sec 4.2.1)"
git push
```

---

### Task 9: Sampling — SamplePolyCBD and SampleNTT

**Files:**
- Create: `rust/ml-kem/src/sampling.rs`
- Create: `rust/ml-kem/tests/sampling_tests.rs`

**Step 1: Write tests**

```rust
// rust/ml-kem/tests/sampling_tests.rs
use ml_kem::sampling::{sample_poly_cbd, sample_ntt};
use pqc_common::field::{FieldElement, Q};

#[test]
fn test_cbd_eta2_range() {
    let bytes = [0xABu8; 128]; // 64 * eta2 = 64 * 2 = 128 bytes
    let poly = sample_poly_cbd::<2>(&bytes);
    for i in 0..256 {
        let v = poly[i].value();
        // CBD(2) produces values in [-2, 2], i.e. mod q: {0, 1, 2, 3327, 3328}
        assert!(
            v <= 2 || v >= Q - 2,
            "CBD(2) produced {v} at index {i}, out of [-2, 2] range"
        );
    }
}

#[test]
fn test_cbd_eta3_range() {
    let bytes = [0xCDu8; 192]; // 64 * 3 = 192 bytes
    let poly = sample_poly_cbd::<3>(&bytes);
    for i in 0..256 {
        let v = poly[i].value();
        assert!(
            v <= 3 || v >= Q - 3,
            "CBD(3) produced {v} at index {i}, out of [-3, 3] range"
        );
    }
}

#[test]
fn test_cbd_deterministic() {
    let bytes = [42u8; 128];
    let a = sample_poly_cbd::<2>(&bytes);
    let b = sample_poly_cbd::<2>(&bytes);
    for i in 0..256 {
        assert_eq!(a[i].value(), b[i].value());
    }
}

#[test]
fn test_sample_ntt_range() {
    let seed = [0u8; 34]; // rho(32) || j || i
    let poly = sample_ntt(&seed);
    for i in 0..256 {
        assert!(poly[i].value() < Q, "SampleNTT produced value >= q at {i}");
    }
}

#[test]
fn test_sample_ntt_deterministic() {
    let seed = [1u8; 34];
    let a = sample_ntt(&seed);
    let b = sample_ntt(&seed);
    for i in 0..256 {
        assert_eq!(a[i].value(), b[i].value());
    }
}
```

**Step 2: Implement sampling functions**

```rust
// rust/ml-kem/src/sampling.rs

//! Sampling functions for ML-KEM.
//!
//! FIPS 203, Algorithms 7 (SampleNTT) and 8 (SamplePolyCBD).

use pqc_common::field::{FieldElement, Q};
use sha3::{Shake128, Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Sample a polynomial from the CBD (Centered Binomial Distribution).
/// FIPS 203, Algorithm 8.
///
/// Input: byte array of length 64*eta.
/// Output: polynomial with coefficients in [-eta, eta] (mod q).
pub fn sample_poly_cbd<const ETA: usize>(bytes: &[u8]) -> [FieldElement; 256] {
    debug_assert_eq!(bytes.len(), 64 * ETA);
    let mut f = [FieldElement::ZERO; 256];

    for i in 0..256 {
        let mut x = 0u16;
        let mut y = 0u16;
        for j in 0..ETA {
            let bit_idx = 2 * i * ETA + j;
            let bit = (bytes[bit_idx / 8] >> (bit_idx % 8)) & 1;
            x += bit as u16;
        }
        for j in 0..ETA {
            let bit_idx = 2 * i * ETA + ETA + j;
            let bit = (bytes[bit_idx / 8] >> (bit_idx % 8)) & 1;
            y += bit as u16;
        }
        if x >= y {
            f[i] = FieldElement::new(x - y);
        } else {
            f[i] = FieldElement::new(Q - (y - x));
        }
    }
    f
}

/// Sample a polynomial in NTT domain via rejection sampling from SHAKE-128.
/// FIPS 203, Algorithm 7.
///
/// Input: 34-byte seed (rho || j || i).
/// Output: polynomial in NTT domain with all coefficients < q.
pub fn sample_ntt(seed: &[u8; 34]) -> [FieldElement; 256] {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut a_hat = [FieldElement::ZERO; 256];
    let mut j = 0usize;
    let mut buf = [0u8; 3];

    while j < 256 {
        reader.read(&mut buf);
        let d1 = (buf[0] as u16) | (((buf[1] & 0x0F) as u16) << 8);
        let d2 = ((buf[1] >> 4) as u16) | ((buf[2] as u16) << 4);

        if d1 < Q {
            a_hat[j] = FieldElement::new(d1);
            j += 1;
        }
        if d2 < Q && j < 256 {
            a_hat[j] = FieldElement::new(d2);
            j += 1;
        }
    }
    a_hat
}

/// Generate PRF output: SHAKE-256(seed || nonce), returning `len` bytes.
pub fn prf(seed: &[u8; 32], nonce: u8, len: usize) -> alloc::vec::Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&[nonce]);
    let mut reader = hasher.finalize_xof();
    let mut output = alloc::vec![0u8; len];
    reader.read(&mut output);
    output
}
```

**Step 3: Run tests, commit, push**

```
cargo test -p ml-kem
git add rust/ml-kem/
git commit -m "feat(rust): implement SampleNTT and SamplePolyCBD (FIPS 203 Alg 7-8)"
git push
```

---

### Task 10: Hash Functions (G, H, J, XOF)

**Files:**
- Create: `rust/ml-kem/src/hash.rs`
- Create: `rust/ml-kem/tests/hash_tests.rs`

**Step 1: Implement hash function wrappers**

```rust
// rust/ml-kem/src/hash.rs

//! Hash function instantiations for ML-KEM.
//!
//! FIPS 203, Section 4.1:
//! - G: SHA3-512
//! - H: SHA3-256
//! - J: SHAKE-256
//! - XOF: SHAKE-128

use sha3::{Sha3_256, Sha3_512, Shake256, digest::{Digest, Update, ExtendableOutput, XofReader}};

/// G(input) = SHA3-512(input), split into two 32-byte halves.
pub fn g(input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hash = Sha3_512::digest(input);
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first.copy_from_slice(&hash[..32]);
    second.copy_from_slice(&hash[32..]);
    (first, second)
}

/// H(input) = SHA3-256(input).
pub fn h(input: &[u8]) -> [u8; 32] {
    let hash = Sha3_256::digest(input);
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash);
    output
}

/// J(input) = first 32 bytes of SHAKE-256(input).
pub fn j(input: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 32];
    reader.read(&mut output);
    output
}
```

**Step 2: Write basic tests, run, commit, push**

```
cargo test -p ml-kem
git add rust/ml-kem/
git commit -m "feat(rust): add hash function wrappers G, H, J (FIPS 203 Sec 4.1)"
git push
```

---

### Task 11: K-PKE.KeyGen (Internal PKE Key Generation)

**Files:**
- Create: `rust/ml-kem/src/kpke.rs`
- Create: `rust/ml-kem/tests/kpke_tests.rs`

**Step 1: Write tests**

```rust
// rust/ml-kem/tests/kpke_tests.rs
use ml_kem::kpke::kpke_keygen;
use ml_kem::params::{MlKem768, ParameterSet};

#[test]
fn test_kpke_keygen_768_output_sizes() {
    let d = [0u8; 32];
    let (ek, dk) = kpke_keygen::<MlKem768>(&d);
    assert_eq!(ek.len(), 384 * MlKem768::K + 32); // 1184
    assert_eq!(dk.len(), 384 * MlKem768::K);       // 1152
}

#[test]
fn test_kpke_keygen_deterministic() {
    let d = [42u8; 32];
    let (ek1, dk1) = kpke_keygen::<MlKem768>(&d);
    let (ek2, dk2) = kpke_keygen::<MlKem768>(&d);
    assert_eq!(ek1, ek2);
    assert_eq!(dk1, dk2);
}
```

**Step 2: Implement K-PKE.KeyGen**

```rust
// rust/ml-kem/src/kpke.rs

//! Internal K-PKE (public key encryption) for ML-KEM.
//!
//! FIPS 203, Algorithms 13-15.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use pqc_common::field::FieldElement;
use crate::hash::g;
use crate::ntt::{ntt, ntt_inverse, multiply_ntts};
use crate::sampling::{sample_ntt, sample_poly_cbd, prf};
use crate::encode::{byte_encode, byte_decode};
use crate::params::ParameterSet;

/// K-PKE.KeyGen — FIPS 203, Algorithm 13.
///
/// Generates encryption and decryption keys from a 32-byte seed `d`.
pub fn kpke_keygen<P: ParameterSet>(d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    // (rho, sigma) = G(d || k)
    let mut g_input = vec![0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = P::K as u8;
    let (rho, sigma) = g(&g_input);

    // Generate matrix A-hat in NTT domain
    let mut a_hat = vec![[FieldElement::ZERO; 256]; P::K * P::K];
    for i in 0..P::K {
        for j_idx in 0..P::K {
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(&rho);
            seed[32] = j_idx as u8;
            seed[33] = i as u8;
            a_hat[i * P::K + j_idx] = sample_ntt(&seed);
        }
    }

    // Generate secret vector s and error vector e
    let mut n: u8 = 0;
    let mut s = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        let prf_output = prf(&sigma, n, 64 * P::ETA1);
        s[i] = match P::ETA1 {
            2 => sample_poly_cbd::<2>(&prf_output),
            3 => sample_poly_cbd::<3>(&prf_output),
            _ => unreachable!(),
        };
        n += 1;
    }

    let mut e = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        let prf_output = prf(&sigma, n, 64 * P::ETA1);
        e[i] = match P::ETA1 {
            2 => sample_poly_cbd::<2>(&prf_output),
            3 => sample_poly_cbd::<3>(&prf_output),
            _ => unreachable!(),
        };
        n += 1;
    }

    // NTT(s) and NTT(e)
    let mut s_hat = s.clone();
    for poly in s_hat.iter_mut() {
        ntt(poly);
    }
    let mut e_hat = e.clone();
    for poly in e_hat.iter_mut() {
        ntt(poly);
    }

    // t-hat = A-hat * s-hat + e-hat
    let mut t_hat = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        for j_idx in 0..P::K {
            let product = multiply_ntts(&a_hat[i * P::K + j_idx], &s_hat[j_idx]);
            for c in 0..256 {
                t_hat[i][c] = t_hat[i][c] + product[c];
            }
        }
        for c in 0..256 {
            t_hat[i][c] = t_hat[i][c] + e_hat[i][c];
        }
    }

    // ekPKE = ByteEncode_12(t-hat) || rho
    let mut ek = Vec::with_capacity(384 * P::K + 32);
    for i in 0..P::K {
        ek.extend_from_slice(&byte_encode::<12>(&t_hat[i]));
    }
    ek.extend_from_slice(&rho);

    // dkPKE = ByteEncode_12(s-hat)
    let mut dk = Vec::with_capacity(384 * P::K);
    for i in 0..P::K {
        dk.extend_from_slice(&byte_encode::<12>(&s_hat[i]));
    }

    (ek, dk)
}
```

**Step 3: Run tests, commit, push**

```
cargo test -p ml-kem
git add rust/ml-kem/
git commit -m "feat(rust): implement K-PKE.KeyGen (FIPS 203 Algorithm 13)"
git push
```

---

### Task 12: K-PKE.Encrypt and K-PKE.Decrypt

**Files:**
- Modify: `rust/ml-kem/src/kpke.rs`
- Modify: `rust/ml-kem/tests/kpke_tests.rs`

**Step 1: Write encrypt/decrypt round-trip test**

```rust
#[test]
fn test_kpke_encrypt_decrypt_roundtrip() {
    let d = [7u8; 32];
    let (ek, dk) = kpke_keygen::<MlKem768>(&d);
    let message = [0xAB; 32];
    let randomness = [0xCD; 32];
    let ct = kpke_encrypt::<MlKem768>(&ek, &message, &randomness);
    let recovered = kpke_decrypt::<MlKem768>(&dk, &ct);
    assert_eq!(recovered, message);
}
```

**Step 2: Implement K-PKE.Encrypt (Algorithm 14) and K-PKE.Decrypt (Algorithm 15)**

These follow the same pattern as KeyGen — matrix operations with NTT, compression, encoding.

**Step 3: Run tests, commit, push**

```
cargo test -p ml-kem
git add rust/ml-kem/
git commit -m "feat(rust): implement K-PKE.Encrypt and K-PKE.Decrypt (FIPS 203 Alg 14-15)"
git push
```

---

### Task 13: ML-KEM.KeyGen, Encaps, Decaps (Top-Level API)

**Files:**
- Create: `rust/ml-kem/src/kem.rs`
- Create: `rust/ml-kem/tests/kem_tests.rs`

**Step 1: Write end-to-end tests**

```rust
// rust/ml-kem/tests/kem_tests.rs
use ml_kem::kem::{keygen, encapsulate, decapsulate};
use ml_kem::params::{MlKem512, MlKem768, MlKem1024};
use rand::rngs::OsRng;

#[test]
fn test_kem_768_roundtrip() {
    let (ek, dk) = keygen::<MlKem768>(&mut OsRng);
    let (ss1, ct) = encapsulate::<MlKem768>(&ek, &mut OsRng);
    let ss2 = decapsulate::<MlKem768>(&dk, &ct);
    assert_eq!(ss1, ss2);
}

#[test]
fn test_kem_512_roundtrip() {
    let (ek, dk) = keygen::<MlKem512>(&mut OsRng);
    let (ss1, ct) = encapsulate::<MlKem512>(&ek, &mut OsRng);
    let ss2 = decapsulate::<MlKem512>(&dk, &ct);
    assert_eq!(ss1, ss2);
}

#[test]
fn test_kem_1024_roundtrip() {
    let (ek, dk) = keygen::<MlKem1024>(&mut OsRng);
    let (ss1, ct) = encapsulate::<MlKem1024>(&ek, &mut OsRng);
    let ss2 = decapsulate::<MlKem1024>(&dk, &ct);
    assert_eq!(ss1, ss2);
}

#[test]
fn test_kem_768_implicit_rejection() {
    let (ek, dk) = keygen::<MlKem768>(&mut OsRng);
    let (ss, ct) = encapsulate::<MlKem768>(&ek, &mut OsRng);
    // Tamper with ciphertext
    let mut bad_ct = ct.clone();
    bad_ct[0] ^= 0xFF;
    let ss_bad = decapsulate::<MlKem768>(&dk, &bad_ct);
    // Should return a pseudorandom value, NOT the real shared secret
    assert_ne!(ss, ss_bad);
    // Should still return 32 bytes (not error)
    assert_eq!(ss_bad.len(), 32);
}
```

**Step 2: Implement ML-KEM.KeyGen (Alg 16), Encaps (Alg 17), Decaps (Alg 18)**

```rust
// rust/ml-kem/src/kem.rs — top-level KEM operations

use crate::kpke::{kpke_keygen, kpke_encrypt, kpke_decrypt};
use crate::hash::{g, h, j};
use crate::params::ParameterSet;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

/// ML-KEM.KeyGen — FIPS 203, Algorithm 16.
pub fn keygen<P: ParameterSet>(rng: &mut (impl CryptoRng + RngCore)) -> (Vec<u8>, Vec<u8>) {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    rng.fill_bytes(&mut d);
    rng.fill_bytes(&mut z);
    keygen_internal::<P>(&d, &z)
}

pub fn keygen_internal<P: ParameterSet>(d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (ek_pke, dk_pke) = kpke_keygen::<P>(d);
    let ek = ek_pke.clone();
    let h_ek = h(&ek);
    let mut dk = Vec::with_capacity(P::DK_SIZE);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(z);
    (ek, dk)
}

/// ML-KEM.Encaps — FIPS 203, Algorithm 17.
pub fn encapsulate<P: ParameterSet>(ek: &[u8], rng: &mut (impl CryptoRng + RngCore)) -> ([u8; 32], Vec<u8>) {
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    encapsulate_internal::<P>(ek, &m)
}

pub fn encapsulate_internal<P: ParameterSet>(ek: &[u8], m: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let h_ek = h(ek);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&h_ek);
    let (k, r) = g(&g_input);
    let ct = kpke_encrypt::<P>(ek, m, &r);
    (k, ct)
}

/// ML-KEM.Decaps — FIPS 203, Algorithm 18.
pub fn decapsulate<P: ParameterSet>(dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let dk_pke_len = 384 * P::K;
    let ek_len = 384 * P::K + 32;

    let dk_pke = &dk[..dk_pke_len];
    let ek_pke = &dk[dk_pke_len..dk_pke_len + ek_len];
    let h_ek = &dk[dk_pke_len + ek_len..dk_pke_len + ek_len + 32];
    let z = &dk[dk_pke_len + ek_len + 32..dk_pke_len + ek_len + 64];

    let m_prime = kpke_decrypt::<P>(dk_pke, ct);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(h_ek);
    let (k_prime, r_prime) = g(&g_input);

    // Implicit rejection: J(z || c)
    let mut j_input = Vec::with_capacity(32 + ct.len());
    j_input.extend_from_slice(z);
    j_input.extend_from_slice(ct);
    let k_bar = j(&j_input);

    let ct_prime = kpke_encrypt::<P>(ek_pke, &m_prime, &r_prime);

    // Constant-time comparison
    let ct_eq = ct.ct_eq(&ct_prime);

    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = u8::conditional_select(&k_bar[i], &k_prime[i], ct_eq);
    }
    result
}
```

**Step 3: Run tests, commit, push**

```
cargo test -p ml-kem
git add rust/ml-kem/
git commit -m "feat(rust): implement ML-KEM KeyGen, Encaps, Decaps (FIPS 203 Alg 16-18)"
git push
```

---

### Task 14: Download and Convert NIST KAT Vectors

**Files:**
- Create: `test-vectors/ml-kem/ml-kem-512.json`
- Create: `test-vectors/ml-kem/ml-kem-768.json`
- Create: `test-vectors/ml-kem/ml-kem-1024.json`

**Step 1: Download ACVP test vectors from NIST**

Fetch from https://github.com/usnistgov/ACVP-Server and https://github.com/C2SP/CCTV/tree/main/ML-KEM

**Step 2: Convert to JSON format, commit, push**

```
git add test-vectors/
git commit -m "feat: add NIST KAT test vectors for ML-KEM-512/768/1024"
git push
```

---

### Task 15: KAT Vector Validation Tests

**Files:**
- Create: `rust/ml-kem/tests/kat_tests.rs`

**Step 1: Write KAT tests that load JSON vectors and validate**

Test KeyGen, Encaps, and Decaps against all official vectors for all three parameter sets.

**Step 2: Run tests, commit, push**

```
cargo test -p ml-kem -- kat
git add rust/ml-kem/tests/
git commit -m "test(rust): add KAT vector validation for all ML-KEM parameter sets"
git push
```

---

### Task 16: Benchmarks

**Files:**
- Create: `rust/ml-kem/benches/ml_kem_bench.rs`

**Step 1: Write benchmarks for all operations × all parameter sets**

KeyGen, Encaps, Decaps for 512, 768, 1024 using Criterion.

**Step 2: Run benchmarks, commit, push**

```
cd rust && cargo bench -p ml-kem
git add rust/ml-kem/benches/
git commit -m "perf(rust): add ML-KEM benchmarks for all parameter sets"
git push
```

---

### Task 17: Public API Polish and Documentation

**Files:**
- Modify: `rust/ml-kem/src/lib.rs` (re-exports, module docs)
- Create: `rust/ml-kem/README.md`

**Step 1: Create clean public API with re-exports**

Expose `MlKem512`, `MlKem768`, `MlKem1024`, `keygen`, `encapsulate`, `decapsulate` at crate root.

**Step 2: Add rustdoc examples on all public items**

**Step 3: Commit, push, tag**

```
git add rust/ml-kem/
git commit -m "docs(rust): polish ML-KEM public API and add documentation"
git push
git tag v0.1.0-mlkem-rust
git push --tags
```

---

## Summary: Expected Commits (17+ commits)

| # | Message |
|---|---------|
| 1 | `feat(rust): initialize Cargo workspace with pqc-common and ml-kem crates` |
| 2 | `feat(rust): add field arithmetic for Z_q (q=3329)` |
| 3 | `feat(rust): add NTT zeta table and BitRev7 for ML-KEM` |
| 4 | `feat(rust): implement NTT forward and inverse transforms (FIPS 203 Alg 9-10)` |
| 5 | `feat(rust): implement NTT multiplication (FIPS 203 Alg 11-12)` |
| 6 | `feat(rust): define ML-KEM parameter sets (FIPS 203 Table 1)` |
| 7 | `feat(rust): implement ByteEncode/ByteDecode (FIPS 203 Alg 5-6)` |
| 8 | `feat(rust): implement Compress/Decompress (FIPS 203 Sec 4.2.1)` |
| 9 | `feat(rust): implement SampleNTT and SamplePolyCBD (FIPS 203 Alg 7-8)` |
| 10 | `feat(rust): add hash function wrappers G, H, J (FIPS 203 Sec 4.1)` |
| 11 | `feat(rust): implement K-PKE.KeyGen (FIPS 203 Algorithm 13)` |
| 12 | `feat(rust): implement K-PKE.Encrypt and K-PKE.Decrypt (FIPS 203 Alg 14-15)` |
| 13 | `feat(rust): implement ML-KEM KeyGen, Encaps, Decaps (FIPS 203 Alg 16-18)` |
| 14 | `feat: add NIST KAT test vectors for ML-KEM-512/768/1024` |
| 15 | `test(rust): add KAT vector validation for all ML-KEM parameter sets` |
| 16 | `perf(rust): add ML-KEM benchmarks for all parameter sets` |
| 17 | `docs(rust): polish ML-KEM public API and add documentation` |
