#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Pure Rust implementation of ML-KEM (FIPS 203).
//!
//! Implements ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key encapsulation
//! mechanisms as specified in NIST FIPS 203.
//!
//! # Security
//!
//! - All secret-dependent operations are constant-time
//! - Implicit rejection on decapsulation failure (no error oracle)
//! - Randomness sourced from OS CSPRNG only
//!
//! # Example
//!
//! ```ignore
//! use ml_kem::{MlKem768, keygen, encapsulate, decapsulate};
//! use rand::rngs::OsRng;
//!
//! let (ek, dk) = keygen::<MlKem768>(&mut OsRng);
//! let (shared_secret, ciphertext) = encapsulate::<MlKem768>(&ek, &mut OsRng);
//! let recovered = decapsulate::<MlKem768>(&dk, &ciphertext);
//! assert_eq!(shared_secret, recovered);
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod ntt;
