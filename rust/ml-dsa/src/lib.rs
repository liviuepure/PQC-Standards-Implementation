#![forbid(unsafe_code)]
//! ML-DSA (FIPS 204) — Module-Lattice-Based Digital Signature Algorithm.
//!
//! This crate provides a pure Rust implementation of ML-DSA, the NIST
//! post-quantum digital signature standard (formerly known as CRYSTALS-Dilithium).
//!
//! # Modules
//!
//! - [`field`] — Arithmetic over Z_q (q = 8380417).
//! - [`ntt`]   — Number Theoretic Transform for fast polynomial multiplication.
//! - [`params`] — Parameter sets for ML-DSA-44, ML-DSA-65, and ML-DSA-87.
//! - [`hash`]  — SHAKE-based hashing and sampling functions.
//! - [`decompose`] — Decomposition, rounding, and hint functions.
//! - [`encode`] — Bit-packing and encoding for keys and signatures.
//! - [`dsa`]   — Top-level key generation, signing, and verification.

#![no_std]

extern crate alloc;

pub mod field;
pub mod ntt;
pub mod params;
pub mod hash;
pub mod decompose;
pub mod encode;
pub mod dsa;
