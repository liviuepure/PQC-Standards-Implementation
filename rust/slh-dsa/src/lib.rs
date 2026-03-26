//! SLH-DSA (FIPS 205) — Stateless Hash-Based Digital Signature Algorithm.
//!
//! This crate provides a pure Rust implementation of SLH-DSA, the NIST
//! post-quantum digital signature standard (formerly known as SPHINCS+).
//!
//! # Modules
//!
//! - [`params`]  — Parameter sets for all twelve SLH-DSA configurations.
//! - [`address`] — The 32-byte ADRS tweak structure used in hash computations.
//! - [`hash`]    — SHA-2 and SHAKE-256 hash function suites.

#![no_std]

extern crate alloc;

pub mod params;
pub mod address;
pub mod hash;
