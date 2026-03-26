#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Shared primitives for PQC standard implementations.
//!
//! This crate provides common mathematical building blocks used across
//! ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205).

pub mod field;
