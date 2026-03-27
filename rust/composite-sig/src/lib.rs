//! Composite Signature Schemes — combining ML-DSA (post-quantum) with classical signatures.
//!
//! Composite signatures provide security that holds as long as *either* the classical
//! or the post-quantum component remains secure ("hybrid" / defense-in-depth).
//!
//! # Supported schemes
//!
//! - **ML-DSA-65 + Ed25519** — Most common composite
//! - **ML-DSA-65 + ECDSA-P256** — For NIST curve users
//! - **ML-DSA-87 + Ed25519** — Higher security level
//! - **ML-DSA-44 + Ed25519** — Lightweight composite
//!
//! # Signature format
//!
//! ```text
//! composite_sig = len(sig_classical) [4 bytes LE] || sig_classical || sig_pq
//! ```

pub mod composite_sig;

pub use composite_sig::{
    CompositeScheme, CompositeKeyPair, CompositeSig,
    MLDSA65_ED25519, MLDSA65_ECDSA_P256, MLDSA87_ED25519, MLDSA44_ED25519,
};
