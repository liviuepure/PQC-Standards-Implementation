//! Composite signature implementation combining ML-DSA with Ed25519 or ECDSA-P256.

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey, Signer, Verifier};
use p256::ecdsa::{
    SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    signature::Signer as EcdsaSigner, signature::Verifier as EcdsaVerifier,
    Signature as P256Signature,
};
use rand_core::{CryptoRng, RngCore};

use ml_dsa::dsa as mldsa;
use ml_dsa::params::{MlDsa44, MlDsa65, MlDsa87};

// ---------------------------------------------------------------------------
// Scheme descriptors
// ---------------------------------------------------------------------------

/// Identifies which composite scheme to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositeScheme {
    MlDsa65Ed25519,
    MlDsa65EcdsaP256,
    MlDsa87Ed25519,
    MlDsa44Ed25519,
}

pub const MLDSA65_ED25519: CompositeScheme = CompositeScheme::MlDsa65Ed25519;
pub const MLDSA65_ECDSA_P256: CompositeScheme = CompositeScheme::MlDsa65EcdsaP256;
pub const MLDSA87_ED25519: CompositeScheme = CompositeScheme::MlDsa87Ed25519;
pub const MLDSA44_ED25519: CompositeScheme = CompositeScheme::MlDsa44Ed25519;

// ---------------------------------------------------------------------------
// Key pair
// ---------------------------------------------------------------------------

/// A composite key pair: classical || PQ.
pub struct CompositeKeyPair {
    /// Public key = pk_classical || pk_pq
    pub pk: Vec<u8>,
    /// Secret key = sk_classical || sk_pq
    pub sk: Vec<u8>,
    /// Scheme identifier (needed for parsing boundaries).
    pub scheme: CompositeScheme,
}

// ---------------------------------------------------------------------------
// Composite signature output
// ---------------------------------------------------------------------------

/// A composite signature: length-prefixed classical sig followed by PQ sig.
pub struct CompositeSig {
    pub bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Helpers: classical key sizes
// ---------------------------------------------------------------------------

fn classical_pk_size(scheme: CompositeScheme) -> usize {
    match scheme {
        CompositeScheme::MlDsa65Ed25519
        | CompositeScheme::MlDsa87Ed25519
        | CompositeScheme::MlDsa44Ed25519 => 32, // Ed25519 public key
        CompositeScheme::MlDsa65EcdsaP256 => 33, // SEC1 compressed point
    }
}

fn classical_sk_size(scheme: CompositeScheme) -> usize {
    match scheme {
        CompositeScheme::MlDsa65Ed25519
        | CompositeScheme::MlDsa87Ed25519
        | CompositeScheme::MlDsa44Ed25519 => 32, // Ed25519 seed
        CompositeScheme::MlDsa65EcdsaP256 => 32, // P-256 scalar
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a composite key pair.
pub fn key_gen(scheme: CompositeScheme, rng: &mut (impl CryptoRng + RngCore)) -> CompositeKeyPair {
    let (classical_pk, classical_sk) = gen_classical(scheme, rng);
    let (pq_pk, pq_sk) = gen_pq(scheme, rng);

    let mut pk = Vec::with_capacity(classical_pk.len() + pq_pk.len());
    pk.extend_from_slice(&classical_pk);
    pk.extend_from_slice(&pq_pk);

    let mut sk = Vec::with_capacity(classical_sk.len() + pq_sk.len());
    sk.extend_from_slice(&classical_sk);
    sk.extend_from_slice(&pq_sk);

    CompositeKeyPair { pk, sk, scheme }
}

fn gen_classical(scheme: CompositeScheme, rng: &mut (impl CryptoRng + RngCore)) -> (Vec<u8>, Vec<u8>) {
    match scheme {
        CompositeScheme::MlDsa65Ed25519
        | CompositeScheme::MlDsa87Ed25519
        | CompositeScheme::MlDsa44Ed25519 => {
            let signing_key = Ed25519SigningKey::generate(rng);
            let pk = signing_key.verifying_key().to_bytes().to_vec();
            let sk = signing_key.to_bytes().to_vec();
            (pk, sk)
        }
        CompositeScheme::MlDsa65EcdsaP256 => {
            let signing_key = P256SigningKey::random(rng);
            let pk = signing_key
                .verifying_key()
                .to_encoded_point(true) // compressed
                .as_bytes()
                .to_vec();
            let sk = signing_key.to_bytes().to_vec();
            (pk, sk)
        }
    }
}

fn gen_pq(scheme: CompositeScheme, rng: &mut (impl CryptoRng + RngCore)) -> (Vec<u8>, Vec<u8>) {
    match scheme {
        CompositeScheme::MlDsa44Ed25519 => {
            let (pk, sk) = mldsa::keygen::<MlDsa44>(rng);
            (pk, sk)
        }
        CompositeScheme::MlDsa65Ed25519
        | CompositeScheme::MlDsa65EcdsaP256 => {
            let (pk, sk) = mldsa::keygen::<MlDsa65>(rng);
            (pk, sk)
        }
        CompositeScheme::MlDsa87Ed25519 => {
            let (pk, sk) = mldsa::keygen::<MlDsa87>(rng);
            (pk, sk)
        }
    }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Produce a composite signature on `msg`.
///
/// Format: `len(sig_classical) [4 bytes LE] || sig_classical || sig_pq`
pub fn sign(kp: &CompositeKeyPair, msg: &[u8]) -> CompositeSig {
    let sk_classical = &kp.sk[..classical_sk_size(kp.scheme)];
    let sk_pq = &kp.sk[classical_sk_size(kp.scheme)..];

    let sig_classical = sign_classical(kp.scheme, sk_classical, msg);
    let sig_pq = sign_pq(kp.scheme, sk_pq, msg);

    let len_bytes = (sig_classical.len() as u32).to_le_bytes();
    let mut out = Vec::with_capacity(4 + sig_classical.len() + sig_pq.len());
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(&sig_classical);
    out.extend_from_slice(&sig_pq);

    CompositeSig { bytes: out }
}

fn sign_classical(scheme: CompositeScheme, sk: &[u8], msg: &[u8]) -> Vec<u8> {
    match scheme {
        CompositeScheme::MlDsa65Ed25519
        | CompositeScheme::MlDsa87Ed25519
        | CompositeScheme::MlDsa44Ed25519 => {
            let bytes: [u8; 32] = sk.try_into().expect("Ed25519 sk must be 32 bytes");
            let signing_key = Ed25519SigningKey::from_bytes(&bytes);
            signing_key.sign(msg).to_bytes().to_vec()
        }
        CompositeScheme::MlDsa65EcdsaP256 => {
            let signing_key = P256SigningKey::from_bytes(sk.into())
                .expect("P-256 sk must be 32 bytes");
            let sig: P256Signature = EcdsaSigner::sign(&signing_key, msg);
            sig.to_der().as_bytes().to_vec()
        }
    }
}

fn sign_pq(scheme: CompositeScheme, sk: &[u8], msg: &[u8]) -> Vec<u8> {
    match scheme {
        CompositeScheme::MlDsa44Ed25519 => mldsa::sign::<MlDsa44>(sk, msg),
        CompositeScheme::MlDsa65Ed25519
        | CompositeScheme::MlDsa65EcdsaP256 => mldsa::sign::<MlDsa65>(sk, msg),
        CompositeScheme::MlDsa87Ed25519 => mldsa::sign::<MlDsa87>(sk, msg),
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a composite signature. Returns `true` only if **both** components verify.
pub fn verify(scheme: CompositeScheme, pk: &[u8], msg: &[u8], sig: &CompositeSig) -> bool {
    let data = &sig.bytes;
    if data.len() < 4 {
        return false;
    }
    let classical_sig_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + classical_sig_len {
        return false;
    }
    let sig_classical = &data[4..4 + classical_sig_len];
    let sig_pq = &data[4 + classical_sig_len..];

    let pk_classical = &pk[..classical_pk_size(scheme)];
    let pk_pq = &pk[classical_pk_size(scheme)..];

    let classical_ok = verify_classical(scheme, pk_classical, msg, sig_classical);
    let pq_ok = verify_pq(scheme, pk_pq, msg, sig_pq);

    classical_ok && pq_ok
}

fn verify_classical(scheme: CompositeScheme, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match scheme {
        CompositeScheme::MlDsa65Ed25519
        | CompositeScheme::MlDsa87Ed25519
        | CompositeScheme::MlDsa44Ed25519 => {
            let pk_bytes: [u8; 32] = match pk.try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            let verifying_key = match Ed25519VerifyingKey::from_bytes(&pk_bytes) {
                Ok(k) => k,
                Err(_) => return false,
            };
            let sig_bytes: [u8; 64] = match sig.try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            verifying_key.verify(msg, &signature).is_ok()
        }
        CompositeScheme::MlDsa65EcdsaP256 => {
            let verifying_key = match P256VerifyingKey::from_sec1_bytes(pk) {
                Ok(k) => k,
                Err(_) => return false,
            };
            let signature = match P256Signature::from_der(sig) {
                Ok(s) => s,
                Err(_) => return false,
            };
            EcdsaVerifier::verify(&verifying_key, msg, &signature).is_ok()
        }
    }
}

fn verify_pq(scheme: CompositeScheme, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match scheme {
        CompositeScheme::MlDsa44Ed25519 => mldsa::verify::<MlDsa44>(pk, msg, sig),
        CompositeScheme::MlDsa65Ed25519
        | CompositeScheme::MlDsa65EcdsaP256 => mldsa::verify::<MlDsa65>(pk, msg, sig),
        CompositeScheme::MlDsa87Ed25519 => mldsa::verify::<MlDsa87>(pk, msg, sig),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn roundtrip(scheme: CompositeScheme) {
        let mut rng = OsRng;
        let kp = key_gen(scheme, &mut rng);
        let msg = b"Composite signature test message";
        let sig = sign(&kp, msg);
        assert!(verify(scheme, &kp.pk, msg, &sig), "valid signature must verify");
    }

    fn wrong_message(scheme: CompositeScheme) {
        let mut rng = OsRng;
        let kp = key_gen(scheme, &mut rng);
        let msg = b"Original message";
        let sig = sign(&kp, msg);
        assert!(!verify(scheme, &kp.pk, b"Tampered message", &sig), "wrong message must fail");
    }

    fn tamper_classical(scheme: CompositeScheme) {
        let mut rng = OsRng;
        let kp = key_gen(scheme, &mut rng);
        let msg = b"Test message for tamper";
        let sig = sign(&kp, msg);
        let mut tampered = sig.bytes.clone();
        // Flip a byte in the classical signature portion (byte index 4)
        if tampered.len() > 4 {
            tampered[4] ^= 0xFF;
        }
        let tampered_sig = CompositeSig { bytes: tampered };
        assert!(!verify(scheme, &kp.pk, msg, &tampered_sig),
            "tampered classical sig must fail");
    }

    fn tamper_pq(scheme: CompositeScheme) {
        let mut rng = OsRng;
        let kp = key_gen(scheme, &mut rng);
        let msg = b"Test message for tamper PQ";
        let sig = sign(&kp, msg);
        let mut tampered = sig.bytes.clone();
        // Flip the last byte (in the PQ portion)
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let tampered_sig = CompositeSig { bytes: tampered };
        assert!(!verify(scheme, &kp.pk, msg, &tampered_sig),
            "tampered PQ sig must fail");
    }

    // ML-DSA-65 + Ed25519
    #[test]
    fn test_roundtrip_mldsa65_ed25519() { roundtrip(MLDSA65_ED25519); }
    #[test]
    fn test_wrong_msg_mldsa65_ed25519() { wrong_message(MLDSA65_ED25519); }
    #[test]
    fn test_tamper_classical_mldsa65_ed25519() { tamper_classical(MLDSA65_ED25519); }
    #[test]
    fn test_tamper_pq_mldsa65_ed25519() { tamper_pq(MLDSA65_ED25519); }

    // ML-DSA-65 + ECDSA-P256
    #[test]
    fn test_roundtrip_mldsa65_ecdsa() { roundtrip(MLDSA65_ECDSA_P256); }
    #[test]
    fn test_wrong_msg_mldsa65_ecdsa() { wrong_message(MLDSA65_ECDSA_P256); }
    #[test]
    fn test_tamper_classical_mldsa65_ecdsa() { tamper_classical(MLDSA65_ECDSA_P256); }
    #[test]
    fn test_tamper_pq_mldsa65_ecdsa() { tamper_pq(MLDSA65_ECDSA_P256); }

    // ML-DSA-87 + Ed25519
    #[test]
    fn test_roundtrip_mldsa87_ed25519() { roundtrip(MLDSA87_ED25519); }
    #[test]
    fn test_wrong_msg_mldsa87_ed25519() { wrong_message(MLDSA87_ED25519); }
    #[test]
    fn test_tamper_classical_mldsa87_ed25519() { tamper_classical(MLDSA87_ED25519); }
    #[test]
    fn test_tamper_pq_mldsa87_ed25519() { tamper_pq(MLDSA87_ED25519); }

    // ML-DSA-44 + Ed25519
    #[test]
    fn test_roundtrip_mldsa44_ed25519() { roundtrip(MLDSA44_ED25519); }
    #[test]
    fn test_wrong_msg_mldsa44_ed25519() { wrong_message(MLDSA44_ED25519); }
    #[test]
    fn test_tamper_classical_mldsa44_ed25519() { tamper_classical(MLDSA44_ED25519); }
    #[test]
    fn test_tamper_pq_mldsa44_ed25519() { tamper_pq(MLDSA44_ED25519); }
}
