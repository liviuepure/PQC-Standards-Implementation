// FN-DSA (FIPS 206 / FALCON) — pure Rust implementation.

pub mod params;
pub mod ntt;
pub mod fft;
pub mod gaussian;
pub mod ntru;
pub mod encode;
pub mod sign;
pub mod verify;

// NOTE: The FIPS 206 spec and Go reference implementation use names like
// "FNDSAPadded512" and "FNDSAPadded1024". In Rust, SCREAMING_SNAKE_CASE is
// idiomatic for constants, so we use FNDSA_PADDED_512 / FNDSA_PADDED_1024
// instead of FNDSA_PADDED512 / FNDSA_PADDED1024. This is a deliberate
// idiomatic Rust choice, not a spec deviation.
pub use params::{Params, FNDSA512, FNDSA1024, FNDSA_PADDED_512, FNDSA_PADDED_1024, ALL_PARAMS};

/// Error type for FN-DSA operations.
#[derive(Debug)]
pub enum FnDsaError {
    KeyGenFailed,
    InvalidKey,
    SigningFailed,
}

impl std::fmt::Display for FnDsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FnDsaError::KeyGenFailed => write!(f, "FN-DSA key generation failed"),
            FnDsaError::InvalidKey => write!(f, "FN-DSA invalid key"),
            FnDsaError::SigningFailed => write!(f, "FN-DSA signing failed"),
        }
    }
}

impl std::error::Error for FnDsaError {}

/// Generates a FN-DSA key pair (pk, sk) for parameter set p.
pub fn keygen<R: rand_core::RngCore>(
    p: Params,
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), FnDsaError> {
    let (f, g, cap_f, _cap_g) = ntru::ntru_keygen(p, rng)?;
    let h = ntru::ntru_public_key(&f, &g, p);
    let pk = encode::encode_pk(&h, p);
    let sk = encode::encode_sk(&f, &g, &cap_f, p);
    Ok((pk, sk))
}

/// Signs msg using the encoded secret key sk under parameter set p.
pub fn sign<R: rand_core::RngCore>(
    sk: &[u8],
    msg: &[u8],
    p: Params,
    rng: &mut R,
) -> Result<Vec<u8>, FnDsaError> {
    sign::sign(sk, msg, p, rng)
}

/// Verifies sig on msg under public key pk for parameter set p.
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8], p: Params) -> bool {
    verify::verify(pk, msg, sig, p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_consistency() {
        for p in ALL_PARAMS {
            assert!(p.n == 512 || p.n == 1024);
            assert_eq!(p.log_n, if p.n == 512 { 9 } else { 10 });
            assert!(p.pk_size > 0);
            assert!(p.sk_size > 0);
            assert!(p.sig_size > 0);
            assert!(p.beta_sq > 0);
        }
    }

    #[test]
    fn test_interop_vectors() {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/fn-dsa");

        let test_files = [
            ("FN-DSA-512.json", FNDSA512),
            ("FN-DSA-1024.json", FNDSA1024),
        ];

        for (filename, p) in &test_files {
            let path = base.join(filename);
            if !path.exists() {
                eprintln!("Skipping interop test: {} not found", path.display());
                continue;
            }

            let data = std::fs::read_to_string(&path)
                .expect("failed to read test vector file");
            let json: serde_json::Value = serde_json::from_str(&data)
                .expect("failed to parse JSON");

            let vectors = json["vectors"].as_array().expect("vectors must be array");
            for vec in vectors {
                let count = vec["count"].as_u64().unwrap_or(0);
                let pk_hex = vec["pk"].as_str().expect("pk must be string");
                let msg_hex = vec["msg"].as_str().expect("msg must be string");
                let sig_hex = vec["sig"].as_str().expect("sig must be string");

                let pk = hex::decode(pk_hex).expect("pk hex decode failed");
                let msg = hex::decode(msg_hex).expect("msg hex decode failed");
                let sig = hex::decode(sig_hex).expect("sig hex decode failed");

                assert!(
                    verify(&pk, &msg, &sig, *p),
                    "Vector {} in {} failed verification",
                    count, filename
                );
            }

            eprintln!("Passed {} vectors in {}", vectors.len(), filename);
        }
    }
}
