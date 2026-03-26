//! Internal K-PKE (public key encryption) for ML-KEM.
//!
//! FIPS 203, Algorithms 13 (KeyGen), 14 (Encrypt), 15 (Decrypt).
//!
//! K-PKE is the underlying IND-CPA secure public key encryption scheme.
//! ML-KEM wraps it with the Fujisaki-Okamoto transform to achieve
//! IND-CCA2 security.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use pqc_common::field::FieldElement;
use crate::hash::g;
use crate::ntt::{ntt, ntt_inverse, multiply_ntts};
use crate::sampling::{sample_ntt, sample_poly_cbd, prf};
use crate::encode::{byte_encode, byte_decode};
use crate::compress::{compress, decompress};
use crate::params::ParameterSet;

/// K-PKE.KeyGen — FIPS 203, Algorithm 13.
///
/// Generates an encryption key pair from a 32-byte seed `d`.
/// Returns (encapsulation_key, decapsulation_key_pke).
pub fn kpke_keygen<P: ParameterSet>(d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    // (rho, sigma) = G(d || k)
    let mut g_input = vec![0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = P::K as u8;
    let (rho, sigma) = g(&g_input);

    // Generate matrix A-hat in NTT domain
    let mut a_hat = vec![[FieldElement::ZERO; 256]; P::K * P::K];
    for i in 0..P::K {
        for j in 0..P::K {
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(&rho);
            seed[32] = j as u8;
            seed[33] = i as u8;
            a_hat[i * P::K + j] = sample_ntt(&seed);
        }
    }

    // Generate secret vector s
    let mut n: u8 = 0;
    let mut s = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        let prf_output = prf(&sigma, n, 64 * P::ETA1);
        s[i] = cbd_dispatch(P::ETA1, &prf_output);
        n += 1;
    }

    // Generate error vector e
    let mut e = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        let prf_output = prf(&sigma, n, 64 * P::ETA1);
        e[i] = cbd_dispatch(P::ETA1, &prf_output);
        n += 1;
    }

    // NTT(s) and NTT(e)
    let mut s_hat = s;
    for poly in s_hat.iter_mut() {
        ntt(poly);
    }
    let mut e_hat = e;
    for poly in e_hat.iter_mut() {
        ntt(poly);
    }

    // t-hat = A-hat * s-hat + e-hat
    let mut t_hat = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        for j in 0..P::K {
            let product = multiply_ntts(&a_hat[i * P::K + j], &s_hat[j]);
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

/// K-PKE.Encrypt — FIPS 203, Algorithm 14.
///
/// Encrypts a 32-byte message `m` under the encapsulation key `ek`
/// using 32 bytes of randomness `r`.
pub fn kpke_encrypt<P: ParameterSet>(ek: &[u8], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    let ek_pke_poly_bytes = 384 * P::K;

    // Decode t-hat from ek
    let mut t_hat = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        t_hat[i] = byte_decode::<12>(&ek[i * 384..(i + 1) * 384]);
    }
    let rho = &ek[ek_pke_poly_bytes..ek_pke_poly_bytes + 32];

    // Reconstruct A-hat
    let mut a_hat = vec![[FieldElement::ZERO; 256]; P::K * P::K];
    for i in 0..P::K {
        for j in 0..P::K {
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(rho);
            seed[32] = j as u8;
            seed[33] = i as u8;
            a_hat[i * P::K + j] = sample_ntt(&seed);
        }
    }

    // Sample y, e1, e2
    let mut n: u8 = 0;
    let mut y = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        let prf_output = prf(r, n, 64 * P::ETA1);
        y[i] = cbd_dispatch(P::ETA1, &prf_output);
        n += 1;
    }

    let mut e1 = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        let prf_output = prf(r, n, 64 * P::ETA2);
        e1[i] = cbd_dispatch(P::ETA2, &prf_output);
        n += 1;
    }

    let prf_output = prf(r, n, 64 * P::ETA2);
    let e2 = cbd_dispatch(P::ETA2, &prf_output);

    // NTT(y)
    let mut y_hat = y;
    for poly in y_hat.iter_mut() {
        ntt(poly);
    }

    // u = NTT^{-1}(A^T * y-hat) + e1
    let mut u = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        let mut acc = [FieldElement::ZERO; 256];
        for j in 0..P::K {
            // A^T[i][j] = A[j][i]
            let product = multiply_ntts(&a_hat[j * P::K + i], &y_hat[j]);
            for c in 0..256 {
                acc[c] = acc[c] + product[c];
            }
        }
        ntt_inverse(&mut acc);
        for c in 0..256 {
            u[i][c] = acc[c] + e1[i][c];
        }
    }

    // v = NTT^{-1}(t-hat^T * y-hat) + e2 + Decompress_1(ByteDecode_1(m))
    let mut v = [FieldElement::ZERO; 256];
    let mut acc = [FieldElement::ZERO; 256];
    for j in 0..P::K {
        let product = multiply_ntts(&t_hat[j], &y_hat[j]);
        for c in 0..256 {
            acc[c] = acc[c] + product[c];
        }
    }
    ntt_inverse(&mut acc);

    // Decode and decompress message
    let m_poly = byte_decode::<1>(m);
    for c in 0..256 {
        let mu = decompress::<1>(m_poly[c].value());
        v[c] = acc[c] + e2[c] + mu;
    }

    // Compress and encode ciphertext
    let mut ct = Vec::with_capacity(P::CT_SIZE);
    for i in 0..P::K {
        let compressed = compress_poly_dyn(P::DU, &u[i]);
        ct.extend_from_slice(&encode_poly_dyn(P::DU, &compressed));
    }
    let compressed_v = compress_poly_dyn(P::DV, &v);
    ct.extend_from_slice(&encode_poly_dyn(P::DV, &compressed_v));

    ct
}

/// K-PKE.Decrypt — FIPS 203, Algorithm 15.
///
/// Decrypts a ciphertext under the decapsulation key, recovering
/// the 32-byte message.
pub fn kpke_decrypt<P: ParameterSet>(dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let c1_len = 32 * P::DU * P::K;

    // Decode and decompress u from c1
    let mut u = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        let chunk_size = 32 * P::DU;
        let start = i * chunk_size;
        let compressed = decode_poly_dyn(P::DU, &ct[start..start + chunk_size]);
        u[i] = decompress_poly_dyn(P::DU, &compressed);
    }

    // Decode and decompress v from c2
    let c2 = &ct[c1_len..];
    let compressed_v = decode_poly_dyn(P::DV, c2);
    let v = decompress_poly_dyn(P::DV, &compressed_v);

    // Decode s-hat from dk
    let mut s_hat = vec![[FieldElement::ZERO; 256]; P::K];
    for i in 0..P::K {
        s_hat[i] = byte_decode::<12>(&dk[i * 384..(i + 1) * 384]);
    }

    // w = v - NTT^{-1}(s-hat^T * NTT(u))
    let mut u_hat = u;
    for poly in u_hat.iter_mut() {
        ntt(poly);
    }

    let mut acc = [FieldElement::ZERO; 256];
    for j in 0..P::K {
        let product = multiply_ntts(&s_hat[j], &u_hat[j]);
        for c in 0..256 {
            acc[c] = acc[c] + product[c];
        }
    }
    ntt_inverse(&mut acc);

    let mut w = [FieldElement::ZERO; 256];
    for c in 0..256 {
        w[c] = v[c] - acc[c];
    }

    // m = ByteEncode_1(Compress_1(w))
    let mut compressed_w = [FieldElement::ZERO; 256];
    for c in 0..256 {
        compressed_w[c] = FieldElement::new(compress::<1>(w[c]));
    }
    let m_bytes = byte_encode::<1>(&compressed_w);
    let mut m = [0u8; 32];
    m.copy_from_slice(&m_bytes);
    m
}

// --- Helper functions for dynamic D values ---

fn cbd_dispatch(eta: usize, bytes: &[u8]) -> [FieldElement; 256] {
    match eta {
        2 => sample_poly_cbd::<2>(bytes),
        3 => sample_poly_cbd::<3>(bytes),
        _ => panic!("unsupported eta: {eta}"),
    }
}

fn compress_poly_dyn(d: usize, f: &[FieldElement; 256]) -> [u16; 256] {
    let mut out = [0u16; 256];
    for i in 0..256 {
        out[i] = match d {
            1 => compress::<1>(f[i]),
            4 => compress::<4>(f[i]),
            5 => compress::<5>(f[i]),
            10 => compress::<10>(f[i]),
            11 => compress::<11>(f[i]),
            _ => panic!("unsupported d: {d}"),
        };
    }
    out
}

fn decompress_poly_dyn(d: usize, c: &[u16; 256]) -> [FieldElement; 256] {
    let mut out = [FieldElement::ZERO; 256];
    for i in 0..256 {
        out[i] = match d {
            1 => decompress::<1>(c[i]),
            4 => decompress::<4>(c[i]),
            5 => decompress::<5>(c[i]),
            10 => decompress::<10>(c[i]),
            11 => decompress::<11>(c[i]),
            _ => panic!("unsupported d: {d}"),
        };
    }
    out
}

fn encode_poly_dyn(d: usize, vals: &[u16; 256]) -> Vec<u8> {
    let f: [FieldElement; 256] = core::array::from_fn(|i| FieldElement::new(vals[i]));
    match d {
        1 => byte_encode::<1>(&f),
        4 => byte_encode::<4>(&f),
        5 => byte_encode::<5>(&f),
        10 => byte_encode::<10>(&f),
        11 => byte_encode::<11>(&f),
        _ => panic!("unsupported d: {d}"),
    }
}

fn decode_poly_dyn(d: usize, bytes: &[u8]) -> [u16; 256] {
    let f = match d {
        1 => byte_decode::<1>(bytes),
        4 => byte_decode::<4>(bytes),
        5 => byte_decode::<5>(bytes),
        10 => byte_decode::<10>(bytes),
        11 => byte_decode::<11>(bytes),
        _ => panic!("unsupported d: {d}"),
    };
    let mut out = [0u16; 256];
    for i in 0..256 {
        out[i] = f[i].value();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlKem512, MlKem768, MlKem1024};

    #[test]
    fn test_kpke_keygen_768_sizes() {
        let d = [0u8; 32];
        let (ek, dk) = kpke_keygen::<MlKem768>(&d);
        assert_eq!(ek.len(), 384 * 3 + 32); // 1184
        assert_eq!(dk.len(), 384 * 3);       // 1152
    }

    #[test]
    fn test_kpke_keygen_512_sizes() {
        let d = [0u8; 32];
        let (ek, dk) = kpke_keygen::<MlKem512>(&d);
        assert_eq!(ek.len(), 384 * 2 + 32); // 800
        assert_eq!(dk.len(), 384 * 2);       // 768
    }

    #[test]
    fn test_kpke_keygen_1024_sizes() {
        let d = [0u8; 32];
        let (ek, dk) = kpke_keygen::<MlKem1024>(&d);
        assert_eq!(ek.len(), 384 * 4 + 32); // 1568
        assert_eq!(dk.len(), 384 * 4);       // 1536
    }

    #[test]
    fn test_kpke_keygen_deterministic() {
        let d = [42u8; 32];
        let (ek1, dk1) = kpke_keygen::<MlKem768>(&d);
        let (ek2, dk2) = kpke_keygen::<MlKem768>(&d);
        assert_eq!(ek1, ek2);
        assert_eq!(dk1, dk2);
    }

    #[test]
    fn test_kpke_encrypt_decrypt_768() {
        let d = [7u8; 32];
        let (ek, dk) = kpke_keygen::<MlKem768>(&d);
        let message = [0xABu8; 32];
        let randomness = [0xCDu8; 32];
        let ct = kpke_encrypt::<MlKem768>(&ek, &message, &randomness);
        assert_eq!(ct.len(), MlKem768::CT_SIZE);
        let recovered = kpke_decrypt::<MlKem768>(&dk, &ct);
        assert_eq!(recovered, message);
    }

    #[test]
    fn test_kpke_encrypt_decrypt_512() {
        let d = [3u8; 32];
        let (ek, dk) = kpke_keygen::<MlKem512>(&d);
        let message = [0x55u8; 32];
        let randomness = [0x99u8; 32];
        let ct = kpke_encrypt::<MlKem512>(&ek, &message, &randomness);
        assert_eq!(ct.len(), MlKem512::CT_SIZE);
        let recovered = kpke_decrypt::<MlKem512>(&dk, &ct);
        assert_eq!(recovered, message);
    }

    #[test]
    fn test_kpke_encrypt_decrypt_1024() {
        let d = [11u8; 32];
        let (ek, dk) = kpke_keygen::<MlKem1024>(&d);
        let message = [0xFFu8; 32];
        let randomness = [0x01u8; 32];
        let ct = kpke_encrypt::<MlKem1024>(&ek, &message, &randomness);
        assert_eq!(ct.len(), MlKem1024::CT_SIZE);
        let recovered = kpke_decrypt::<MlKem1024>(&dk, &ct);
        assert_eq!(recovered, message);
    }

    #[test]
    fn test_kpke_encrypt_decrypt_zero_message() {
        let d = [0u8; 32];
        let (ek, dk) = kpke_keygen::<MlKem768>(&d);
        let message = [0u8; 32];
        let randomness = [0u8; 32];
        let ct = kpke_encrypt::<MlKem768>(&ek, &message, &randomness);
        let recovered = kpke_decrypt::<MlKem768>(&dk, &ct);
        assert_eq!(recovered, message);
    }

    #[test]
    fn test_kpke_encrypt_deterministic() {
        let d = [7u8; 32];
        let (ek, _) = kpke_keygen::<MlKem768>(&d);
        let m = [0xABu8; 32];
        let r = [0xCDu8; 32];
        let ct1 = kpke_encrypt::<MlKem768>(&ek, &m, &r);
        let ct2 = kpke_encrypt::<MlKem768>(&ek, &m, &r);
        assert_eq!(ct1, ct2);
    }
}
