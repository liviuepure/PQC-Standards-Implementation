package com.pqc.tls;

import com.pqc.composite.CompositeSig;
import com.pqc.mldsa.DsaParams;
import com.pqc.mldsa.MLDSA;

/**
 * PQC Signature Algorithms for TLS 1.3.
 * <p>
 * Defines PQC and composite signature algorithms for the {@code signature_algorithms}
 * extension (CertificateVerify), along with sign/verify helpers.
 */
public final class SigAlgorithms {

    private SigAlgorithms() {}

    // ── Code points ────────────────────────────────────────────────────────

    /** ML-DSA-44 (0x0904). */
    public static final int MLDSA44 = 0x0904;
    /** ML-DSA-65 (0x0905). */
    public static final int MLDSA65 = 0x0905;
    /** ML-DSA-87 (0x0906). */
    public static final int MLDSA87 = 0x0906;
    /** ML-DSA-65 + Ed25519 composite (0x0907). */
    public static final int MLDSA65_ED25519 = 0x0907;
    /** ML-DSA-87 + Ed25519 composite (0x0908). */
    public static final int MLDSA87_ED25519 = 0x0908;

    /** All defined signature algorithms. */
    public static final int[] ALL = { MLDSA44, MLDSA65, MLDSA87, MLDSA65_ED25519, MLDSA87_ED25519 };

    /** Human-readable name. */
    public static String name(int algId) {
        return switch (algId) {
            case MLDSA44 -> "MLDSA44";
            case MLDSA65 -> "MLDSA65";
            case MLDSA87 -> "MLDSA87";
            case MLDSA65_ED25519 -> "MLDSA65_ED25519";
            case MLDSA87_ED25519 -> "MLDSA87_ED25519";
            default -> "Unknown";
        };
    }

    /** Whether the algorithm is composite. */
    public static boolean isComposite(int algId) {
        return algId == MLDSA65_ED25519 || algId == MLDSA87_ED25519;
    }

    /** Whether the code point is a known signature algorithm. */
    public static boolean isKnown(int codePoint) {
        return codePoint == MLDSA44 || codePoint == MLDSA65 || codePoint == MLDSA87 ||
               codePoint == MLDSA65_ED25519 || codePoint == MLDSA87_ED25519;
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static DsaParams mldsaParams(int algId) {
        return switch (algId) {
            case MLDSA44 -> DsaParams.ML_DSA_44;
            case MLDSA65 -> DsaParams.ML_DSA_65;
            case MLDSA87 -> DsaParams.ML_DSA_87;
            default -> throw new IllegalArgumentException("Not a pure ML-DSA algorithm: " + algId);
        };
    }

    private static CompositeSig.Scheme compositeScheme(int algId) {
        return switch (algId) {
            case MLDSA65_ED25519 -> CompositeSig.Scheme.MLDSA65_ED25519;
            case MLDSA87_ED25519 -> CompositeSig.Scheme.MLDSA87_ED25519;
            default -> throw new IllegalArgumentException("Not a composite algorithm: " + algId);
        };
    }

    // ── Key pair ───────────────────────────────────────────────────────────

    public record SigningKeyPair(
        byte[] pk,
        byte[] sk,
        int algorithm,
        /** For composite: the JCA classical key pair (needed for signing). */
        CompositeSig.CompositeKeyPair compositeKP
    ) {}

    /** Generate a signing key pair. */
    public static SigningKeyPair generateSigningKey(int algId) {
        if (isComposite(algId)) {
            CompositeSig.Scheme scheme = compositeScheme(algId);
            CompositeSig.CompositeKeyPair ckp = CompositeSig.keyGen(scheme);
            return new SigningKeyPair(ckp.pk(), ckp.sk(), algId, ckp);
        }
        DsaParams params = mldsaParams(algId);
        MLDSA.KeyPair kp = MLDSA.keyGen(params);
        return new SigningKeyPair(kp.pk(), kp.sk(), algId, null);
    }

    // ── Sign ───────────────────────────────────────────────────────────────

    /** Sign a TLS 1.3 CertificateVerify handshake hash (pure ML-DSA). */
    public static byte[] signHandshake(int algId, byte[] sk, byte[] handshakeHash) {
        DsaParams params = mldsaParams(algId);
        return MLDSA.sign(sk, handshakeHash, params);
    }

    /** Sign a TLS 1.3 CertificateVerify handshake hash (composite — needs CompositeKeyPair). */
    public static byte[] signHandshakeComposite(CompositeSig.CompositeKeyPair ckp, byte[] handshakeHash) {
        return CompositeSig.sign(ckp, handshakeHash);
    }

    /** Sign using the SigningKeyPair (works for both pure and composite). */
    public static byte[] signHandshake(SigningKeyPair kp, byte[] handshakeHash) {
        if (isComposite(kp.algorithm())) {
            return signHandshakeComposite(kp.compositeKP(), handshakeHash);
        }
        return signHandshake(kp.algorithm(), kp.sk(), handshakeHash);
    }

    // ── Verify ─────────────────────────────────────────────────────────────

    /** Verify a TLS 1.3 CertificateVerify signature. */
    public static boolean verifyHandshake(int algId, byte[] pk, byte[] handshakeHash, byte[] signature) {
        if (isComposite(algId)) {
            CompositeSig.Scheme scheme = compositeScheme(algId);
            return CompositeSig.verify(scheme, pk, handshakeHash, signature);
        }
        DsaParams params = mldsaParams(algId);
        return MLDSA.verify(pk, handshakeHash, signature, params);
    }
}
