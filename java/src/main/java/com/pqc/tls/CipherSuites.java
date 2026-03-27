package com.pqc.tls;

/**
 * TLS 1.3 PQC Cipher Suite definitions.
 */
public final class CipherSuites {

    private CipherSuites() {}

    // ── AEAD Algorithms ────────────────────────────────────────────────────

    public enum AeadAlgorithm {
        AES_128_GCM_SHA256("TLS_AES_128_GCM_SHA256", 16, 32),
        AES_256_GCM_SHA384("TLS_AES_256_GCM_SHA384", 32, 48),
        CHACHA20_POLY1305_SHA256("TLS_CHACHA20_POLY1305_SHA256", 32, 32);

        public final String displayName;
        public final int keyLength;
        public final int hashLength;

        AeadAlgorithm(String displayName, int keyLength, int hashLength) {
            this.displayName = displayName;
            this.keyLength = keyLength;
            this.hashLength = hashLength;
        }
    }

    // ── Cipher Suite ───────────────────────────────────────────────────────

    public record CipherSuite(
        int id,
        String name,
        AeadAlgorithm aead,
        int keyExchange,
        int signature
    ) {}

    /** TLS_AES_128_GCM_SHA256 with ML-KEM-768 and ML-DSA-65. */
    public static final CipherSuite TLS_AES_128_GCM_SHA256_MLKEM768 = new CipherSuite(
        0x13010768,
        "TLS_AES_128_GCM_SHA256_MLKEM768",
        AeadAlgorithm.AES_128_GCM_SHA256,
        NamedGroups.MLKEM768,
        SigAlgorithms.MLDSA65
    );

    /** TLS_AES_256_GCM_SHA384 with X25519+ML-KEM-768 and ML-DSA-65+Ed25519. */
    public static final CipherSuite TLS_AES_256_GCM_SHA384_X25519MLKEM768 = new CipherSuite(
        0x13026399,
        "TLS_AES_256_GCM_SHA384_X25519MLKEM768",
        AeadAlgorithm.AES_256_GCM_SHA384,
        NamedGroups.X25519MLKEM768,
        SigAlgorithms.MLDSA65_ED25519
    );

    /** All defined PQC cipher suites. */
    public static final CipherSuite[] ALL = {
        TLS_AES_128_GCM_SHA256_MLKEM768,
        TLS_AES_256_GCM_SHA384_X25519MLKEM768,
    };

    /** Look up a cipher suite by ID. */
    public static CipherSuite byId(int id) {
        for (CipherSuite cs : ALL) {
            if (cs.id() == id) return cs;
        }
        return null;
    }
}
