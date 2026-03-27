package com.pqc.tls;

import com.pqc.hybrid.HybridKEM;
import com.pqc.mlkem.MLKEM;
import com.pqc.mlkem.Params;

/**
 * PQC Named Groups for TLS 1.3 key exchange.
 * <p>
 * Defines PQC and hybrid named groups for the {@code supported_groups} extension,
 * along with key share generation and exchange completion helpers.
 */
public final class NamedGroups {

    private NamedGroups() {}

    // ── Code points ────────────────────────────────────────────────────────

    /** Pure ML-KEM-768 (0x0768). */
    public static final int MLKEM768 = 0x0768;
    /** Pure ML-KEM-1024 (0x1024). */
    public static final int MLKEM1024 = 0x1024;
    /** X25519 + ML-KEM-768 hybrid (0x6399). */
    public static final int X25519MLKEM768 = 0x6399;
    /** P-256 + ML-KEM-768 hybrid (0x639A). */
    public static final int SecP256r1MLKEM768 = 0x639A;

    /** All defined named groups. */
    public static final int[] ALL = { MLKEM768, MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768 };

    /** Human-readable name. */
    public static String name(int groupId) {
        return switch (groupId) {
            case MLKEM768 -> "MLKEM768";
            case MLKEM1024 -> "MLKEM1024";
            case X25519MLKEM768 -> "X25519MLKEM768";
            case SecP256r1MLKEM768 -> "SecP256r1MLKEM768";
            default -> "Unknown";
        };
    }

    /** Whether the code point is a known named group. */
    public static boolean isKnown(int codePoint) {
        return codePoint == MLKEM768 || codePoint == MLKEM1024 ||
               codePoint == X25519MLKEM768 || codePoint == SecP256r1MLKEM768;
    }

    // ── Results ────────────────────────────────────────────────────────────

    public record KeyShareResult(
        byte[] privateKey,
        byte[] publicKeyShare,
        int classicalEkSize,
        int classicalDkSize
    ) {}

    public record KeyExchangeResult(
        byte[] sharedSecret,
        byte[] responseKeyShare,
        int classicalCtSize
    ) {}

    // ── Key share generation ───────────────────────────────────────────────

    private static Params mlkemParams(int groupId) {
        return switch (groupId) {
            case MLKEM768 -> Params.ML_KEM_768;
            case MLKEM1024 -> Params.ML_KEM_1024;
            default -> throw new IllegalArgumentException("Not a pure ML-KEM group: " + groupId);
        };
    }

    private static HybridKEM.Scheme hybridScheme(int groupId) {
        return switch (groupId) {
            case X25519MLKEM768 -> HybridKEM.Scheme.X25519_MLKEM768;
            case SecP256r1MLKEM768 -> HybridKEM.Scheme.ECDHP256_MLKEM768;
            default -> throw new IllegalArgumentException("Not a hybrid group: " + groupId);
        };
    }

    /** Generate a key share for the given named group. */
    public static KeyShareResult generateKeyShare(int groupId) {
        return switch (groupId) {
            case MLKEM768, MLKEM1024 -> {
                Params p = mlkemParams(groupId);
                MLKEM.KeyPair kp = MLKEM.keyGen(p);
                yield new KeyShareResult(kp.dk(), kp.ek(), 0, 0);
            }
            case X25519MLKEM768, SecP256r1MLKEM768 -> {
                HybridKEM.Scheme scheme = hybridScheme(groupId);
                HybridKEM.HybridKeyPair kp = HybridKEM.keyGen(scheme);
                yield new KeyShareResult(kp.dk(), kp.ek(), kp.classicalEkSize(), kp.classicalDkSize());
            }
            default -> throw new IllegalArgumentException("Unsupported named group: " + groupId);
        };
    }

    /** Complete key exchange as responder. */
    public static KeyExchangeResult completeKeyExchange(int groupId, byte[] peerKeyShare, int classicalEkSize) {
        return switch (groupId) {
            case MLKEM768, MLKEM1024 -> {
                Params p = mlkemParams(groupId);
                MLKEM.EncapsResult er = MLKEM.encaps(peerKeyShare, p);
                yield new KeyExchangeResult(er.sharedSecret(), er.ciphertext(), 0);
            }
            case X25519MLKEM768, SecP256r1MLKEM768 -> {
                HybridKEM.Scheme scheme = hybridScheme(groupId);
                HybridKEM.EncapsResult er = HybridKEM.encaps(scheme, peerKeyShare, classicalEkSize);
                yield new KeyExchangeResult(er.sharedSecret(), er.ciphertext(), er.classicalCtSize());
            }
            default -> throw new IllegalArgumentException("Unsupported named group: " + groupId);
        };
    }

    /** Recover shared secret as initiator. */
    public static byte[] recoverSharedSecret(int groupId, byte[] privateKey, byte[] peerResponse,
                                              int classicalDkSize, int classicalCtSize) {
        return switch (groupId) {
            case MLKEM768, MLKEM1024 -> {
                Params p = mlkemParams(groupId);
                yield MLKEM.decaps(privateKey, peerResponse, p);
            }
            case X25519MLKEM768, SecP256r1MLKEM768 -> {
                HybridKEM.Scheme scheme = hybridScheme(groupId);
                yield HybridKEM.decaps(scheme, privateKey, peerResponse, classicalDkSize, classicalCtSize);
            }
            default -> throw new IllegalArgumentException("Unsupported named group: " + groupId);
        };
    }

    /** Expected key share size. */
    public static int keyShareSize(int groupId) {
        return switch (groupId) {
            case MLKEM768 -> Params.ML_KEM_768.ekSize;
            case MLKEM1024 -> Params.ML_KEM_1024.ekSize;
            case X25519MLKEM768 -> 32 + Params.ML_KEM_768.ekSize;
            case SecP256r1MLKEM768 -> 65 + Params.ML_KEM_768.ekSize;
            default -> 0;
        };
    }
}
