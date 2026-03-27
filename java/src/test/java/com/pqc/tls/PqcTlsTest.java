package com.pqc.tls;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

class PqcTlsTest {

    // ── Named Groups ───────────────────────────────────────────────────────

    @Test
    void testNamedGroupCodePoints() {
        assertEquals(0x0768, NamedGroups.MLKEM768);
        assertEquals(0x1024, NamedGroups.MLKEM1024);
        assertEquals(0x6399, NamedGroups.X25519MLKEM768);
        assertEquals(0x639A, NamedGroups.SecP256r1MLKEM768);
    }

    @Test
    void testNamedGroupFromCodePoint() {
        assertTrue(NamedGroups.isKnown(0x6399));
        assertFalse(NamedGroups.isKnown(0xFFFF));
    }

    @Test
    void testMlkem768KeyExchangeRoundtrip() {
        var ks = NamedGroups.generateKeyShare(NamedGroups.MLKEM768);
        assertEquals(NamedGroups.keyShareSize(NamedGroups.MLKEM768), ks.publicKeyShare().length);

        var resp = NamedGroups.completeKeyExchange(NamedGroups.MLKEM768, ks.publicKeyShare(), 0);
        byte[] ss = NamedGroups.recoverSharedSecret(
            NamedGroups.MLKEM768, ks.privateKey(), resp.responseKeyShare(), 0, 0
        );
        assertArrayEquals(resp.sharedSecret(), ss);
    }

    @Test
    void testX25519Mlkem768KeyExchangeRoundtrip() {
        var ks = NamedGroups.generateKeyShare(NamedGroups.X25519MLKEM768);
        assertEquals(NamedGroups.keyShareSize(NamedGroups.X25519MLKEM768), ks.publicKeyShare().length);

        var resp = NamedGroups.completeKeyExchange(
            NamedGroups.X25519MLKEM768, ks.publicKeyShare(), ks.classicalEkSize()
        );
        byte[] ss = NamedGroups.recoverSharedSecret(
            NamedGroups.X25519MLKEM768, ks.privateKey(), resp.responseKeyShare(),
            ks.classicalDkSize(), resp.classicalCtSize()
        );
        assertArrayEquals(resp.sharedSecret(), ss);
    }

    @Test
    void testAllGroupsKeyShareSizes() {
        for (int group : NamedGroups.ALL) {
            var ks = NamedGroups.generateKeyShare(group);
            assertEquals(
                NamedGroups.keyShareSize(group), ks.publicKeyShare().length,
                "Key share size mismatch for " + NamedGroups.name(group)
            );
        }
    }

    // ── Signature Algorithms ───────────────────────────────────────────────

    @Test
    void testSignatureAlgorithmCodePoints() {
        assertEquals(0x0904, SigAlgorithms.MLDSA44);
        assertEquals(0x0905, SigAlgorithms.MLDSA65);
        assertEquals(0x0906, SigAlgorithms.MLDSA87);
        assertEquals(0x0907, SigAlgorithms.MLDSA65_ED25519);
        assertEquals(0x0908, SigAlgorithms.MLDSA87_ED25519);
    }

    @Test
    void testSignatureAlgorithmFromCodePoint() {
        assertTrue(SigAlgorithms.isKnown(0x0905));
        assertFalse(SigAlgorithms.isKnown(0xFFFF));
    }

    @Test
    void testMldsa65SignVerify() {
        var kp = SigAlgorithms.generateSigningKey(SigAlgorithms.MLDSA65);
        byte[] hash = "test handshake transcript hash for CertificateVerify".getBytes();
        byte[] sig = SigAlgorithms.signHandshake(kp, hash);
        assertTrue(SigAlgorithms.verifyHandshake(SigAlgorithms.MLDSA65, kp.pk(), hash, sig));
    }

    @Test
    void testCompositeMldsa65Ed25519SignVerify() {
        var kp = SigAlgorithms.generateSigningKey(SigAlgorithms.MLDSA65_ED25519);
        byte[] hash = "composite handshake hash".getBytes();
        byte[] sig = SigAlgorithms.signHandshake(kp, hash);
        assertTrue(SigAlgorithms.verifyHandshake(SigAlgorithms.MLDSA65_ED25519, kp.pk(), hash, sig));
    }

    @Test
    void testWrongKeyFailsVerification() {
        var kp1 = SigAlgorithms.generateSigningKey(SigAlgorithms.MLDSA65);
        var kp2 = SigAlgorithms.generateSigningKey(SigAlgorithms.MLDSA65);
        byte[] hash = "test hash".getBytes();
        byte[] sig = SigAlgorithms.signHandshake(kp1, hash);
        assertFalse(SigAlgorithms.verifyHandshake(SigAlgorithms.MLDSA65, kp2.pk(), hash, sig));
    }

    // ── Cipher Suites ──────────────────────────────────────────────────────

    @Test
    void testCipherSuiteDefinitions() {
        var cs = CipherSuites.TLS_AES_128_GCM_SHA256_MLKEM768;
        assertEquals(CipherSuites.AeadAlgorithm.AES_128_GCM_SHA256, cs.aead());
        assertEquals(NamedGroups.MLKEM768, cs.keyExchange());
        assertEquals(SigAlgorithms.MLDSA65, cs.signature());
    }

    @Test
    void testCipherSuiteLookupById() {
        var cs = CipherSuites.byId(0x13010768);
        assertNotNull(cs);
        assertEquals("TLS_AES_128_GCM_SHA256_MLKEM768", cs.name());

        var cs2 = CipherSuites.byId(0x13026399);
        assertNotNull(cs2);
        assertEquals("TLS_AES_256_GCM_SHA384_X25519MLKEM768", cs2.name());

        assertNull(CipherSuites.byId(0xDEADBEEF));
    }
}
