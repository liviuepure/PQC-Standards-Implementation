package com.pqc.mldsa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ML-DSA key generation, signing, and verification.
 */
class MLDSATest {

    @Test
    void testKeyGenSizes44() {
        MLDSA.KeyPair kp = MLDSA.keyGen(DsaParams.ML_DSA_44);
        assertEquals(DsaParams.ML_DSA_44.pkSize, kp.pk().length,
            "ML-DSA-44 public key size mismatch");
        assertEquals(DsaParams.ML_DSA_44.skSize, kp.sk().length,
            "ML-DSA-44 secret key size mismatch");
    }

    @Test
    void testKeyGenSizes65() {
        MLDSA.KeyPair kp = MLDSA.keyGen(DsaParams.ML_DSA_65);
        assertEquals(DsaParams.ML_DSA_65.pkSize, kp.pk().length,
            "ML-DSA-65 public key size mismatch");
        assertEquals(DsaParams.ML_DSA_65.skSize, kp.sk().length,
            "ML-DSA-65 secret key size mismatch");
    }

    @Test
    void testKeyGenSizes87() {
        MLDSA.KeyPair kp = MLDSA.keyGen(DsaParams.ML_DSA_87);
        assertEquals(DsaParams.ML_DSA_87.pkSize, kp.pk().length,
            "ML-DSA-87 public key size mismatch");
        assertEquals(DsaParams.ML_DSA_87.skSize, kp.sk().length,
            "ML-DSA-87 secret key size mismatch");
    }

    @Test
    void testSignVerify44() {
        DsaParams params = DsaParams.ML_DSA_44;
        MLDSA.KeyPair kp = MLDSA.keyGen(params);
        byte[] msg = "Hello, ML-DSA-44!".getBytes();

        byte[] sig = MLDSA.sign(kp.sk(), msg, params);
        assertNotNull(sig);
        assertEquals(params.sigSize, sig.length,
            "ML-DSA-44 signature size mismatch");

        boolean valid = MLDSA.verify(kp.pk(), msg, sig, params);
        assertTrue(valid, "ML-DSA-44 signature should verify");
    }

    @Test
    void testSignVerify65() {
        DsaParams params = DsaParams.ML_DSA_65;
        MLDSA.KeyPair kp = MLDSA.keyGen(params);
        byte[] msg = "Hello, ML-DSA-65!".getBytes();

        byte[] sig = MLDSA.sign(kp.sk(), msg, params);
        assertNotNull(sig);
        assertEquals(params.sigSize, sig.length,
            "ML-DSA-65 signature size mismatch");

        boolean valid = MLDSA.verify(kp.pk(), msg, sig, params);
        assertTrue(valid, "ML-DSA-65 signature should verify");
    }

    @Test
    void testSignVerify87() {
        DsaParams params = DsaParams.ML_DSA_87;
        MLDSA.KeyPair kp = MLDSA.keyGen(params);
        byte[] msg = "Hello, ML-DSA-87!".getBytes();

        byte[] sig = MLDSA.sign(kp.sk(), msg, params);
        assertNotNull(sig);
        assertEquals(params.sigSize, sig.length,
            "ML-DSA-87 signature size mismatch");

        boolean valid = MLDSA.verify(kp.pk(), msg, sig, params);
        assertTrue(valid, "ML-DSA-87 signature should verify");
    }

    @Test
    void testRejectTamperedMessage() {
        DsaParams params = DsaParams.ML_DSA_44;
        MLDSA.KeyPair kp = MLDSA.keyGen(params);
        byte[] msg = "Original message".getBytes();
        byte[] sig = MLDSA.sign(kp.sk(), msg, params);

        // Tamper with message
        byte[] tampered = "Tampered message".getBytes();
        assertFalse(MLDSA.verify(kp.pk(), tampered, sig, params),
            "Verification should fail for tampered message");
    }

    @Test
    void testRejectTamperedSignature() {
        DsaParams params = DsaParams.ML_DSA_44;
        MLDSA.KeyPair kp = MLDSA.keyGen(params);
        byte[] msg = "Test message".getBytes();
        byte[] sig = MLDSA.sign(kp.sk(), msg, params);

        // Tamper with signature
        byte[] tamperedSig = sig.clone();
        tamperedSig[0] ^= 0xFF;
        assertFalse(MLDSA.verify(kp.pk(), msg, tamperedSig, params),
            "Verification should fail for tampered signature");
    }

    @Test
    void testRejectWrongKey() {
        DsaParams params = DsaParams.ML_DSA_44;
        MLDSA.KeyPair kp1 = MLDSA.keyGen(params);
        MLDSA.KeyPair kp2 = MLDSA.keyGen(params);
        byte[] msg = "Test message".getBytes();
        byte[] sig = MLDSA.sign(kp1.sk(), msg, params);

        // Verify with wrong public key
        assertFalse(MLDSA.verify(kp2.pk(), msg, sig, params),
            "Verification should fail with wrong public key");
    }
}
