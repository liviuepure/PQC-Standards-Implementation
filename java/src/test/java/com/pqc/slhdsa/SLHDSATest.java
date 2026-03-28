package com.pqc.slhdsa;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SLH-DSA (FIPS 205) implementation.
 */
class SLHDSATest {

    @Test
    void testRoundtripShake128f() {
        SlhParams params = SlhParams.SHAKE_128F;
        SLHDSA.KeyPair kp = SLHDSA.keyGen(params);

        assertNotNull(kp.secretKey());
        assertNotNull(kp.publicKey());
        assertEquals(params.skSize(), kp.secretKey().length);
        assertEquals(params.pkSize(), kp.publicKey().length);

        byte[] msg = "Hello, SLH-DSA!".getBytes();
        byte[] sig = SLHDSA.sign(msg, kp.secretKey(), params);

        assertTrue(SLHDSA.verify(msg, sig, kp.publicKey(), params));
    }

    @Test
    void testSignatureSize() {
        SlhParams params = SlhParams.SHAKE_128F;
        SLHDSA.KeyPair kp = SLHDSA.keyGen(params);

        byte[] msg = "Test message".getBytes();
        byte[] sig = SLHDSA.sign(msg, kp.secretKey(), params);

        assertEquals(params.sigSize(), sig.length,
            "Signature size should match expected size for " + params.name);
    }

    @Test
    void testRejectTamperedSignature() {
        SlhParams params = SlhParams.SHAKE_128F;
        SLHDSA.KeyPair kp = SLHDSA.keyGen(params);

        byte[] msg = "Authentic message".getBytes();
        byte[] sig = SLHDSA.sign(msg, kp.secretKey(), params);

        // Verify original signature
        assertTrue(SLHDSA.verify(msg, sig, kp.publicKey(), params));

        // Tamper with the signature (flip a byte in the middle)
        byte[] tampered = sig.clone();
        tampered[sig.length / 2] ^= 0xFF;

        assertFalse(SLHDSA.verify(msg, tampered, kp.publicKey(), params),
            "Tampered signature should not verify");
    }

    @Test
    void testRejectWrongMessage() {
        SlhParams params = SlhParams.SHAKE_128F;
        SLHDSA.KeyPair kp = SLHDSA.keyGen(params);

        byte[] msg = "Original message".getBytes();
        byte[] sig = SLHDSA.sign(msg, kp.secretKey(), params);

        byte[] wrongMsg = "Wrong message".getBytes();
        assertFalse(SLHDSA.verify(wrongMsg, sig, kp.publicKey(), params),
            "Signature should not verify for wrong message");
    }

    @Test
    void testRejectWrongKey() {
        SlhParams params = SlhParams.SHAKE_128F;
        SLHDSA.KeyPair kp1 = SLHDSA.keyGen(params);
        SLHDSA.KeyPair kp2 = SLHDSA.keyGen(params);

        byte[] msg = "Test".getBytes();
        byte[] sig = SLHDSA.sign(msg, kp1.secretKey(), params);

        assertFalse(SLHDSA.verify(msg, sig, kp2.publicKey(), params),
            "Signature should not verify with wrong public key");
    }

    @Test
    void testEmptyMessage() {
        SlhParams params = SlhParams.SHAKE_128F;
        SLHDSA.KeyPair kp = SLHDSA.keyGen(params);

        byte[] msg = new byte[0];
        byte[] sig = SLHDSA.sign(msg, kp.secretKey(), params);

        assertTrue(SLHDSA.verify(msg, sig, kp.publicKey(), params),
            "Empty message should sign and verify");
    }

    @Test
    void testParameterSetSizes() {
        // Verify expected sizes for SHAKE-128f per FIPS 205 Table 1
        SlhParams p = SlhParams.SHAKE_128F;
        assertEquals(16, p.n);
        assertEquals(16, p.w);
        assertEquals(3,  p.hPrime);
        assertEquals(22, p.d);
        assertEquals(66, p.h);  // 3 * 22
        assertEquals(6,  p.a);
        assertEquals(33, p.k);
    }

    @Test
    void testWrongSigLengthRejected() {
        SlhParams params = SlhParams.SHAKE_128F;
        SLHDSA.KeyPair kp = SLHDSA.keyGen(params);

        byte[] msg = "Test".getBytes();
        byte[] shortSig = new byte[100]; // way too short

        assertFalse(SLHDSA.verify(msg, shortSig, kp.publicKey(), params),
            "Wrong-length signature should be rejected");
    }
}
