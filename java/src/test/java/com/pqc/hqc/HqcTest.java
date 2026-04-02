package com.pqc.hqc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the HQC KEM implementation.
 */
class HqcTest {

    static Stream<HqcParams> allParams() {
        return Stream.of(HqcParams.allParams());
    }

    // --- GF(256) tests ---

    @Test
    void testGF256Tables() {
        for (int i = 1; i < 256; i++) {
            int logA = GF256.LOG[i];
            int expLogA = GF256.EXP[logA];
            assertEquals(i, expLogA, "exp(log(" + i + ")) should equal " + i);
        }
    }

    @Test
    void testGF256Mul() {
        for (int i = 0; i < 256; i++) {
            assertEquals(i, GF256.mul(1, i), "1 * " + i + " should equal " + i);
        }
        for (int i = 1; i < 256; i++) {
            assertEquals(1, GF256.mul(i, GF256.inv(i)),
                i + " * inv(" + i + ") should equal 1");
        }
    }

    // --- GF(2) vector tests ---

    @Test
    void testGF2VectOps() {
        long[] a = { 0xAAAAL, 0x5555L };
        long[] b = { 0x5555L, 0xAAAAL };
        long[] c = GF2.vectAdd(a, b);
        assertEquals(0xFFFFL, c[0]);
        assertEquals(0xFFFFL, c[1]);

        long[] one = { 1, 0 };
        long[] d = { 0xDEADBEEFCAFEBABEL, 0x1234567890ABCDEFL };
        long[] r = GF2.vectMul(d, one, 128);
        assertEquals(d[0], r[0]);
        assertEquals(d[1], r[1]);
    }

    // --- Reed-Muller tests ---

    @Test
    void testRMEncodeDecodeRoundtrip() {
        for (int msg = 0; msg < 256; msg++) {
            for (int mult : new int[]{ 3, 5 }) {
                int n2 = mult * 128;
                int nWords = (n2 + 63) / 64;
                long[] cw = new long[nWords];
                ReedMuller.encodeInto(cw, msg, 0, mult);
                int decoded = ReedMuller.decode(cw, n2, mult);
                assertEquals(msg, decoded,
                    "RM mult=" + mult + " msg=" + msg + ": got " + decoded);
            }
        }
    }

    // --- Reed-Solomon tests ---

    @ParameterizedTest
    @MethodSource("allParams")
    void testRSEncodeDecodeRoundtrip(HqcParams p) {
        int[] msg = new int[p.k];
        for (int i = 0; i < msg.length; i++) {
            msg[i] = (i + 1) & 0xFF;
        }
        int[] cw = ReedSolomon.encode(msg, p);
        int[] decoded = ReedSolomon.decode(cw, p);
        assertNotNull(decoded, "decode failed on clean codeword");
        assertArrayEquals(msg, decoded);
    }

    @ParameterizedTest
    @MethodSource("allParams")
    void testRSDecodeWithErrors(HqcParams p) {
        int[] msg = new int[p.k];
        for (int i = 0; i < msg.length; i++) {
            msg[i] = (i * 3 + 7) & 0xFF;
        }
        int[] cw = ReedSolomon.encode(msg, p);
        // Introduce delta correctable errors
        for (int i = 0; i < p.delta; i++) {
            cw[i] ^= (i + 1) & 0xFF;
        }
        int[] decoded = ReedSolomon.decode(cw, p);
        assertNotNull(decoded, "decode failed with correctable errors");
        assertArrayEquals(msg, decoded);
    }

    // --- Tensor code tests ---

    @ParameterizedTest
    @MethodSource("allParams")
    void testTensorEncodeDecodeRoundtrip(HqcParams p) {
        byte[] msg = new byte[p.k];
        for (int i = 0; i < msg.length; i++) {
            msg[i] = (byte) (i + 42);
        }
        long[] encoded = TensorCode.encode(msg, p);
        byte[] decoded = TensorCode.decode(encoded, p);
        assertNotNull(decoded, "tensor decode failed");
        assertArrayEquals(msg, decoded);
    }

    // --- KEM roundtrip tests ---

    @ParameterizedTest
    @MethodSource("allParams")
    void testRoundtrip(HqcParams p) {
        byte[][] keys = Hqc.keyGen(p);
        byte[] pk = keys[0];
        byte[] sk = keys[1];

        assertEquals(p.pkSize, pk.length);
        assertEquals(p.skSize, sk.length);

        byte[][] enc = Hqc.encaps(pk, p);
        byte[] ct = enc[0];
        byte[] ss1 = enc[1];

        assertEquals(p.ctSize, ct.length);
        assertEquals(p.ssSize, ss1.length);

        byte[] ss2 = Hqc.decaps(sk, ct, p);
        assertArrayEquals(ss1, ss2, "shared secrets must match");
    }

    @Test
    void testDecapsBadCiphertext() {
        HqcParams p = HqcParams.HQC_128;
        byte[][] keys = Hqc.keyGen(p);
        byte[][] enc = Hqc.encaps(keys[0], p);
        byte[] ct = enc[0];
        byte[] ss1 = enc[1];

        // Corrupt the ciphertext
        ct[0] ^= (byte) 0xFF;
        ct[1] ^= (byte) 0xFF;

        byte[] ss2 = Hqc.decaps(keys[1], ct, p);
        assertFalse(java.util.Arrays.equals(ss1, ss2),
            "shared secrets should not match with corrupted ciphertext");
    }

    @ParameterizedTest
    @MethodSource("allParams")
    void testMultipleRoundtrips(HqcParams p) {
        int trials = 10;
        for (int i = 0; i < trials; i++) {
            byte[][] keys = Hqc.keyGen(p);
            byte[][] enc = Hqc.encaps(keys[0], p);
            byte[] ss2 = Hqc.decaps(keys[1], enc[0], p);
            assertArrayEquals(enc[1], ss2,
                "trial " + i + ": shared secrets do not match");
        }
    }
}
