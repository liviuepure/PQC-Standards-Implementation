package com.pqc.mldsa;

import org.junit.jupiter.api.Test;

import static com.pqc.mldsa.DsaField.*;
import static com.pqc.mldsa.DsaNTT.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ML-DSA NTT operations.
 */
class DsaNTTTest {

    @Test
    void testZetasRange() {
        // All zetas should be in [0, Q)
        for (int i = 0; i < 256; i++) {
            assertTrue(ZETAS[i] >= 0, "zeta[" + i + "] should be >= 0");
            assertTrue(ZETAS[i] < Q, "zeta[" + i + "] should be < Q");
        }
    }

    @Test
    void testZeta0Is1() {
        // bitRev8(0) = 0, so zeta[0] = 1753^0 = 1
        assertEquals(1, ZETAS[0]);
    }

    @Test
    void testBitRev8() {
        assertEquals(0, bitRev8(0));
        assertEquals(128, bitRev8(1)); // 00000001 -> 10000000
        assertEquals(64, bitRev8(2));  // 00000010 -> 01000000
        assertEquals(255, bitRev8(255));
    }

    @Test
    void testNttRoundTrip() {
        // Create a random-ish polynomial
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) {
            f[i] = modQ((long)i * 12345 + 67890);
        }

        int[] fHat = ntt(f);
        int[] fBack = nttInverse(fHat);

        for (int i = 0; i < 256; i++) {
            assertEquals(f[i], fBack[i],
                "NTT round-trip failed at index " + i + ": expected " + f[i] + " got " + fBack[i]);
        }
    }

    @Test
    void testNttRoundTripZero() {
        int[] f = new int[256]; // all zeros
        int[] fHat = ntt(f);
        int[] fBack = nttInverse(fHat);
        for (int i = 0; i < 256; i++) {
            assertEquals(0, fBack[i]);
        }
    }

    @Test
    void testNttRoundTripOnes() {
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) f[i] = 1;
        int[] fHat = ntt(f);
        int[] fBack = nttInverse(fHat);
        for (int i = 0; i < 256; i++) {
            assertEquals(1, fBack[i]);
        }
    }

    @Test
    void testPointwiseMul() {
        int[] a = new int[256];
        int[] b = new int[256];
        for (int i = 0; i < 256; i++) {
            a[i] = modQ(i + 1);
            b[i] = modQ(256 - i);
        }
        int[] c = pointwiseMul(a, b);
        for (int i = 0; i < 256; i++) {
            assertEquals(fieldMul(a[i], b[i]), c[i]);
        }
    }
}
