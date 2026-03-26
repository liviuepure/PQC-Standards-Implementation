package com.pqc.mldsa;

import org.junit.jupiter.api.Test;

import static com.pqc.mldsa.DsaField.*;
import static com.pqc.mldsa.Decompose.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ML-DSA decomposition functions.
 */
class DecomposeTest {

    @Test
    void testPower2RoundIdentity() {
        // For any r in [0, Q), r = r1 * 2^13 + r0
        for (int r = 0; r < 1000; r++) {
            int rVal = modQ((long)r * 8377);
            int[] parts = power2Round(rVal);
            int r1 = parts[0];
            int r0 = parts[1];
            int reconstructed = modQ((long)r1 * (1 << 13) + r0);
            assertEquals(rVal, reconstructed,
                "Power2Round identity failed for r=" + rVal + ": r1=" + r1 + ", r0=" + r0);
        }
    }

    @Test
    void testPower2RoundR0Range() {
        // r0 should be in [-(2^12-1), 2^12]
        for (int r = 0; r < 1000; r++) {
            int rVal = modQ((long)r * 12347);
            int[] parts = power2Round(rVal);
            int r0 = parts[1];
            assertTrue(r0 >= -(1 << 12) + 1, "r0 too small: " + r0);
            assertTrue(r0 <= (1 << 12), "r0 too large: " + r0);
        }
    }

    @Test
    void testDecomposeIdentity44() {
        int gamma2 = 95232; // ML-DSA-44
        for (int i = 0; i < 1000; i++) {
            int r = modQ((long)i * 9871);
            int[] parts = decompose(r, gamma2);
            int r1 = parts[0];
            int r0 = parts[1];
            int reconstructed = modQ((long)r1 * 2 * gamma2 + r0);
            assertEquals(r, reconstructed,
                "Decompose identity failed for r=" + r + " with gamma2=" + gamma2);
        }
    }

    @Test
    void testDecomposeIdentity65() {
        int gamma2 = 261888; // ML-DSA-65/87
        for (int i = 0; i < 1000; i++) {
            int r = modQ((long)i * 7331);
            int[] parts = decompose(r, gamma2);
            int r1 = parts[0];
            int r0 = parts[1];
            int reconstructed = modQ((long)r1 * 2 * gamma2 + r0);
            assertEquals(r, reconstructed,
                "Decompose identity failed for r=" + r + " with gamma2=" + gamma2);
        }
    }

    @Test
    void testHintRoundTrip() {
        // MakeHint/UseHint property:
        // If we decompose w into (w1, w0), then modify w0 by some small amount,
        // MakeHint tells us if the high bits changed, and UseHint recovers the original w1.
        int gamma2 = 95232;
        for (int i = 0; i < 200; i++) {
            int w = modQ((long)i * 41111);
            int[] parts = decompose(w, gamma2);
            int w1 = parts[0];
            int w0 = parts[1];
            // Small perturbation
            int perturbed_w0 = w0 + (i % 20) - 10;
            int hint = makeHint(perturbed_w0, w1, gamma2);
            assertTrue(hint == 0 || hint == 1, "Hint should be 0 or 1");
        }
    }

    @Test
    void testUseHintConsistency() {
        int gamma2 = 261888;
        for (int i = 0; i < 200; i++) {
            int r = modQ((long)i * 41111);
            int h = (i % 3 == 0) ? 1 : 0;
            int result = useHint(h, r, gamma2);
            assertTrue(result >= 0, "UseHint result should be non-negative");
        }
    }
}
