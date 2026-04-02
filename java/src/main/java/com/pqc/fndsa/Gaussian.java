package com.pqc.fndsa;

import java.security.SecureRandom;

/**
 * Discrete Gaussian sampler for FN-DSA (FIPS 206 §3.12).
 *
 * sigma_0 = 1.8205 (base Gaussian parameter).
 * Uses RCDT (Rejection Cumulative Distribution Table) with 72-bit entries.
 * Each entry is (hi: uint8, lo: uint64) representing floor(2^72 * Pr[|Z| >= i+1]).
 */
final class Gaussian {

    private Gaussian() {}

    static final double SIGMA_0 = 1.8205;

    // RCDT table: 18 entries, each a 72-bit unsigned integer stored as (hi, lo).
    // lo values are stored as signed Java longs but compared unsigned.
    private static final long[] RCDT_HI = {
        199L, 103L, 42L, 13L, 3L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L
    };

    // Stored as signed Java longs (bit pattern is the same as unsigned uint64).
    // Go values (unsigned): converted to signed by subtracting 2^64 when >= 2^63.
    private static final long[] RCDT_LO = {
        -1836302521707528192L,  // 16610441552002023424 unsigned (hi=199)
        7624082642567692288L,   // (hi=103)
        919243735747002368L,    // (hi=42)
        3484267233246674944L,   // (hi=13)
        2772878652510347264L,   // (hi=3)
        -7967145968181350400L,  // 10479598105528201216 unsigned (hi=0)
        1418221736465465344L,   // (hi=0)
        143439473028577328L,    // (hi=0)
        10810581864167812L,     // (hi=0)
        605874652027744L,       // (hi=0)
        25212870589170L,        // (hi=0)
        778215157694L,          // (hi=0)
        17802250993L,           // (hi=0)
        301647562L,             // (hi=0)
        3784361L,               // (hi=0)
        35141L,                 // (hi=0)
        241L,                   // (hi=0)
        1L                      // (hi=0)
    };

    private static final int TABLE_SIZE = 18;

    /**
     * Sample one integer from the base Gaussian D_{Z, sigma_0} using RCDT.
     * Reads 10 bytes from rng (9 for the 72-bit sample, 1 for sign).
     * Constant-time with respect to the sampled value.
     */
    static int sampleBase(SecureRandom rng) {
        byte[] buf = new byte[9];
        rng.nextBytes(buf);

        // Parse as little-endian 72-bit: lo = bytes[0..7], hi = bytes[8]
        long sampleLo = 0L;
        for (int i = 0; i < 8; i++) {
            sampleLo |= ((long)(buf[i] & 0xFF)) << (8 * i);
        }
        long sampleHi = buf[8] & 0xFFL; // 8-bit unsigned

        // Count how many table entries the sample falls strictly below.
        // Constant-time 72-bit unsigned comparison:
        //   (sampleHi, sampleLo) < (tHi, tLo)  iff
        //   sampleHi < tHi  OR  (sampleHi == tHi AND sampleLo < tLo)
        // All comparisons use unsigned semantics.
        int z = 0;
        for (int i = 0; i < TABLE_SIZE; i++) {
            long tHi = RCDT_HI[i];
            long tLo = RCDT_LO[i];

            // hiLT: 1 if sampleHi < tHi (both in [0,255], compare as signed is fine)
            long hiLT = (sampleHi < tHi) ? 1L : 0L;
            // hiEQ: 1 if sampleHi == tHi
            long hiEQ = (sampleHi == tHi) ? 1L : 0L;
            // loLT: 1 if sampleLo < tLo (unsigned 64-bit comparison)
            long loLT = (Long.compareUnsigned(sampleLo, tLo) < 0) ? 1L : 0L;

            long lt72 = hiLT | (hiEQ & loLT);
            z += (int) lt72;
        }

        // Read 1 byte for sign (bit 0)
        byte[] signBuf = new byte[1];
        rng.nextBytes(signBuf);
        int signBit = signBuf[0] & 1;

        // Branchless conditional negate: z if sign==0, -z if sign==1
        int mask = -signBit;
        return (z ^ mask) - mask;
    }

    /**
     * Sample from D_{Z, sigma} centered at 0.
     * Uses rejection sampling over the base D_{Z, sigma_0} sampler.
     */
    static int sampleGaussian(SecureRandom rng, double sigma) {
        double sigma2 = sigma * sigma;
        double sigma02 = SIGMA_0 * SIGMA_0;
        double c = (sigma2 - sigma02) / (2.0 * sigma2 * sigma02);

        while (true) {
            int z = sampleBase(rng);

            double fz = z;
            double logProb = -fz * fz * c; // <= 0

            // Sample u in [0, 1) using 53 random bits (float64 mantissa)
            byte[] ubuf = new byte[8];
            rng.nextBytes(ubuf);
            long u53bits = 0L;
            for (int i = 0; i < 8; i++) {
                u53bits |= ((long)(ubuf[i] & 0xFF)) << (8 * i);
            }
            u53bits >>>= 11; // unsigned right shift to get 53-bit integer
            double u = (double) u53bits / (double) (1L << 53);

            if (u < Math.exp(logProb)) {
                return z;
            }
        }
    }
}
