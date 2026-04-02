<?php

declare(strict_types=1);

namespace PQC\FnDsa;

/**
 * Gaussian sampling for FN-DSA (FIPS 206).
 *
 * Uses the RCDT (Rejection Cumulative Distribution Table) approach
 * with base sigma_0 = 1.8205, and rejection sampling for larger sigma.
 */
final class Gaussian
{
    private const SIGMA0 = 1.8205;

    /**
     * RCDT table entries as [hi (uint8), lo (uint64 as string for GMP)].
     * Each entry i: table[i] = floor(2^72 * Pr[|Z| >= i+1]).
     */
    private const RCDT_TABLE = [
        [199, '16610441552002023424'],
        [103, '7624082642567692288'],
        [42,  '919243735747002368'],
        [13,  '3484267233246674944'],
        [3,   '2772878652510347264'],
        [0,   '10479598105528201216'],
        [0,   '1418221736465465344'],
        [0,   '143439473028577328'],
        [0,   '10810581864167812'],
        [0,   '605874652027744'],
        [0,   '25212870589170'],
        [0,   '778215157694'],
        [0,   '17802250993'],
        [0,   '301647562'],
        [0,   '3784361'],
        [0,   '35141'],
        [0,   '241'],
        [0,   '1'],
    ];

    /**
     * Sample from D_{Z, sigma0} using the RCDT table.
     *
     * @param string $randomBytes At least 10 bytes of random data.
     * @param int $offset Offset into randomBytes to start reading.
     * @return array [value, bytesConsumed]
     */
    public static function sampleBaseGaussian(string $randomBytes, int $offset): array
    {
        // Read 9 bytes (72 bits) for the sample.
        // Interpret first 8 bytes as little-endian uint64.
        $sampleLo = gmp_import(strrev(substr($randomBytes, $offset, 8)));
        $sampleHi = ord($randomBytes[$offset + 8]);

        // Count how many table entries the sample falls strictly below.
        $z = 0;
        for ($i = 0; $i < 18; $i++) {
            $tHi = self::RCDT_TABLE[$i][0];
            $tLo = gmp_init(self::RCDT_TABLE[$i][1]);

            // 72-bit comparison: sample < table[i]
            if ($sampleHi < $tHi || ($sampleHi === $tHi && gmp_cmp($sampleLo, $tLo) < 0)) {
                $z++;
            }
        }

        // Read 1 byte for sign.
        $signBit = ord($randomBytes[$offset + 9]) & 1;
        if ($signBit) {
            $z = -$z;
        }

        return [$z, 10];
    }

    /**
     * Sample from D_{Z, sigma} using RCDT + rejection.
     *
     * @param callable $rng Function that returns n random bytes: rng(int $n): string
     * @param float $sigma Standard deviation.
     * @return int Sampled value.
     */
    public static function sampleGaussian(callable $rng, float $sigma): int
    {
        $sigma2 = $sigma * $sigma;
        $sigma02 = self::SIGMA0 * self::SIGMA0;
        $c = ($sigma2 - $sigma02) / (2.0 * $sigma2 * $sigma02);

        while (true) {
            $bytes = $rng(18); // 10 for base + 8 for rejection
            [$z, ] = self::sampleBaseGaussian($bytes, 0);

            // Rejection step: accept with probability exp(-z^2 * c).
            $fz = (float)$z;
            $logProb = -$fz * $fz * $c;

            // Sample u uniformly in [0, 1) using 53 random bits.
            $ubytes = substr($bytes, 10, 8);
            $u64 = unpack('P', $ubytes)[1]; // unsigned 64-bit LE
            // PHP's unpack 'P' gives signed, handle with care
            // Use bit masking to get 53 bits
            $u53 = self::unsignedRightShift64($u64, 11);
            $u = $u53 / (float)(1 << 53);

            if ($u < exp($logProb)) {
                return $z;
            }
        }
    }

    /**
     * Unsigned right shift for 64-bit integers.
     * PHP's >> is arithmetic (sign-extending), so we mask.
     */
    private static function unsignedRightShift64(int $val, int $shift): int
    {
        if ($shift === 0) return $val;
        if ($shift >= 64) return 0;
        // Clear the sign bit after shifting
        return ($val >> $shift) & ((1 << (64 - $shift)) - 1);
    }
}
