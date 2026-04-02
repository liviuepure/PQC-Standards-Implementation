<?php

declare(strict_types=1);

namespace PQC\Hqc;

/**
 * GF(2) polynomial arithmetic using GMP for arbitrary-precision bit operations.
 *
 * Polynomials are represented as GMP integers where bit i is the coefficient of x^i.
 * Arithmetic is in GF(2)[x] / (x^n - 1).
 */
final class GF2
{
    /**
     * Add two GF(2) polynomials (XOR).
     */
    public static function add(\GMP $a, \GMP $b): \GMP
    {
        return gmp_xor($a, $b);
    }

    /**
     * Set bit at position $pos.
     */
    public static function setBit(\GMP $v, int $pos): \GMP
    {
        return gmp_or($v, gmp_pow(gmp_init(2), $pos));
    }

    /**
     * Get bit at position $pos.
     */
    public static function getBit(\GMP $v, int $pos): int
    {
        return gmp_testbit($v, $pos) ? 1 : 0;
    }

    /**
     * Hamming weight (number of set bits).
     */
    public static function weight(\GMP $v): int
    {
        return gmp_popcount($v);
    }

    /**
     * Mask to n bits: clear all bits >= n.
     */
    public static function mask(\GMP $v, int $n): \GMP
    {
        $m = gmp_sub(gmp_pow(gmp_init(2), $n), gmp_init(1));
        return gmp_and($v, $m);
    }

    /**
     * Multiply two GF(2) polynomials modulo (x^n - 1).
     *
     * Uses schoolbook multiplication with reduction.
     */
    public static function mulMod(\GMP $a, \GMP $b, int $n): \GMP
    {
        // Full carryless multiplication
        $result = gmp_init(0);
        $bb = $b;
        $shift = 0;

        while (gmp_cmp($bb, gmp_init(0)) > 0) {
            if (gmp_testbit($bb, 0)) {
                $result = gmp_xor($result, gmp_mul(gmp_init(1), self::shiftLeft($a, $shift)));
            }
            $bb = self::shiftRight($bb, 1);
            $shift++;
        }

        // Reduce modulo x^n - 1
        $result = self::reduceMod($result, $n);
        return $result;
    }

    /**
     * Reduce polynomial modulo (x^n - 1).
     * Since x^n = 1, we XOR bits above position n back at position 0.
     */
    public static function reduceMod(\GMP $a, int $n): \GMP
    {
        $maskVal = gmp_sub(gmp_pow(gmp_init(2), $n), gmp_init(1));
        $result = gmp_and($a, $maskVal);
        $a = self::shiftRight($a, $n);

        while (gmp_cmp($a, gmp_init(0)) > 0) {
            $result = gmp_xor($result, gmp_and($a, $maskVal));
            $a = self::shiftRight($a, $n);
        }

        return $result;
    }

    /**
     * Convert GMP polynomial to bytes (little-endian).
     */
    public static function toBytes(\GMP $v, int $nBytes): string
    {
        $result = str_repeat("\x00", $nBytes);
        $bytes = [];
        for ($i = 0; $i < $nBytes; $i++) {
            $byte = 0;
            for ($b = 0; $b < 8; $b++) {
                if (gmp_testbit($v, $i * 8 + $b)) {
                    $byte |= (1 << $b);
                }
            }
            $bytes[] = $byte;
        }
        return pack('C*', ...$bytes);
    }

    /**
     * Convert bytes to GMP polynomial (little-endian).
     */
    public static function fromBytes(string $data, int $nBits): \GMP
    {
        $result = gmp_init(0);
        $len = strlen($data);
        for ($i = $len - 1; $i >= 0; $i--) {
            $result = gmp_or(
                self::shiftLeft($result, 8),
                gmp_init(ord($data[$i]))
            );
        }
        return self::mask($result, $nBits);
    }

    /**
     * Constant-time equality check. Returns 1 if equal, 0 otherwise.
     */
    public static function equal(\GMP $a, \GMP $b): int
    {
        return (gmp_cmp(gmp_xor($a, $b), gmp_init(0)) === 0) ? 1 : 0;
    }

    /**
     * Shift left by $n bits (GF(2) polynomial << n).
     */
    public static function shiftLeft(\GMP $v, int $n): \GMP
    {
        if ($n === 0) {
            return $v;
        }
        // GMP doesn't have native shift, use multiplication by 2^n
        return gmp_mul($v, gmp_pow(gmp_init(2), $n));
    }

    /**
     * Shift right by $n bits (GF(2) polynomial >> n).
     */
    public static function shiftRight(\GMP $v, int $n): \GMP
    {
        if ($n === 0) {
            return $v;
        }
        return gmp_div_q($v, gmp_pow(gmp_init(2), $n));
    }

    /**
     * Create GMP zero.
     */
    public static function zero(): \GMP
    {
        return gmp_init(0);
    }
}
