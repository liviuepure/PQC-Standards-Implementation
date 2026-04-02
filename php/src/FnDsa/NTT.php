<?php

declare(strict_types=1);

namespace PQC\FnDsa;

/**
 * NTT and INTT for FN-DSA mod q = 12289.
 *
 * Ring is Z[x]/(x^n+1) with q = 12289 = 12*1024+1.
 * Primitive root mod q is g = 11 (order q-1 = 12288 = 2^12 * 3).
 */
final class NTT
{
    public const Q = 12289;

    /** @var int[] Precomputed forward zetas for n=512 */
    private static ?array $zetas512 = null;
    /** @var int[] Precomputed inverse zetas for n=512 */
    private static ?array $zetasInv512 = null;
    /** @var int[] Precomputed forward zetas for n=1024 */
    private static ?array $zetas1024 = null;
    /** @var int[] Precomputed inverse zetas for n=1024 */
    private static ?array $zetasInv1024 = null;

    /**
     * Modular multiplication: (a * b) mod Q.
     */
    public static function mulModQ(int $a, int $b): int
    {
        return (int)($a * $b % self::Q);
    }

    /**
     * Modular addition: (a + b) mod Q with inputs in [0, Q).
     */
    public static function addModQ(int $a, int $b): int
    {
        $r = $a + $b;
        if ($r >= self::Q) {
            $r -= self::Q;
        }
        return $r;
    }

    /**
     * Modular subtraction: (a - b) mod Q with inputs in [0, Q).
     */
    public static function subModQ(int $a, int $b): int
    {
        $r = $a - $b;
        if ($r < 0) {
            $r += self::Q;
        }
        return $r;
    }

    /**
     * Fast modular exponentiation: base^exp mod Q.
     */
    public static function powModQ(int $base, int $exp): int
    {
        $result = 1;
        $b = $base % self::Q;
        if ($b < 0) {
            $b += self::Q;
        }
        while ($exp > 0) {
            if ($exp & 1) {
                $result = $result * $b % self::Q;
            }
            $exp >>= 1;
            $b = $b * $b % self::Q;
        }
        return $result;
    }

    /**
     * Reverse the low logn bits of k.
     */
    public static function bitRev(int $k, int $logn): int
    {
        $r = 0;
        for ($i = 0; $i < $logn; $i++) {
            $r = ($r << 1) | ($k & 1);
            $k >>= 1;
        }
        return $r;
    }

    /**
     * Initialize zeta tables for given n.
     */
    private static function initTables(int $n): void
    {
        if ($n === 512 && self::$zetas512 !== null) {
            return;
        }
        if ($n === 1024 && self::$zetas1024 !== null) {
            return;
        }

        $logn = ($n === 512) ? 9 : 10;
        $psi = self::powModQ(11, (self::Q - 1) / (2 * $n));

        $zetas = [];
        $zetasInv = [];
        for ($k = 0; $k < $n; $k++) {
            $br = self::bitRev($k, $logn);
            $z = self::powModQ($psi, $br);
            $zetas[$k] = $z;
            $zetasInv[$k] = self::powModQ($z, self::Q - 2);
        }

        if ($n === 512) {
            self::$zetas512 = $zetas;
            self::$zetasInv512 = $zetasInv;
        } else {
            self::$zetas1024 = $zetas;
            self::$zetasInv1024 = $zetasInv;
        }
    }

    /**
     * In-place forward negacyclic NTT.
     *
     * @param int[] &$f Polynomial coefficients in [0, Q), modified in-place.
     * @param int $n Degree (512 or 1024).
     */
    public static function ntt(array &$f, int $n): void
    {
        self::initTables($n);
        $zetas = ($n === 512) ? self::$zetas512 : self::$zetas1024;

        $k = 0;
        for ($length = $n >> 1; $length >= 1; $length >>= 1) {
            for ($start = 0; $start < $n; $start += 2 * $length) {
                $k++;
                $zeta = $zetas[$k];
                for ($j = $start; $j < $start + $length; $j++) {
                    $t = self::mulModQ($zeta, $f[$j + $length]);
                    $f[$j + $length] = self::subModQ($f[$j], $t);
                    $f[$j] = self::addModQ($f[$j], $t);
                }
            }
        }
    }

    /**
     * In-place inverse negacyclic NTT.
     *
     * @param int[] &$f NTT coefficients, modified in-place.
     * @param int $n Degree (512 or 1024).
     */
    public static function intt(array &$f, int $n): void
    {
        self::initTables($n);
        $zetasInv = ($n === 512) ? self::$zetasInv512 : self::$zetasInv1024;
        $nInv = self::powModQ($n, self::Q - 2);

        $k = $n;
        for ($length = 1; $length < $n; $length <<= 1) {
            for ($start = $n - 2 * $length; $start >= 0; $start -= 2 * $length) {
                $k--;
                $zetaInv = $zetasInv[$k];
                for ($j = $start; $j < $start + $length; $j++) {
                    $t = $f[$j];
                    $f[$j] = self::addModQ($t, $f[$j + $length]);
                    $f[$j + $length] = self::mulModQ($zetaInv, self::subModQ($t, $f[$j + $length]));
                }
            }
        }

        // Scale by n^{-1} mod Q.
        for ($i = 0; $i < $n; $i++) {
            $f[$i] = self::mulModQ($nInv, $f[$i]);
        }
    }

    /**
     * Multiply two polynomials mod (q, x^n+1) using NTT.
     *
     * @param int[] $a Coefficients in [0, Q).
     * @param int[] $b Coefficients in [0, Q).
     * @param int $n Degree.
     * @return int[] Product coefficients in [0, Q).
     */
    public static function polyMulNtt(array $a, array $b, int $n): array
    {
        $aNtt = $a;
        $bNtt = $b;
        self::ntt($aNtt, $n);
        self::ntt($bNtt, $n);
        $cNtt = [];
        for ($i = 0; $i < $n; $i++) {
            $cNtt[$i] = (int)($aNtt[$i] * $bNtt[$i] % self::Q);
        }
        self::intt($cNtt, $n);
        return $cNtt;
    }
}
