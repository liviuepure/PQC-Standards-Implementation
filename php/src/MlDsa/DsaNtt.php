<?php

declare(strict_types=1);

namespace PQC\MlDsa;

/**
 * NTT for ML-DSA (q=8380417, zeta=1753).
 */
final class DsaNtt
{
    private static ?array $zetas = null;

    /**
     * Precompute zetas: zeta^{BitRev8(i)} mod q.
     */
    public static function getZetas(): array
    {
        if (self::$zetas !== null) {
            return self::$zetas;
        }

        // Precomputed zetas for ML-DSA
        $zeta = 1753;
        $q = DsaField::Q;

        // Compute powers of zeta in bit-reversed order
        $powers = [];
        $powers[0] = 1;
        for ($i = 1; $i < 256; $i++) {
            $powers[$i] = DsaField::mul($powers[$i - 1], $zeta);
        }

        self::$zetas = [];
        for ($i = 0; $i < 256; $i++) {
            $br = self::bitRev8($i);
            self::$zetas[$i] = $powers[$br];
        }

        return self::$zetas;
    }

    private static function bitRev8(int $n): int
    {
        $r = 0;
        for ($i = 0; $i < 8; $i++) {
            $r = ($r << 1) | ($n & 1);
            $n >>= 1;
        }
        return $r;
    }

    /**
     * Forward NTT.
     */
    public static function ntt(array $f): array
    {
        $zetas = self::getZetas();
        $k = 1;
        $len = 128;

        while ($len >= 1) {
            for ($start = 0; $start < 256; $start += 2 * $len) {
                $z = $zetas[$k++];
                for ($j = $start; $j < $start + $len; $j++) {
                    $t = DsaField::mul($z, $f[$j + $len]);
                    $f[$j + $len] = DsaField::sub($f[$j], $t);
                    $f[$j] = DsaField::add($f[$j], $t);
                }
            }
            $len >>= 1;
        }

        return $f;
    }

    /**
     * Inverse NTT.
     */
    public static function invNtt(array $f): array
    {
        $zetas = self::getZetas();
        $k = 256;
        $len = 1;

        while ($len <= 128) {
            for ($start = 0; $start < 256; $start += 2 * $len) {
                $k--;
                $z = $zetas[$k];
                for ($j = $start; $j < $start + $len; $j++) {
                    $t = $f[$j];
                    $f[$j] = DsaField::add($t, $f[$j + $len]);
                    $f[$j + $len] = DsaField::mul($z, DsaField::sub($f[$j + $len], $t));
                }
            }
            $len <<= 1;
        }

        $nInv = DsaField::inv(256);
        for ($i = 0; $i < 256; $i++) {
            $f[$i] = DsaField::mul($f[$i], $nInv);
        }

        return $f;
    }

    /**
     * Pointwise multiplication in NTT domain.
     */
    public static function mulNtt(array $a, array $b): array
    {
        $c = [];
        for ($i = 0; $i < 256; $i++) {
            $c[$i] = DsaField::mul($a[$i], $b[$i]);
        }
        return $c;
    }

    /**
     * Polynomial addition.
     */
    public static function polyAdd(array $a, array $b): array
    {
        $c = [];
        for ($i = 0; $i < 256; $i++) {
            $c[$i] = DsaField::add($a[$i], $b[$i]);
        }
        return $c;
    }

    /**
     * Polynomial subtraction.
     */
    public static function polySub(array $a, array $b): array
    {
        $c = [];
        for ($i = 0; $i < 256; $i++) {
            $c[$i] = DsaField::sub($a[$i], $b[$i]);
        }
        return $c;
    }

    /**
     * Matrix-vector product: A * v (both in NTT domain).
     */
    public static function matVecMul(array $mat, array $vec, int $k, int $l): array
    {
        $result = [];
        for ($i = 0; $i < $k; $i++) {
            $result[$i] = array_fill(0, 256, 0);
            for ($j = 0; $j < $l; $j++) {
                $prod = self::mulNtt($mat[$i][$j], $vec[$j]);
                $result[$i] = self::polyAdd($result[$i], $prod);
            }
        }
        return $result;
    }

    /**
     * Vector dot product in NTT domain.
     */
    public static function vecDot(array $a, array $b, int $len): array
    {
        $result = array_fill(0, 256, 0);
        for ($i = 0; $i < $len; $i++) {
            $prod = self::mulNtt($a[$i], $b[$i]);
            $result = self::polyAdd($result, $prod);
        }
        return $result;
    }
}
