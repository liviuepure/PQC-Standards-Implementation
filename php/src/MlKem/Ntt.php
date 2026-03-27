<?php

declare(strict_types=1);

namespace PQC\MlKem;

/**
 * Number Theoretic Transform for ML-KEM (q=3329, zeta=17).
 */
final class Ntt
{
    /**
     * Precomputed zetas: zeta^{BitRev7(i)} mod q for i=0..127.
     * zeta = 17, q = 3329.
     */
    private static ?array $zetas = null;

    public static function getZetas(): array
    {
        if (self::$zetas !== null) {
            return self::$zetas;
        }

        // Precomputed zetas for ML-KEM NTT
        self::$zetas = [
            1, 1729, 2580, 3289, 2642, 630, 1897, 848,
            1062, 1919, 193, 797, 2786, 3260, 569, 1746,
            296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
            1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
            289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
            650, 1977, 2513, 632, 2865, 33, 1320, 1915,
            2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
            2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
            17, 2761, 583, 2649, 1637, 723, 2288, 1100,
            1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
            1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
            939, 2308, 2437, 2388, 733, 2337, 268, 641,
            1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
            1063, 319, 2773, 757, 2099, 561, 2466, 2594,
            2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
            1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
        ];

        return self::$zetas;
    }

    /**
     * Forward NTT: transforms polynomial from normal to NTT domain.
     *
     * @param array $f Polynomial coefficients (256 integers)
     * @return array NTT-domain coefficients
     */
    public static function ntt(array $f): array
    {
        $zetas = self::getZetas();
        $k = 1;
        $len = 128;

        while ($len >= 2) {
            for ($start = 0; $start < 256; $start += 2 * $len) {
                $z = $zetas[$k++];
                for ($j = $start; $j < $start + $len; $j++) {
                    $t = Field::mul($z, $f[$j + $len]);
                    $f[$j + $len] = Field::sub($f[$j], $t);
                    $f[$j] = Field::add($f[$j], $t);
                }
            }
            $len >>= 1;
        }

        return $f;
    }

    /**
     * Inverse NTT: transforms from NTT domain back to normal.
     *
     * @param array $f NTT-domain coefficients
     * @return array Normal polynomial coefficients
     */
    public static function invNtt(array $f): array
    {
        $zetas = self::getZetas();
        $k = 127;
        $len = 2;

        while ($len <= 128) {
            for ($start = 0; $start < 256; $start += 2 * $len) {
                $z = $zetas[$k--];
                for ($j = $start; $j < $start + $len; $j++) {
                    $t = $f[$j];
                    $f[$j] = Field::add($t, $f[$j + $len]);
                    $f[$j + $len] = Field::mul($z, Field::sub($f[$j + $len], $t));
                }
            }
            $len <<= 1;
        }

        // Multiply by 128^{-1} mod q (7-layer NTT for ML-KEM)
        $nInv = Field::inv(128);
        for ($i = 0; $i < 256; $i++) {
            $f[$i] = Field::mul($f[$i], $nInv);
        }

        return $f;
    }

    /**
     * Base case multiplication for two NTT-domain elements.
     * Multiplies (a0 + a1*X) * (b0 + b1*X) mod (X^2 - gamma).
     */
    public static function baseMul(int $a0, int $a1, int $b0, int $b1, int $gamma): array
    {
        $c0 = Field::add(Field::mul($a0, $b0), Field::mul(Field::mul($a1, $b1), $gamma));
        $c1 = Field::add(Field::mul($a0, $b1), Field::mul($a1, $b0));
        return [$c0, $c1];
    }

    /**
     * Multiply two polynomials in NTT domain.
     */
    public static function mulNtt(array $a, array $b): array
    {
        $zetas = self::getZetas();
        $c = array_fill(0, 256, 0);

        for ($i = 0; $i < 64; $i++) {
            $z = $zetas[64 + $i];
            [$c[4*$i], $c[4*$i+1]] = self::baseMul(
                $a[4*$i], $a[4*$i+1], $b[4*$i], $b[4*$i+1], $z
            );
            [$c[4*$i+2], $c[4*$i+3]] = self::baseMul(
                $a[4*$i+2], $a[4*$i+3], $b[4*$i+2], $b[4*$i+3], Field::mod(-$z)
            );
        }

        return $c;
    }

    /**
     * Add two polynomials (coefficient-wise).
     */
    public static function polyAdd(array $a, array $b): array
    {
        $c = [];
        for ($i = 0; $i < 256; $i++) {
            $c[$i] = Field::add($a[$i], $b[$i]);
        }
        return $c;
    }

    /**
     * Subtract two polynomials.
     */
    public static function polySub(array $a, array $b): array
    {
        $c = [];
        for ($i = 0; $i < 256; $i++) {
            $c[$i] = Field::sub($a[$i], $b[$i]);
        }
        return $c;
    }
}
