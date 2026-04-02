<?php

declare(strict_types=1);

namespace PQC\Hqc;

/**
 * GF(2^8) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
 *
 * Generator alpha = 2 (primitive element).
 */
final class GF256
{
    private const GF_POLY = 0x11D;
    private const GF_GEN = 2;
    private const GF_MUL_ORDER = 255;

    /** @var int[] exp table (doubled for convenience) */
    private static array $exp = [];

    /** @var int[] log table */
    private static array $log = [];

    private static bool $initialized = false;

    /**
     * Initialize the exp/log lookup tables.
     */
    public static function init(): void
    {
        if (self::$initialized) {
            return;
        }

        self::$exp = array_fill(0, 512, 0);
        self::$log = array_fill(0, 256, 0);

        $x = 1;
        for ($i = 0; $i < 255; $i++) {
            self::$exp[$i] = $x;
            self::$exp[$i + 255] = $x; // wrap-around
            self::$log[$x] = $i;
            $x <<= 1;
            if ($x >= 256) {
                $x ^= self::GF_POLY;
            }
        }
        self::$log[0] = 0; // convention
        self::$exp[510] = self::$exp[0];

        self::$initialized = true;
    }

    /**
     * Addition in GF(2^8) = XOR.
     */
    public static function add(int $a, int $b): int
    {
        return $a ^ $b;
    }

    /**
     * Multiplication in GF(2^8) via log/exp tables.
     */
    public static function mul(int $a, int $b): int
    {
        if ($a === 0 || $b === 0) {
            return 0;
        }
        self::init();
        return self::$exp[self::$log[$a] + self::$log[$b]];
    }

    /**
     * Multiplicative inverse in GF(2^8).
     */
    public static function inv(int $a): int
    {
        if ($a === 0) {
            return 0;
        }
        self::init();
        return self::$exp[255 - self::$log[$a]];
    }

    /**
     * Power in GF(2^8): a^n.
     */
    public static function pow(int $a, int $n): int
    {
        if ($a === 0) {
            return ($n === 0) ? 1 : 0;
        }
        self::init();
        $logA = self::$log[$a];
        $logResult = ($logA * $n) % 255;
        if ($logResult < 0) {
            $logResult += 255;
        }
        return self::$exp[$logResult];
    }

    /**
     * Division in GF(2^8): a / b.
     */
    public static function div(int $a, int $b): int
    {
        if ($b === 0) {
            throw new \InvalidArgumentException('GF256 division by zero');
        }
        if ($a === 0) {
            return 0;
        }
        self::init();
        $logDiff = self::$log[$a] - self::$log[$b];
        if ($logDiff < 0) {
            $logDiff += 255;
        }
        return self::$exp[$logDiff];
    }
}
