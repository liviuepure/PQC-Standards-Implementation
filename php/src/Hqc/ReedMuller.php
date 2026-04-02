<?php

declare(strict_types=1);

namespace PQC\Hqc;

/**
 * Reed-Muller code RM(1, 7) for HQC.
 *
 * RM(1, 7) encodes 8 bits (1 byte) into 128 bits.
 * The codeword is then duplicated (Multiplicity times) to form an n2-bit codeword.
 *
 * Decoding uses the Walsh-Hadamard transform.
 */
final class ReedMuller
{
    private const BASE_LEN = 128;

    /**
     * Encode a single byte into 128-bit RM(1,7) codeword.
     * Returns a GMP integer with 128 bits.
     */
    public static function encodeBase(int $msg): \GMP
    {
        // The generator matrix rows for RM(1,7):
        // Row 0 (constant): all-ones
        // Row 1: 0xAAAAAAAAAAAAAAAA (repeated for 128 bits)
        // Row 2: 0xCCCCCCCCCCCCCCCC
        // Row 3: 0xF0F0F0F0F0F0F0F0
        // Row 4: 0xFF00FF00FF00FF00
        // Row 5: 0xFFFF0000FFFF0000
        // Row 6: 0xFFFFFFFF00000000
        // Row 7: 64 zeros then 64 ones = hi word all ones

        // We build 128 bits as two 64-bit halves (lo, hi) packed into GMP
        $lo = gmp_init(0);
        $hi = gmp_init(0);

        // Helper: expand bit $bit of $msg to all-64-bit mask
        $expand = function (int $bit) use ($msg): \GMP {
            if (($msg >> $bit) & 1) {
                return gmp_init('FFFFFFFFFFFFFFFF', 16);
            }
            return gmp_init(0);
        };

        // Bit 0: constant row (all-ones if set)
        $lo = gmp_xor($lo, $expand(0));
        $hi = gmp_xor($hi, $expand(0));

        // Bit 1: 0xAAAAAAAAAAAAAAAA
        $pat1 = gmp_init('AAAAAAAAAAAAAAAA', 16);
        $lo = gmp_xor($lo, gmp_and($expand(1), $pat1));
        $hi = gmp_xor($hi, gmp_and($expand(1), $pat1));

        // Bit 2: 0xCCCCCCCCCCCCCCCC
        $pat2 = gmp_init('CCCCCCCCCCCCCCCC', 16);
        $lo = gmp_xor($lo, gmp_and($expand(2), $pat2));
        $hi = gmp_xor($hi, gmp_and($expand(2), $pat2));

        // Bit 3: 0xF0F0F0F0F0F0F0F0
        $pat3 = gmp_init('F0F0F0F0F0F0F0F0', 16);
        $lo = gmp_xor($lo, gmp_and($expand(3), $pat3));
        $hi = gmp_xor($hi, gmp_and($expand(3), $pat3));

        // Bit 4: 0xFF00FF00FF00FF00
        $pat4 = gmp_init('FF00FF00FF00FF00', 16);
        $lo = gmp_xor($lo, gmp_and($expand(4), $pat4));
        $hi = gmp_xor($hi, gmp_and($expand(4), $pat4));

        // Bit 5: 0xFFFF0000FFFF0000
        $pat5 = gmp_init('FFFF0000FFFF0000', 16);
        $lo = gmp_xor($lo, gmp_and($expand(5), $pat5));
        $hi = gmp_xor($hi, gmp_and($expand(5), $pat5));

        // Bit 6: 0xFFFFFFFF00000000
        $pat6 = gmp_init('FFFFFFFF00000000', 16);
        $lo = gmp_xor($lo, gmp_and($expand(6), $pat6));
        $hi = gmp_xor($hi, gmp_and($expand(6), $pat6));

        // Bit 7: (0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
        $hi = gmp_xor($hi, $expand(7));

        // Combine: result = hi << 64 | lo
        $result = gmp_or(GF2::shiftLeft($hi, 64), $lo);
        return $result;
    }

    /**
     * Encode a byte into the destination GMP polynomial at the given bit offset.
     * The codeword is duplicated `multiplicity` times.
     */
    public static function encodeInto(\GMP &$dst, int $msg, int $bitOffset, int $multiplicity): void
    {
        $base = self::encodeBase($msg);

        $bitPos = $bitOffset;
        for ($rep = 0; $rep < $multiplicity; $rep++) {
            // Place the 128-bit base codeword at bitPos
            $shifted = GF2::shiftLeft($base, $bitPos);
            $dst = gmp_xor($dst, $shifted);
            $bitPos += self::BASE_LEN;
        }
    }

    /**
     * Decode an n2-bit received codeword (with duplicated RM(1,7)) to a single byte.
     * Uses the Walsh-Hadamard transform.
     *
     * @param \GMP $src The received codeword as GMP integer
     * @param int $n2 Total codeword bits
     * @param int $multiplicity Number of repetitions
     */
    public static function decode(\GMP $src, int $n2, int $multiplicity): int
    {
        // Step 1: Accumulate all copies into signed sum array of 128 entries.
        $sums = array_fill(0, self::BASE_LEN, 0);

        $bitPos = 0;
        for ($rep = 0; $rep < $multiplicity; $rep++) {
            for ($i = 0; $i < self::BASE_LEN; $i++) {
                $bit = gmp_testbit($src, $bitPos) ? 1 : 0;
                // Convert 0/1 to +1/-1: (0 -> +1, 1 -> -1)
                $sums[$i] += 1 - 2 * $bit;
                $bitPos++;
            }
        }

        // Step 2: Fast Walsh-Hadamard Transform (in-place, 7 passes)
        for ($pass = 0; $pass < 7; $pass++) {
            $step = 1 << $pass;
            for ($i = 0; $i < self::BASE_LEN; $i += 2 * $step) {
                for ($j = $i; $j < $i + $step; $j++) {
                    $a = $sums[$j];
                    $b = $sums[$j + $step];
                    $sums[$j] = $a + $b;
                    $sums[$j + $step] = $a - $b;
                }
            }
        }

        // Step 3: Find position with maximum absolute value
        $maxAbs = 0;
        $maxPos = 0;
        $sign = 1;

        for ($i = 0; $i < self::BASE_LEN; $i++) {
            $v = $sums[$i];
            $abs = ($v < 0) ? -$v : $v;
            if ($abs > $maxAbs) {
                $maxAbs = $abs;
                $maxPos = $i;
                $sign = ($v > 0) ? 1 : -1;
            }
        }

        // Step 4: Recover the message byte.
        $msg = ($maxPos << 1) & 0xFF;
        if ($sign < 0) {
            $msg |= 1;
        }
        return $msg;
    }
}
