<?php

declare(strict_types=1);

namespace PQC\Hqc;

/**
 * Reed-Solomon encoding and decoding over GF(2^8) for HQC.
 *
 * RS(n1, k) with minimum distance d = n1 - k + 1 = 2*delta + 1.
 * Generator polynomial: g(x) = prod(x - alpha^i) for i = 1..2*delta.
 * alpha = 2 (primitive element of GF(2^8) with polynomial 0x11D).
 */
final class ReedSolomon
{
    private const GF_GEN = 2;

    /**
     * Compute the generator polynomial of the RS code.
     * Returns coefficients [g0, g1, ..., g_{2*delta}] where g_{2*delta} = 1.
     *
     * @return int[]
     */
    public static function generatorPoly(int $delta): array
    {
        $deg = 2 * $delta;
        $g = array_fill(0, $deg + 1, 0);
        $g[0] = 1; // g(x) = 1

        for ($i = 1; $i <= $deg; $i++) {
            $alphai = GF256::pow(self::GF_GEN, $i);
            $prev = 0;
            for ($j = 0; $j <= $deg; $j++) {
                $tmp = $g[$j];
                $g[$j] = GF256::mul($g[$j], $alphai) ^ $prev;
                $prev = $tmp;
            }
        }

        return $g;
    }

    /**
     * Systematic RS encoding.
     * Input: msg of length k bytes.
     * Output: codeword of length n1 bytes (parity || msg).
     *
     * @param int[] $msg
     * @return int[]
     */
    public static function encode(array $msg, HqcParams $p): array
    {
        $k = $p->k;
        $n1 = $p->n1;
        $delta = $p->delta;
        $g = self::generatorPoly($delta);
        $parityLen = 2 * $delta;

        $feedback = array_fill(0, $parityLen, 0);

        for ($i = $k - 1; $i >= 0; $i--) {
            $coeff = GF256::add($msg[$i], $feedback[$parityLen - 1]);
            for ($j = $parityLen - 1; $j > 0; $j--) {
                $feedback[$j] = GF256::add($feedback[$j - 1], GF256::mul($coeff, $g[$j]));
            }
            $feedback[0] = GF256::mul($coeff, $g[0]);
        }

        // Codeword = [parity bytes] [message bytes]
        $codeword = array_fill(0, $n1, 0);
        for ($i = 0; $i < $parityLen; $i++) {
            $codeword[$i] = $feedback[$i];
        }
        for ($i = 0; $i < $k; $i++) {
            $codeword[$parityLen + $i] = $msg[$i];
        }

        return $codeword;
    }

    /**
     * Decode a received RS codeword.
     * Returns [decoded_message, success].
     *
     * @param int[] $received
     * @return array{0: int[], 1: bool}
     */
    public static function decode(array $received, HqcParams $p): array
    {
        $n1 = $p->n1;
        $k = $p->k;
        $delta = $p->delta;

        $r = $received;

        // Step 1: Compute syndromes S[1..2*delta]
        $syndromes = array_fill(0, 2 * $delta + 1, 0);
        $allZero = true;
        for ($i = 1; $i <= 2 * $delta; $i++) {
            $alphai = GF256::pow(self::GF_GEN, $i);
            $s = 0;
            for ($j = $n1 - 1; $j >= 0; $j--) {
                $s = GF256::add(GF256::mul($s, $alphai), $r[$j]);
            }
            $syndromes[$i] = $s;
            if ($s !== 0) {
                $allZero = false;
            }
        }

        if ($allZero) {
            return [array_slice($r, 2 * $delta, $k), true];
        }

        // Step 2: Berlekamp-Massey algorithm
        $sigma = self::berlekampMassey($syndromes, $delta);
        $sigDeg = 0;
        for ($i = $delta; $i >= 0; $i--) {
            if ($sigma[$i] !== 0) {
                $sigDeg = $i;
                break;
            }
        }
        if ($sigDeg > $delta) {
            return [array_fill(0, $k, 0), false];
        }

        // Step 3: Chien search - find roots of sigma
        $errorPositions = [];
        for ($i = 0; $i < $n1; $i++) {
            $alphaInv = GF256::pow(self::GF_GEN, 255 - $i);
            $val = 0;
            $alphaPow = 1;
            for ($j = 0; $j <= $sigDeg; $j++) {
                $val ^= GF256::mul($sigma[$j], $alphaPow);
                $alphaPow = GF256::mul($alphaPow, $alphaInv);
            }
            if ($val === 0) {
                $errorPositions[] = $i;
            }
        }

        if (count($errorPositions) !== $sigDeg) {
            return [array_fill(0, $k, 0), false];
        }

        // Step 4: Forney's algorithm - compute error values
        // omega(x) = S(x) * sigma(x) mod x^(2*delta+1)
        $omega = array_fill(0, 2 * $delta + 1, 0);
        for ($i = 0; $i < 2 * $delta; $i++) {
            for ($j = 0; $j <= $sigDeg && $j <= $i; $j++) {
                $omega[$i + 1] ^= GF256::mul($sigma[$j], $syndromes[$i + 1 - $j]);
            }
        }

        // sigma'(x) = formal derivative
        $sigmaPrime = array_fill(0, $delta + 1, 0);
        for ($i = 1; $i <= $sigDeg; $i += 2) {
            $sigmaPrime[$i - 1] = $sigma[$i];
        }

        // Correct errors
        foreach ($errorPositions as $pos) {
            $alphaInvI = GF256::inv(GF256::pow(self::GF_GEN, $pos));

            // Evaluate omega(alpha^(-pos))
            $omegaVal = 0;
            $alphaPow = 1;
            for ($j = 0; $j <= 2 * $delta; $j++) {
                $omegaVal ^= GF256::mul($omega[$j], $alphaPow);
                $alphaPow = GF256::mul($alphaPow, $alphaInvI);
            }

            // Evaluate sigma'(alpha^(-pos))
            $sigPrimeVal = 0;
            $alphaPow = 1;
            for ($j = 0; $j < count($sigmaPrime); $j++) {
                $sigPrimeVal ^= GF256::mul($sigmaPrime[$j], $alphaPow);
                $alphaPow = GF256::mul($alphaPow, $alphaInvI);
            }

            if ($sigPrimeVal === 0) {
                return [array_fill(0, $k, 0), false];
            }

            // Forney: e_j = X_j * omega(X_j^{-1}) / sigma'(X_j^{-1})
            $xj = GF256::pow(self::GF_GEN, $pos);
            $errorVal = GF256::mul(GF256::mul($xj, $omegaVal), GF256::inv($sigPrimeVal));
            $r[$pos] ^= $errorVal;
        }

        return [array_slice($r, 2 * $delta, $k), true];
    }

    /**
     * Berlekamp-Massey algorithm.
     * Returns the error locator polynomial sigma[0..delta].
     *
     * @param int[] $syndromes
     * @return int[]
     */
    private static function berlekampMassey(array $syndromes, int $delta): array
    {
        $n = 2 * $delta;
        $sigma = array_fill(0, $delta + 2, 0);
        $sigma[0] = 1;
        $b = array_fill(0, $delta + 2, 0);
        $b[0] = 1;
        $L = 0;
        $m = 1;
        $deltaN = 1; // previous discrepancy

        for ($kk = 1; $kk <= $n; $kk++) {
            // Compute discrepancy d
            $d = $syndromes[$kk];
            for ($i = 1; $i <= $L; $i++) {
                $d ^= GF256::mul($sigma[$i], $syndromes[$kk - $i]);
            }

            if ($d === 0) {
                $m++;
                continue;
            }

            // t(x) = sigma(x) - (d/deltaN) * x^m * b(x)
            $t = $sigma; // copy
            $coeff = GF256::mul($d, GF256::inv($deltaN));
            for ($i = 0; $i <= $delta + 1 - $m; $i++) {
                if ($i + $m <= $delta + 1) {
                    $t[$i + $m] ^= GF256::mul($coeff, $b[$i]);
                }
            }

            if (2 * $L < $kk) {
                $b = $sigma; // copy
                $L = $kk - $L;
                $deltaN = $d;
                $m = 1;
            } else {
                $m++;
            }
            $sigma = $t;
        }

        return array_slice($sigma, 0, $delta + 1);
    }
}
