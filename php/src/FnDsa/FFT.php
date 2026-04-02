<?php

declare(strict_types=1);

namespace PQC\FnDsa;

/**
 * Complex FFT/IFFT/SplitFFT/MergeFFT for FN-DSA (FIPS 206 / FALCON).
 *
 * Operates over C[x]/(x^n+1), evaluating polynomials at the 2n-th
 * primitive roots of unity.
 *
 * Complex numbers are represented as [float, float] = [re, im].
 */
final class FFT
{
    /**
     * Compute log2(n).
     */
    public static function logN(int $n): int
    {
        $logn = 0;
        $t = $n;
        while ($t > 1) {
            $logn++;
            $t >>= 1;
        }
        return $logn;
    }

    /**
     * Bit-reverse the low logn bits of k.
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
     * In-place forward negacyclic complex FFT.
     *
     * @param array $f Array of n [re, im] pairs, modified in-place.
     * @param int $n Polynomial degree (power of 2, 4 <= n <= 1024).
     */
    public static function fft(array &$f, int $n): void
    {
        $logn = self::logN($n);

        $k = 0;
        for ($length = $n >> 1; $length >= 1; $length >>= 1) {
            for ($start = 0; $start < $n; $start += 2 * $length) {
                $k++;
                $brk = self::bitRev($k, $logn);
                $angle = M_PI * $brk / $n;
                $wRe = cos($angle);
                $wIm = sin($angle);
                for ($j = $start; $j < $start + $length; $j++) {
                    // t = w * f[j+length]
                    $tRe = $wRe * $f[$j + $length][0] - $wIm * $f[$j + $length][1];
                    $tIm = $wRe * $f[$j + $length][1] + $wIm * $f[$j + $length][0];
                    // f[j+length] = f[j] - t
                    $f[$j + $length] = [
                        $f[$j][0] - $tRe,
                        $f[$j][1] - $tIm,
                    ];
                    // f[j] = f[j] + t
                    $f[$j] = [
                        $f[$j][0] + $tRe,
                        $f[$j][1] + $tIm,
                    ];
                }
            }
        }
    }

    /**
     * In-place inverse negacyclic complex FFT.
     *
     * @param array $f Array of n [re, im] pairs, modified in-place.
     * @param int $n Polynomial degree.
     */
    public static function ifft(array &$f, int $n): void
    {
        $logn = self::logN($n);

        $k = $n;
        for ($length = 1; $length < $n; $length <<= 1) {
            for ($start = $n - 2 * $length; $start >= 0; $start -= 2 * $length) {
                $k--;
                $brk = self::bitRev($k, $logn);
                $angle = -M_PI * $brk / $n;
                $wRe = cos($angle);
                $wIm = sin($angle);
                for ($j = $start; $j < $start + $length; $j++) {
                    $aRe = $f[$j][0];
                    $aIm = $f[$j][1];
                    $bRe = $f[$j + $length][0];
                    $bIm = $f[$j + $length][1];
                    // f[j] = a + b
                    $f[$j] = [$aRe + $bRe, $aIm + $bIm];
                    // f[j+length] = w * (a - b)
                    $dRe = $aRe - $bRe;
                    $dIm = $aIm - $bIm;
                    $f[$j + $length] = [
                        $wRe * $dRe - $wIm * $dIm,
                        $wRe * $dIm + $wIm * $dRe,
                    ];
                }
            }
        }

        // Scale by 1/n.
        $invN = 1.0 / $n;
        for ($i = 0; $i < $n; $i++) {
            $f[$i][0] *= $invN;
            $f[$i][1] *= $invN;
        }
    }

    /**
     * Split an n-element FFT-domain polynomial into two (n/2)-element ones.
     *
     * @param array $f n [re, im] pairs in FFT domain.
     * @param int $n Polynomial degree.
     * @return array [f0, f1] each of size n/2.
     */
    public static function splitFft(array $f, int $n): array
    {
        $logn = self::logN($n);
        $h = $n / 2;
        $f0 = [];
        $f1 = [];
        for ($k = 0; $k < $h; $k++) {
            $j = self::bitRev($k, $logn - 1);
            $angle = M_PI * (2 * $j + 1) / $n;
            $omRe = cos($angle);
            $omIm = sin($angle);
            $aRe = $f[2 * $k][0];
            $aIm = $f[2 * $k][1];
            $bRe = $f[2 * $k + 1][0];
            $bIm = $f[2 * $k + 1][1];
            // f0[k] = (a + b) / 2
            $f0[$k] = [($aRe + $bRe) / 2.0, ($aIm + $bIm) / 2.0];
            // f1[k] = (a - b) / (2 * omega_j)
            $dRe = ($aRe - $bRe) / 2.0;
            $dIm = ($aIm - $bIm) / 2.0;
            // Divide by omega_j: (dRe+i*dIm) / (omRe+i*omIm)
            $denom = $omRe * $omRe + $omIm * $omIm;
            $f1[$k] = [
                ($dRe * $omRe + $dIm * $omIm) / $denom,
                ($dIm * $omRe - $dRe * $omIm) / $denom,
            ];
        }
        return [$f0, $f1];
    }

    /**
     * Merge two (n/2)-element FFT-domain polynomials into an n-element one.
     *
     * @param array $f0 n/2 [re, im] pairs.
     * @param array $f1 n/2 [re, im] pairs.
     * @param int $n Full polynomial degree.
     * @return array n [re, im] pairs.
     */
    public static function mergeFft(array $f0, array $f1, int $n): array
    {
        $logn = self::logN($n);
        $h = $n / 2;
        $f = [];
        for ($k = 0; $k < $h; $k++) {
            $j = self::bitRev($k, $logn - 1);
            $angle = M_PI * (2 * $j + 1) / $n;
            $omRe = cos($angle);
            $omIm = sin($angle);
            // t = omega_j * f1[k]
            $tRe = $omRe * $f1[$k][0] - $omIm * $f1[$k][1];
            $tIm = $omRe * $f1[$k][1] + $omIm * $f1[$k][0];
            $f[2 * $k] = [$f0[$k][0] + $tRe, $f0[$k][1] + $tIm];
            $f[2 * $k + 1] = [$f0[$k][0] - $tRe, $f0[$k][1] - $tIm];
        }
        return $f;
    }
}
